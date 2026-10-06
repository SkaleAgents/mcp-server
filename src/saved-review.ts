import { AsyncLocalStorage } from "node:async_hooks";
import { z } from "zod";
import { getApiAccessToken } from "./auth.js";
import { getApiUrl } from "./config.js";
import { VERSION } from "./version.js";

const repositoryLabel = z
  .string()
  .regex(/^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)?$/)
  .max(200);
const relativePath = z
  .string()
  .min(1)
  .max(500)
  .refine((path) => !path.startsWith("/") && !path.includes("..") && !path.includes("\\"));
const revision = z.string().regex(/^[A-Za-z0-9._-]{1,64}$/);

export const savedTargetSchema = z
  .object({
    repository: repositoryLabel.optional(),
    path: relativePath.optional(),
    revision: revision.optional(),
  })
  .strict()
  .optional()
  .describe("Repository label for the next comparison. The server does not fetch it.");

export const applicationTargetSchema = z
  .object({
    repository: repositoryLabel.optional(),
    revision: revision.optional(),
  })
  .strict()
  .optional()
  .describe("Repository label for the next comparison. Send paths on each file.");

export const requestAuthorization = new AsyncLocalStorage<string>();

export const ASSISTANT_INSTRUCTION =
  "Report the headline and the one recommended change. Include the share link. If the headline says the finding is gone, say that. If there are no findings, say that this does not prove the system is secure. Do not paste source, diffs, or account details. Do not invent a link when the share link is missing.";

type Target = {
  repository?: string;
  path?: string;
  revision?: string;
};

type SaveInput = {
  tool: string;
  target?: Target | null;
  submittedPaths: string[];
};

const refused = {
  saved: false,
  id: null,
  ownerUrl: null,
  shareUrl: null,
  shareExpiresAt: null,
  comparison: null,
  headline: null,
  assistantInstruction: ASSISTANT_INSTRUCTION,
};

function clip(value: unknown, max = 200): string | null {
  if (typeof value !== "string") return null;
  const text = value.replaceAll("\n", " ").trim();
  if (!text || text.length > max) return null;
  return text;
}

function findingPath(finding: Record<string, unknown>, fallback: string): string {
  const location = finding.location;
  if (location && typeof location === "object" && "path" in location && fallback) {
    return fallback;
  }
  const evidence = finding.evidence;
  if (Array.isArray(evidence) && evidence[0] && typeof evidence[0] === "object" && "file" in evidence[0]) {
    const file = clip(evidence[0].file, 500);
    if (file) return file;
  }
  return fallback;
}

export function buildProjection(input: SaveInput, output: Record<string, unknown>) {
  const findings = Array.isArray(output.findings) ? output.findings : [];
  const fallbackPath = input.target?.path ?? "";
  const projected = findings.slice(0, 100).flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const finding = item as Record<string, unknown>;
    const title = clip(finding.title);
    const severity = clip(finding.severity, 16);
    if (!title || !severity) return [];
    const row: Record<string, unknown> = { title, severity };
    const ruleId = clip(finding.ruleId, 64);
    if (ruleId) row.ruleId = ruleId;
    for (const field of ["detail", "resource", "remediation"] as const) {
      const text = clip(finding[field]);
      if (text) row[field] = text;
    }
    const path = findingPath(finding, fallbackPath);
    if (path) row.path = path;
    const line = finding.location && typeof finding.location === "object" && "line" in finding.location
      ? finding.location.line
      : Array.isArray(finding.evidence) && finding.evidence[0] && typeof finding.evidence[0] === "object"
        ? (finding.evidence[0] as { line?: unknown }).line
        : null;
    if (typeof line === "number" && Number.isInteger(line) && line > 0) row.line = line;
    return [row];
  });

  const checked = Array.isArray(output.rulesEvaluated)
    ? output.rulesEvaluated.flatMap((rule) => {
        const text = clip(rule, 64);
        return text ? [text] : [];
      })
    : [];
  if (input.tool === "review_application_architecture") {
    checked.unshift(`Reviewed ${input.submittedPaths.length} files.`);
    checked.push(...input.submittedPaths);
  }
  const skipped: string[] = [];
  if (Array.isArray(output.warnings) && output.warnings.length > 0) {
    const count = output.warnings.length;
    skipped.push(`The scanner reported ${count} ${count === 1 ? "warning" : "warnings"}.`);
  }
  for (const field of ["evidenceGaps", "limitations"] as const) {
    if (!Array.isArray(output[field])) continue;
    for (const entry of output[field]) {
      const text = clip(entry);
      if (text) skipped.push(text);
      if (skipped.length >= 20) break;
    }
  }

  const summary = clip(output.summary);
  const riskSentence = summary
    ?? (projected.length === 0
      ? "No findings. That does not prove the system is secure."
      : projected[0].title);

  return {
    tool: input.tool,
    engineVersion: VERSION,
    target: input.target ?? null,
    riskSentence,
    findings: projected,
    truncated: output.truncated === true || findings.length > 100,
    checked: checked.length > 0 ? checked.slice(0, 20) : ["Individual checks were not recorded."],
    skipped: skipped.length > 0 ? skipped.slice(0, 20) : ["Nothing was recorded as skipped."],
    submittedPaths: input.submittedPaths.length > 0 ? input.submittedPaths : [fallbackPath],
  };
}

async function authorizationHeader(): Promise<string | null> {
  const fromRequest = requestAuthorization.getStore();
  if (fromRequest) return fromRequest;
  const token = await getApiAccessToken();
  return token ? `Bearer ${token}` : null;
}

export async function withSavedReview(
  output: Record<string, unknown>,
  input: SaveInput,
): Promise<Record<string, unknown>> {
  const projection = buildProjection(input, output);
  let savedReview: Record<string, unknown> = refused;
  const authorization = await authorizationHeader();
  if (authorization) {
    try {
      const response = await fetch(`${getApiUrl()}/api/mcp/reviews`, {
        method: "POST",
        headers: {
          Authorization: authorization,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(projection),
        signal: AbortSignal.timeout(10_000),
        redirect: "error",
        cache: "no-store",
      });
      if (response.ok) {
        const body = await response.json() as { savedReview?: Record<string, unknown> };
        if (body.savedReview) savedReview = body.savedReview;
      }
    } catch {
      savedReview = refused;
    }
  }
  return { ...output, savedReview };
}
