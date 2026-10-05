import { parseIac, readCloudFormationTables, ScanInputError, type CloudFormationTables, type IacFormat, type ParsedIac, type Resource } from "./parse.js";
import { resourceFindings, terraformLiterals, type TerraformLiterals } from "./rules.js";
import type { Finding, FindingSeverity } from "../review.js";
import { VERSION } from "../version.js";

export const severityRank: Record<FindingSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
export type ScanOptions = {
  format?: IacFormat | "auto";
  focus?: "security" | "reliability" | "cost" | "general";
  minSeverity?: FindingSeverity;
  maxFindings?: number;
};

const markerLine = /^----- skaleagents-file: (.+) -----$/;

export function summarize(findings: Finding[]) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) bySeverity[finding.severity]++;
  return bySeverity;
}

export function filterFindings(findings: Finding[], options: ScanOptions) {
  return findings
    .filter(
      (f) =>
        (!options.focus ||
          options.focus === "general" ||
          f.category === options.focus) &&
        severityRank[f.severity] >= severityRank[options.minSeverity ?? "info"],
    )
    .sort(
      (a, b) =>
        severityRank[b.severity] - severityRank[a.severity] ||
        (a.location?.line ?? 0) - (b.location?.line ?? 0) ||
        (a.ruleId ?? "").localeCompare(b.ruleId ?? ""),
    );
}

function fileBasename(name: string): string {
  const trimmed = name.trim();
  const base = trimmed.split(/[/\\]/).filter((part) => part.length > 0).pop() ?? "";
  return base.trim();
}

function splitSubmittedFiles(content: string): { name: string; text: string }[] | undefined {
  const lines = content.split("\n");
  const markers: { index: number; name: string }[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].endsWith("\r") ? lines[index].slice(0, -1) : lines[index];
    const match = markerLine.exec(line);
    if (!match) continue;
    const name = fileBasename(match[1]);
    if (!name || name.includes("----- skaleagents-file:")) continue;
    markers.push({ index, name });
  }
  if (markers.length === 0) return undefined;
  const parts: { name: string; text: string }[] = [];
  const preamble = lines.slice(0, markers[0].index).join("\n");
  if (preamble.trim()) parts.push({ name: "", text: preamble });
  for (let index = 0; index < markers.length; index += 1) {
    const start = markers[index].index + 1;
    const end = index + 1 < markers.length ? markers[index + 1].index : lines.length;
    parts.push({ name: markers[index].name, text: lines.slice(start, end).join("\n") });
  }
  return parts;
}

function labelResource(resource: Resource, fileName: string): Resource {
  if (!fileName) return resource;
  return {
    id: `${fileName}:${resource.id}`,
    type: resource.type,
    value: resource.value,
    locate: (path) => {
      const location = resource.locate(path);
      return { ...location, path: `${fileName}:${location.path}` };
    },
  };
}

function mergeTables(parts: CloudFormationTables[]): CloudFormationTables {
  const defaults = new Map<string, string | boolean | number>();
  const secretNames = new Set<string>();
  const mappings = new Map<string, Record<string, Record<string, string | number | boolean>>>();
  for (const part of parts) {
    for (const [name, value] of part.defaults) if (!defaults.has(name)) defaults.set(name, value);
    for (const name of part.secretNames) secretNames.add(name);
    for (const [name, value] of part.mappings) if (!mappings.has(name)) mappings.set(name, value);
  }
  return { defaults, secretNames, mappings };
}

const sharedResolutionLimit =
  "Files in one audit share variable defaults, locals, and parameter defaults. join, Fn::Join, Fn::FindInMap, format, and a simple Fn::Sub resolve when every piece is a known literal. Other functions and module sources do not. A finding names var, local, or parameter when the value came from one.";

function presentScan(
  parsed: { format: IacFormat; resources: Resource[]; warnings: string[] },
  findings: Finding[],
  checked: Set<string>,
  options: ScanOptions,
) {
  const visible = filterFindings(findings, options);
  const limit = options.maxFindings ?? 100;
  const sharesResolution = parsed.format === "terraform" || parsed.format === "cloudformation";
  return {
    status: "completed" as const,
    engineVersion: VERSION,
    format: parsed.format,
    focus: options.focus ?? "general",
    summary: `Scanned ${parsed.resources.length} resources; ${visible.length} findings match the selected filters.`,
    parsedResourceCount: parsed.resources.length,
    resources: parsed.resources.map((r) => ({
      id: r.id,
      type: r.type,
      location: r.locate(),
    })),
    findings: visible.slice(0, limit),
    totals: summarize(visible),
    totalFindings: visible.length,
    truncated: visible.length > limit,
    rulesEvaluated: [...checked].sort(),
    warnings: [...new Set(parsed.warnings)],
    limitations: [
      "Static configuration review only. No cloud credentials, deployments, external modules, or runtime state are inspected.",
      "Resource-specific checks cover Kubernetes workloads, RBAC and Secrets, plus AWS networking, IAM, S3, RDS, EC2 and EBS. Other resources receive literal credential and URL checks only.",
      ...(parsed.format === "terraform"
        ? [
            "HCL locations point to resource declarations; property paths identify the affected setting.",
          ]
        : []),
      ...(sharesResolution ? [sharedResolutionLimit] : []),
    ],
  };
}

function scanDocument(content: string, options: ScanOptions) {
  const parsed = parseIac(content, options.format);
  const result = resourceFindings(parsed.resources, parsed.format);
  return presentScan(parsed, result.findings, result.checked, options);
}

function scanMarked(parts: { name: string; text: string }[], options: ScanOptions) {
  const tables = mergeTables(parts.map((part) => readCloudFormationTables(part.text)));
  const parsedParts: { name: string; parsed: ParsedIac }[] = [];
  let lastError: unknown;
  for (const part of parts) {
    if (!part.text.trim()) continue;
    try {
      parsedParts.push({ name: part.name, parsed: parseIac(part.text, "auto", tables) });
    } catch (error) {
      lastError = error;
    }
  }
  if (parsedParts.length === 0) {
    if (lastError instanceof Error) throw lastError;
    throw new ScanInputError("Content must not be empty or whitespace.");
  }
  const literals: TerraformLiterals = terraformLiterals(
    parsedParts.flatMap((part) => part.parsed.resources),
  );
  const resources: Resource[] = [];
  const findings: Finding[] = [];
  const checked = new Set<string>();
  const warnings: string[] = [];
  const formats = new Set<IacFormat>();
  for (const part of parsedParts) {
    const labeled = part.parsed.resources.map((resource) => labelResource(resource, part.name));
    const result = resourceFindings(labeled, part.parsed.format, literals);
    resources.push(...labeled);
    findings.push(...result.findings);
    for (const id of result.checked) checked.add(id);
    warnings.push(...part.parsed.warnings);
    formats.add(part.parsed.format);
  }
  const format = formats.size === 1 ? [...formats][0] : parsedParts[0].parsed.format;
  const presented = presentScan({ format, resources, warnings }, findings, checked, options);
  if (formats.has("terraform") || formats.has("cloudformation")) {
    if (!presented.limitations.includes(sharedResolutionLimit))
      presented.limitations.push(sharedResolutionLimit);
  }
  return presented;
}

export function scanIac(content: string, options: ScanOptions = {}) {
  const parts = splitSubmittedFiles(content);
  if (!parts) return scanDocument(content, options);
  return scanMarked(parts, options);
}
