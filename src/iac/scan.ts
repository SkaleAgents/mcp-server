import { parseIac, type IacFormat } from "./parse.js";
import { resourceFindings } from "./rules.js";
import type { Finding, FindingSeverity } from "../review.js";

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

export function scanIac(content: string, options: ScanOptions = {}) {
  const parsed = parseIac(content, options.format);
  const result = resourceFindings(parsed.resources, parsed.format);
  const findings = filterFindings(result.findings, options);
  const limit = options.maxFindings ?? 100;
  return {
    status: "completed",
    engineVersion: "0.5.0",
    format: parsed.format,
    focus: options.focus ?? "general",
    summary: `Scanned ${parsed.resources.length} resources; ${findings.length} findings match the selected filters.`,
    parsedResourceCount: parsed.resources.length,
    resources: parsed.resources.map((r) => ({
      id: r.id,
      type: r.type,
      location: r.locate(),
    })),
    findings: findings.slice(0, limit),
    totals: summarize(findings),
    totalFindings: findings.length,
    truncated: findings.length > limit,
    rulesEvaluated: [...result.checked].sort(),
    warnings: parsed.warnings,
    limitations: [
      "Static configuration review only. No cloud credentials, deployments, external modules, or runtime state are inspected.",
      "Resource-specific checks cover Kubernetes workloads, RBAC and Secrets, plus AWS networking, IAM, S3, RDS, EC2 and EBS. Other resources receive literal credential and URL checks only.",
      ...(parsed.format === "terraform"
        ? [
            "HCL locations point to resource declarations; property paths identify the affected setting.",
          ]
        : []),
    ],
  };
}
