export type ExactLineEdit = {
  diff: string;
  from: string;
  to: string | null;
};

const severityOrder = ["critical", "high", "medium", "low", "info"] as const;
const noFindingsSummary = "No findings. That does not prove the system is secure.";

const rules: Record<string, (lines: string[]) => ExactLineEdit | null> = {
  "Dockerfile runs as root": dockerfileUser,
  "Workflow permissions are broad": workflowPermissions,
  "Elevated container privileges": privilegedContainer,
  "Privileged container in a Helm template": privilegedContainer,
  "Database publicly accessible": publicDatabase,
  "Database or storage allows public network access": publicNetworkAccess,
  "Storage encryption disabled": storageEncryption,
  "Pull request target checks out PR code": pullRequestTargetCheckout,
};

export function exactLineEdit(content: string, title: string): ExactLineEdit | null {
  const rule = rules[title];
  if (!rule) return null;
  return rule(content.split("\n"));
}

export function rankFindings<T extends { severity: string }>(findings: T[]): T[] {
  return findings
    .map((finding, index) => ({ finding, index }))
    .sort((left, right) => {
      const leftRank = severityOrder.indexOf(left.finding.severity as (typeof severityOrder)[number]);
      const rightRank = severityOrder.indexOf(right.finding.severity as (typeof severityOrder)[number]);
      return (leftRank === -1 ? severityOrder.length : leftRank) - (rightRank === -1 ? severityOrder.length : rightRank) || left.index - right.index;
    })
    .map((item) => item.finding);
}

export function changePhrase(edit: ExactLineEdit): string {
  if (edit.to === null) return `${edit.from.trim()} removed`;
  return `${edit.from.trim()} becomes ${edit.to.trim()}`;
}

type RankedFinding = { title: string; severity: string; proposedChange?: ExactLineEdit };

function isRankedFinding(value: unknown): value is RankedFinding {
  if (!value || typeof value !== "object") return false;
  const finding = value as { title?: unknown; severity?: unknown };
  return typeof finding.title === "string" && typeof finding.severity === "string";
}

export function presentReview(content: string, output: Record<string, unknown>) {
  const raw = Array.isArray(output.findings) ? output.findings : [];
  const findings = raw.map((finding) => {
    if (!isRankedFinding(finding)) return finding;
    const edit = exactLineEdit(content, finding.title);
    if (!edit) return finding;
    return { ...finding, proposedChange: edit };
  });
  const priority = rankFindings(findings.filter(isRankedFinding)).slice(0, 3);
  return {
    ...output,
    findings,
    priority,
    summary: priority.length === 0
      ? noFindingsSummary
      : `Fix these first: ${priority.map((finding) => finding.proposedChange ? `${finding.title}: ${changePhrase(finding.proposedChange)}` : finding.title).join(", ")}.`,
  };
}

function dockerfileUser(lines: string[]): ExactLineEdit | null {
  const exact = lines.flatMap((line, index) => line === "USER root" || line === "USER 0" ? [{ line, index }] : []);
  if (exact.length !== 1) return null;
  return replacement(exact[0].line, "USER nobody", exact[0].index);
}

function workflowPermissions(lines: string[]): ExactLineEdit | null {
  const exact = lines.flatMap((line, index) => line.trim() === "permissions: write-all" ? [{ line, index }] : []);
  if (exact.length !== 1) return null;
  const indent = exact[0].line.match(/^\s*/)?.[0] ?? "";
  return replacement(exact[0].line, `${indent}permissions: contents: read`, exact[0].index);
}

function privilegedContainer(lines: string[]): ExactLineEdit | null {
  return oneExactReplacement(lines, [{ from: "privileged: true", to: "privileged: false" }]);
}

function publicDatabase(lines: string[]): ExactLineEdit | null {
  return oneExactReplacement(lines, [{ from: "publicly_accessible = true", to: "publicly_accessible = false" }]);
}

function publicNetworkAccess(lines: string[]): ExactLineEdit | null {
  return oneExactReplacement(lines, [
    { from: "publicNetworkAccess: 'Enabled'", to: "publicNetworkAccess: 'Disabled'" },
    { from: "publicNetworkAccess: \"Enabled\"", to: "publicNetworkAccess: \"Disabled\"" },
  ]);
}

function storageEncryption(lines: string[]): ExactLineEdit | null {
  return oneExactReplacement(lines, [
    { from: "storage_encrypted = false", to: "storage_encrypted = true" },
    { from: "encrypted: false", to: "encrypted: true" },
    { from: "encrypted = false", to: "encrypted = true" },
  ]);
}

function pullRequestTargetCheckout(lines: string[]): ExactLineEdit | null {
  const exact = lines.flatMap((line, index) => isExactHeadRefLine(line) ? [{ line, index }] : []);
  if (exact.length !== 1) return null;
  const match = exact[0];
  if (!isPullRequestTargetWorkflow(lines) || !refBelongsToCheckout(lines, match.index)) return null;
  return {
    from: match.line,
    to: null,
    diff: [
      `@@ -${match.index + 1},1 +${Math.max(match.index, 0)},0 @@`,
      `-${match.line}`,
    ].join("\n"),
  };
}

function oneExactReplacement(lines: string[], pairs: Array<{ from: string; to: string }>): ExactLineEdit | null {
  const matches = lines.flatMap((line, index) => {
    const pair = pairs.find((item) => item.from === line.trim());
    return pair ? [{ line, index, to: pair.to }] : [];
  });
  if (matches.length !== 1) return null;
  const indent = matches[0].line.match(/^\s*/)?.[0] ?? "";
  return replacement(matches[0].line, `${indent}${matches[0].to}`, matches[0].index);
}

function replacement(from: string, to: string, lineIndex: number): ExactLineEdit {
  const line = lineIndex + 1;
  return {
    from,
    to,
    diff: [`@@ -${line},1 +${line},1 @@`, `-${from}`, `+${to}`].join("\n"),
  };
}

function isExactHeadRefLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed === "ref: ${{ github.event.pull_request.head.ref }}" || trimmed === "ref: ${{ github.event.pull_request.head.sha }}";
}

function isPullRequestTargetWorkflow(lines: string[]): boolean {
  return lines.some((line) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) return false;
    return trimmed === "on: pull_request_target" || trimmed === "pull_request_target:" || trimmed.startsWith("pull_request_target:");
  });
}

function refBelongsToCheckout(lines: string[], index: number): boolean {
  for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
    const trimmed = lines[cursor].trim();
    if (trimmed.startsWith("- uses:") || trimmed.startsWith("uses:")) return /actions\/checkout@/.test(trimmed);
  }
  return false;
}
