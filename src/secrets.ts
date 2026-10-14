import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { relative } from "node:path";
import { applySuppressions } from "./iac/scan.js";
import type { Finding } from "./review.js";

// High-confidence formats only: a false alarm on every high-entropy string would get the hook uninstalled.
const patterns: [name: string, pattern: RegExp][] = [
  ["AWS access key ID", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g],
  ["Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/g],
  ["Stripe live key", /\b[sr]k_live_[A-Za-z0-9]{20,}\b/g],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ["npm token", /\bnpm_[A-Za-z0-9]{36}\b/g],
  ["Anthropic API key", /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  ["Private key", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g],
];
const maxBytes = 1_000_000;
const maxFindings = 1000;
const placeholder = /EXAMPLE|YOUR|PLACEHOLDER|XXXX/i;
const skipped = /(^|[/\\])(package-lock\.json|composer\.lock|pnpm-lock\.yaml|yarn\.lock|\.skaleagents-baseline\.json)$|\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|woff2?|ttf|mp4|mov|wasm|lock|map)$/i;

function gitIgnored(files: string[]): Set<string> {
  try {
    const out = execFileSync("git", ["check-ignore", "--stdin", "-z"], {
      input: files.join("\0"),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "ignore"],
    });
    return new Set(out.split("\0").filter(Boolean));
  } catch {
    return new Set(); // Not a git repo, or nothing is ignored (exit 1).
  }
}

export type SecretFinding = Finding & { file: string };

// The matched text is never copied into a finding. A short digest keeps two keys in one file distinct.
export function scanSecrets(files: string[]) {
  const ignored = gitIgnored(files);
  const findings: SecretFinding[] = [];
  let suppressed = 0;
  for (const file of files) {
    if (skipped.test(file) || ignored.has(file)) continue;
    let text: string;
    try {
      if (statSync(file).size > maxBytes) continue;
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (text.includes("\0")) continue;
    const found: Finding[] = [];
    const seen = new Set<string>();
    const lineStarts = [0];
    for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) lineStarts.push(i + 1);
    for (const [name, pattern] of patterns) {
      for (const match of text.matchAll(pattern)) {
        if (placeholder.test(match[0])) continue;
        let low = 0;
        let high = lineStarts.length - 1;
        while (low < high) {
          const mid = (low + high + 1) >> 1;
          if (lineStarts[mid] <= match.index) low = mid;
          else high = mid - 1;
        }
        const line = low + 1;
        // A key block's header is the same for every key, so its digest also covers the start of the body.
        const material = name === "Private key" ? text.slice(match.index, match.index + match[0].length + 64) : match[0];
        const digest = createHash("sha256").update(material).digest("hex").slice(0, 6);
        const resource = `${name} ${digest}`;
        found.push({
          severity: "critical",
          category: "security",
          ruleId: "SECRET001",
          title: `${name} in source`,
          detail: `A ${name.toLowerCase()} is committed in plain text. The value is not shown here.`,
          remediation: "Revoke and rotate it now, remove it from the file and from git history, and load it from a secret manager or environment variable.",
          resource,
          location: { line, column: 1, path: name },
        });
      }
    }
    const applied = applySuppressions(found, text);
    suppressed += applied.suppressed;
    for (const finding of applied.kept) {
      // One finding per distinct secret per file, matching the baseline key, after suppressions so an ignored copy cannot hide another.
      if (seen.has(finding.resource ?? "")) continue;
      seen.add(finding.resource ?? "");
      if (findings.length >= maxFindings) return { findings, suppressed, truncated: true };
      findings.push({ ...finding, file: relative(".", file) });
    }
  }
  return { findings, suppressed, truncated: false };
}
