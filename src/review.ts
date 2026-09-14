import { getApiToken, getApiUrl } from "./config.js";

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export type Finding = {
  severity: FindingSeverity;
  title: string;
  detail: string;
};

type ReviewFocus = "security" | "reliability" | "cost" | "general";

function shouldInclude(focus: ReviewFocus, category: Exclude<ReviewFocus, "general">): boolean {
  return focus === "general" || focus === category;
}

export function architectureFindings(content: string, focus: string): Finding[] {
  const focusValue: ReviewFocus =
    focus === "security" ||
    focus === "reliability" ||
    focus === "cost" ||
    focus === "general"
      ? focus
      : "general";
  const findings: Finding[] = [
    {
      severity: "info",
      title: "Structured review completed",
      detail: `Checked ${content.length} characters with the ${focusValue} ruleset. Findings are pattern-based and should be validated against the running system.`,
    },
  ];

  if (shouldInclude(focusValue, "security") && /0\.0\.0\.0(?:\/0)?/.test(content)) {
    findings.push({
      severity: "high",
      title: "Broad network exposure",
      detail: "Detected a possible wide-open CIDR or bind address. Restrict ingress to approved sources and keep public listeners behind the intended edge control.",
    });
  }
  if (shouldInclude(focusValue, "security") && /AKIA[0-9A-Z]{16}/.test(content)) {
    findings.push({
      severity: "critical",
      title: "Possible AWS access key",
      detail: "A value matches an AWS access-key pattern. Remove it from source, rotate the credential, and check repository history.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/.test(content)
  ) {
    findings.push({
      severity: "critical",
      title: "Private key material in source",
      detail: "Detected a private-key block. Revoke or rotate the key, remove it from source and history, and load replacement credentials through a secret manager.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /(?:password|passwd|secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*["'][^"']{8,}["']/i.test(content) &&
    !/(?:process\.env|secrets?\.|vault|parameter|<[^>]+>|\$\{)/i.test(content)
  ) {
    findings.push({
      severity: "high",
      title: "Hardcoded credential-like value",
      detail: "A credential-like assignment contains a literal value. Move it to a secret manager or runtime environment and rotate the exposed value.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /(?:Action|actions?)\s*[:=][^\n]*["']?\*["']?/i.test(content)
  ) {
    findings.push({
      severity: "high",
      title: "Wildcard permission detected",
      detail: "An IAM or policy action uses a wildcard. Replace it with the smallest permission set required by the workload.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /(?:privileged\s*:\s*true|hostNetwork\s*:\s*true|allowPrivilegeEscalation\s*:\s*true)/i.test(content)
  ) {
    findings.push({
      severity: "critical",
      title: "Elevated container privileges",
      detail: "The content enables a privileged container setting. Remove it unless the workload requires it, then isolate and monitor that workload.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /(?:^|[\s"'])https?:\/\/(?!localhost\b|127\.0\.0\.1\b)/i.test(content)
  ) {
    findings.push({
      severity: "medium",
      title: "Unencrypted HTTP endpoint",
      detail: "Detected an HTTP URL outside localhost. Use HTTPS for service and dependency traffic, and verify certificate validation is enabled.",
    });
  }
  if (
    (shouldInclude(focusValue, "security") || shouldInclude(focusValue, "reliability")) &&
    /(?:^|[\s:=])(?:[\w./-]+:)?latest(?:[\s"']|$)/im.test(content)
  ) {
    findings.push({
      severity: "medium",
      title: "Unpinned container image",
      detail: "An image uses the mutable latest tag. Pin a version or digest so deployments are repeatable and rollback targets remain known.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /(?:public-read|publicRead|allUsers)/i.test(content)
  ) {
    findings.push({
      severity: "high",
      title: "Public data access pattern",
      detail: "Detected a public access setting. Confirm the resource is intended to be public and restrict access when it is not.",
    });
  }
  if (
    shouldInclude(focusValue, "reliability") &&
    /(?:debug|app_debug)\s*[:=]\s*["']?(?:true|1|yes)["']?/i.test(content)
  ) {
    findings.push({
      severity: "medium",
      title: "Debug mode enabled",
      detail: "The content enables debug mode. Disable it in production to avoid noisy behavior and accidental disclosure of internal details.",
    });
  }
  if (shouldInclude(focusValue, "cost") && /(?:instance_type|machine_type|vm_size)\s*[:=]/i.test(content)) {
    findings.push({
      severity: "info",
      title: "Compute sizing needs review",
      detail: "Detected an explicit compute size. Compare the selected size with observed utilization and set a review point for scale-up and scale-down decisions.",
    });
  }
  return findings;
}

export async function fetchPublicBotHints(): Promise<string[]> {
  try {
    const res = await fetch(`${getApiUrl()}/api/bots`, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${getApiToken()}`,
      },
    });
    if (!res.ok) return [];
    const data = (await res.json()) as {
      bots: Array<{ name: string; status: string; visibility: string }>;
    };
    return data.bots
      .filter((b) => b.status === "published" && b.visibility === "public")
      .map((b) => b.name)
      .slice(0, 5);
  } catch {
    return [];
  }
}

export function countIacResources(content: string): number {
  return (content.match(/\bresource\b|\bkind:\s*\w+/gi) ?? []).length;
}
