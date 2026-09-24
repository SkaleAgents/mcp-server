import { getApiUrl } from "./config.js";

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export type Finding = {
  severity: FindingSeverity;
  title: string;
  detail: string;
  ruleId?: string;
  category?: "security" | "reliability" | "cost";
  remediation?: string;
  location?: { line: number; column: number; path: string };
  resource?: string;
};

type ReviewFocus = "security" | "reliability" | "cost" | "general";

function shouldInclude(
  focus: ReviewFocus,
  category: Exclude<ReviewFocus, "general">,
): boolean {
  return focus === "general" || focus === category;
}

export function architectureFindings(
  content: string,
  focus: string,
): Finding[] {
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

  if (
    shouldInclude(focusValue, "security") &&
    /0\.0\.0\.0(?:\/0)?/.test(content)
  ) {
    findings.push({
      severity: "high",
      title: "Broad network exposure",
      detail:
        "Detected a possible wide-open CIDR or bind address. Restrict ingress to approved sources and keep public listeners behind the intended edge control.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /AKIA[0-9A-Z]{16}/.test(content)
  ) {
    findings.push({
      severity: "critical",
      title: "Possible AWS access key",
      detail:
        "A value matches an AWS access-key pattern. Remove it from source, rotate the credential, and check repository history.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/.test(content)
  ) {
    findings.push({
      severity: "critical",
      title: "Private key material in source",
      detail:
        "Detected a private-key block. Revoke or rotate the key, remove it from source and history, and load replacement credentials through a secret manager.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    [
      ...content.matchAll(
        /(?:password|passwd|secret|api[_-]?key|auth[_-]?token)["']?\s*[:=]\s*["']([^"'\n]+)["']/gi,
      ),
    ].some((match) => literalCredential(match[1]))
  ) {
    findings.push({
      severity: "high",
      title: "Hardcoded credential-like value",
      detail:
        "A credential-like assignment contains a literal value. Move it to a secret manager or runtime environment and rotate the exposed value.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /(?:Action|actions?)\s*[:=][^\n]*["']?\*["']?/i.test(content)
  ) {
    findings.push({
      severity: "high",
      title: "Wildcard permission detected",
      detail:
        "An IAM or policy action uses a wildcard. Replace it with the smallest permission set required by the workload.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /(?:privileged\s*:\s*true|hostNetwork\s*:\s*true|allowPrivilegeEscalation\s*:\s*true)/i.test(
      content,
    )
  ) {
    findings.push({
      severity: "critical",
      title: "Elevated container privileges",
      detail:
        "The content enables a privileged container setting. Remove it unless the workload requires it, then isolate and monitor that workload.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    [...content.matchAll(/\bhttp:\/\/[^\s"'<>]+/gi)].some((match) =>
      externalHttp(match[0]),
    )
  ) {
    findings.push({
      severity: "medium",
      title: "Unencrypted HTTP endpoint",
      detail:
        "Detected an HTTP URL outside localhost. Use HTTPS for service and dependency traffic, and verify certificate validation is enabled.",
    });
  }
  if (
    (shouldInclude(focusValue, "security") ||
      shouldInclude(focusValue, "reliability")) &&
    /(?:^|[\s:=])(?:[\w./-]+:)?latest(?:[\s"']|$)/im.test(content)
  ) {
    findings.push({
      severity: "medium",
      title: "Unpinned container image",
      detail:
        "An image uses the mutable latest tag. Pin a version or digest so deployments are repeatable and rollback targets remain known.",
    });
  }
  if (
    shouldInclude(focusValue, "security") &&
    /(?:public-read|publicRead|allUsers)/i.test(content)
  ) {
    findings.push({
      severity: "high",
      title: "Public data access pattern",
      detail:
        "Detected a public access setting. Confirm the resource is intended to be public and restrict access when it is not.",
    });
  }
  if (
    shouldInclude(focusValue, "reliability") &&
    /(?:debug|app_debug)\s*[:=]\s*["']?(?:true|1|yes)["']?/i.test(content)
  ) {
    findings.push({
      severity: "medium",
      title: "Debug mode enabled",
      detail:
        "The content enables debug mode. Disable it in production to avoid noisy behavior and accidental disclosure of internal details.",
    });
  }
  if (
    shouldInclude(focusValue, "cost") &&
    /(?:instance_type|machine_type|vm_size)\s*[:=]/i.test(content)
  ) {
    findings.push({
      severity: "info",
      title: "Compute sizing needs review",
      detail:
        "Detected an explicit compute size. Compare the selected size with observed utilization and set a review point for scale-up and scale-down decisions.",
    });
  }
  return findings.map((finding, index) => {
    if (index === 0) return finding;
    const matchers: Record<string, RegExp> = {
      "Broad network exposure": /0\.0\.0\.0(?:\/0)?/,
      "Possible AWS access key": /AKIA[0-9A-Z]{16}/,
      "Private key material in source":
        /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/,
      "Hardcoded credential-like value":
        /(?:password|passwd|secret|api[_-]?key|auth[_-]?token)["']?\s*[:=]\s*["']([^"'\n]+)["']/gi,
      "Wildcard permission detected":
        /(?:Action|actions?)\s*[:=][^\n]*["']?\*["']?/i,
      "Elevated container privileges":
        /(?:privileged|hostNetwork|allowPrivilegeEscalation)\s*:\s*true/i,
      "Unencrypted HTTP endpoint": /\bhttp:\/\/[^\s"'<>]+/gi,
      "Unpinned container image": /\blatest\b/,
      "Public data access pattern": /(?:public-read|publicRead|allUsers)/i,
      "Debug mode enabled": /(?:debug|app_debug)\s*[:=]\s*["']?(?:true|1|yes)/i,
      "Compute sizing needs review":
        /(?:instance_type|machine_type|vm_size)\s*[:=]/i,
    };
    const pattern = matchers[finding.title];
    const matches = pattern
      ? [
          ...content.matchAll(
            new RegExp(
              pattern.source,
              pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g",
            ),
          ),
        ]
      : [];
    const match = matches.find((m) =>
      finding.title === "Hardcoded credential-like value"
        ? literalCredential(m[1])
        : finding.title === "Unencrypted HTTP endpoint"
          ? externalHttp(m[0])
          : true,
    );
    const offset = match?.index ?? 0;
    const before = content.slice(0, offset);
    const ruleIndex = Object.keys(matchers).indexOf(finding.title) + 1;
    return {
      ...finding,
      ruleId: `APP${String(ruleIndex).padStart(3, "0")}`,
      category: (finding.title === "Compute sizing needs review"
        ? "cost"
        : ["Debug mode enabled", "Unpinned container image"].includes(
              finding.title,
            )
          ? "reliability"
          : "security") as Finding["category"],
      remediation: finding.detail,
      location: {
        line: before.split("\n").length,
        column: offset - before.lastIndexOf("\n"),
        path: "source",
      },
    };
  });
}

export function literalCredential(value: string): boolean {
  return (
    value.trim().length > 0 &&
    !/^(?:\$\{|\{\{|<[^>]+>$|process\.env\.|var\.|secrets?\.)/.test(value)
  );
}

export function externalHttp(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === "http:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
    );
  } catch {
    return false;
  }
}

export async function fetchPublicBotHints(token?: string): Promise<string[]> {
  try {
    const res = await fetch(`${getApiUrl()}/api/bots`, {
      signal: AbortSignal.timeout(10_000),
      headers: {
        Accept: "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
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
