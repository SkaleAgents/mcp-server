import { getApiToken, getApiUrl } from "./config.js";

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export type Finding = {
  severity: FindingSeverity;
  title: string;
  detail: string;
};

export function cannedFindings(content: string, focus: string): Finding[] {
  const findings: Finding[] = [
    {
      severity: "info",
      title: "Stub review",
      detail: `Phase 1 canned review (focus=${focus}). Length=${content.length} chars.`,
    },
  ];
  if (/0\.0\.0\.0(?:\/0)?/.test(content)) {
    findings.push({
      severity: "high",
      title: "Broad network exposure",
      detail: "Detected a possible wide-open CIDR or bind address.",
    });
  }
  if (/AKIA[0-9A-Z]{16}/.test(content)) {
    findings.push({
      severity: "critical",
      title: "Possible AWS access key",
      detail: "Remove secrets from source; rotate credentials.",
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
