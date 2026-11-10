import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { extname, relative } from "node:path";
import { applySuppressions } from "./iac/scan.js";
import { parseIac, type Resource } from "./iac/parse.js";
import type { Finding, FindingSeverity } from "./review.js";

export const RULES_FILE = ".skaleagents-rules.json";
const safeValue = /^[\w.:/+=@*-]{1,200}$/;

/** Each rule gets its own id, so baselining or ignoring one rule on a resource never hides another. Letters then digits, to fit the ignore-comment syntax. */
export function ruleId(rule: HouseRule): string {
  const digest = createHash("sha1").update(JSON.stringify([rule.kind, rule.resourceType, rule.attribute, "value" in rule ? rule.value : ""])).digest();
  return `HOUSE${String(digest.readUInt32BE(0) % 1_000_000).padStart(6, "0")}`;
}

type Base = { resourceType: string; severity: Exclude<FindingSeverity, "info"> };
export type HouseRule =
  | (Base & { kind: "require_attribute"; attribute: string })
  | (Base & { kind: "require_tag"; attribute: string })
  | (Base & { kind: "forbid_value"; attribute: string; value: string });

const path = /^[A-Za-z_][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_-]{0,63}){0,7}$/;
const tag = /^[\w.:/+=@-]{1,128}$/;
const MAX_RULES = 25;

/** Reads the committed rules file. A malformed file is an error: a gate that silently stops checking is worse than a loud one. */
export function readRules(file = RULES_FILE): HouseRule[] {
  if (!existsSync(file)) return [];
  const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
  const list = (parsed as { rules?: unknown })?.rules;
  if (!Array.isArray(list) || list.length > MAX_RULES) throw new Error(`${file} must hold a "rules" list of at most ${MAX_RULES} rules`);
  return list.map((raw, index) => {
    const rule = raw as Record<string, unknown>;
    const ok = typeof rule === "object" && rule !== null
      && ["require_attribute", "require_tag", "forbid_value"].includes(rule.kind as string)
      && typeof rule.resourceType === "string" && /^[a-z][a-z0-9_]{1,63}$/.test(rule.resourceType)
      && typeof rule.attribute === "string" && (rule.kind === "require_tag" ? tag : path).test(rule.attribute)
      && ["low", "medium", "high", "critical"].includes(rule.severity as string)
      && (rule.kind !== "forbid_value" || (typeof rule.value === "string" && safeValue.test(rule.value)));
    if (!ok) throw new Error(`${file}: rule ${index + 1} is not valid`);
    return rule as unknown as HouseRule;
  });
}

export function sentence(rule: HouseRule): string {
  if (rule.kind === "require_tag") return `${rule.resourceType} must have the tag ${rule.attribute}`;
  if (rule.kind === "forbid_value") return `${rule.resourceType} must not set ${rule.attribute} to ${rule.value}`;
  return `${rule.resourceType} must set ${rule.attribute}`;
}

const record = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const computed = (value: unknown) => typeof value === "string" && /\$\{|%\{/.test(value);

/** Follows a dotted path; HCL blocks parse as one-item lists, so lists step into their first item. */
function lookup(body: unknown, steps: string[]): unknown {
  let value = body;
  for (const step of steps) {
    if (Array.isArray(value)) value = value[0];
    if (computed(value) || !record(value)) return computed(value) ? value : undefined;
    value = value[step];
  }
  return value;
}

function evaluate(rule: HouseRule, resource: Resource): "pass" | "fail" | "unknown" {
  if (rule.kind === "require_tag") {
    const tags = lookup(resource.value, ["tags"]) ?? lookup(resource.value, ["tags_all"]);
    if (computed(tags)) return "unknown";
    const found = record(tags) ? tags[rule.attribute] : undefined;
    return found === undefined || found === null || found === "" ? "fail" : "pass";
  }
  const value = lookup(resource.value, rule.attribute.split("."));
  if (computed(value)) return "unknown";
  if (rule.kind === "require_attribute") {
    return value === undefined || value === null || value === false || value === "" || (Array.isArray(value) && value.length === 0) ? "fail" : "pass";
  }
  const values = Array.isArray(value) ? value : [value];
  if (values.some(computed)) return "unknown";
  return values.some((item) => ["string", "number", "boolean"].includes(typeof item) && String(item) === rule.value) ? "fail" : "pass";
}

/** Checks Terraform files against the rules. Computed values are skipped, not flagged. */
export function ruleFindings(files: string[], rules: HouseRule[]): { findings: (Finding & { file: string })[]; suppressed: number; warnings: string[] } {
  const out: (Finding & { file: string })[] = [];
  const warnings: string[] = [];
  let suppressed = 0;
  let unknown = 0;
  if (!rules.length) return { findings: out, suppressed, warnings };
  for (const file of files.filter((name) => extname(name) === ".tf")) {
    const text = readFileSync(file, "utf8");
    let resources: Resource[];
    try {
      resources = parseIac(text, "terraform").resources;
    } catch {
      continue; // The regular scan already reports files it cannot parse.
    }
    const found: Finding[] = [];
    for (const rule of rules) {
      for (const resource of resources.filter((item) => item.type === rule.resourceType)) {
        const result = evaluate(rule, resource);
        if (result === "unknown") unknown += 1;
        if (result !== "fail") continue;
        found.push({
          severity: rule.severity,
          title: `House rule: ${sentence(rule)}`,
          detail: `${resource.id} breaks a rule in ${RULES_FILE} (${ruleId(rule)}).`,
          ruleId: ruleId(rule),
          resource: resource.id,
          remediation: rule.kind === "forbid_value" ? `Change ${rule.attribute} on ${resource.id}.`
            : rule.kind === "require_tag" ? `Add the ${rule.attribute} tag to ${resource.id}.`
            : `Set ${rule.attribute} on ${resource.id}.`,
          location: resource.locate(),
        });
      }
    }
    const result = applySuppressions(found, text);
    suppressed += result.suppressed;
    out.push(...result.kept.map((finding) => ({ ...finding, file: relative(".", file) })));
  }
  if (unknown) warnings.push(`${unknown} house rule check${unknown === 1 ? "" : "s"} skipped: the value is computed at apply time`);
  return { findings: out, suppressed, warnings };
}
