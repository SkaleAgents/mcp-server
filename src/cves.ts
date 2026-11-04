import { readFileSync, statSync } from "node:fs";
import { basename, relative } from "node:path";
import { parse as parseYaml } from "yaml";
import { severityRank } from "./iac/scan.js";
import type { Finding, FindingSeverity } from "./review.js";

export type Ecosystem = "npm" | "Packagist" | "PyPI" | "Go";
export type Pkg = { ecosystem: Ecosystem; name: string; version: string; file: string; line: number };
export type CveFinding = Finding & { file: string };

const maxLockBytes = 20_000_000;
const batchSize = 1000;
const detailParallelism = 10;
const timeoutMs = 15_000;
const osv = "https://api.osv.dev/v1";
const publicNpm = /^https:\/\/registry\.(npmjs\.org|yarnpkg\.com)\//;

type Entry = [ecosystem: Ecosystem, name: string, version: string];

// npm entries must resolve to the public registry, so private package names are not sent to a third party.
function npmLock(text: string): Entry[] {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; resolved?: string; link?: boolean }>;
    dependencies?: Record<string, { version?: string; resolved?: string; dependencies?: unknown }>;
  };
  const out: Entry[] = [];
  for (const [key, p] of Object.entries(lock.packages ?? {})) {
    const at = key.lastIndexOf("node_modules/");
    if (at < 0 || p.link || !p.version || !publicNpm.test(p.resolved ?? "")) continue;
    out.push(["npm", key.slice(at + "node_modules/".length), p.version]);
  }
  const walk = (deps: NonNullable<typeof lock.dependencies>) => {
    for (const [name, p] of Object.entries(deps)) {
      if (p.version && publicNpm.test(p.resolved ?? "")) out.push(["npm", name, p.version]);
      if (p.dependencies) walk(p.dependencies as NonNullable<typeof lock.dependencies>);
    }
  };
  if (!lock.packages) walk(lock.dependencies ?? {});
  return out;
}

function pnpmLock(text: string): Entry[] {
  const lock = parseYaml(text) as { packages?: Record<string, { resolution?: { tarball?: string; type?: string } }> } | null;
  const out: Entry[] = [];
  for (const [rawKey, p] of Object.entries(lock?.packages ?? {})) {
    if (p?.resolution?.type || p?.resolution?.tarball) continue; // git, directory and tarball sources
    const key = rawKey.replace(/^\//, "").replace(/\(.*$/, "");
    const at = key.lastIndexOf("@");
    if (at > 0) out.push(["npm", key.slice(0, at), key.slice(at + 1)]);
    else {
      const slash = key.lastIndexOf("/"); // pnpm v5: name/version
      if (slash > 0) out.push(["npm", key.slice(0, slash), key.slice(slash + 1)]);
    }
  }
  return out;
}

function yarnLock(text: string): Entry[] {
  const out: Entry[] = [];
  if (text.includes("__metadata:")) {
    const lock = parseYaml(text) as Record<string, { version?: string; resolution?: string }>;
    for (const [key, p] of Object.entries(lock)) {
      if (key === "__metadata" || !p?.version || !p.resolution?.includes("@npm:")) continue;
      const name = p.resolution.slice(0, p.resolution.indexOf("@npm:"));
      if (name) out.push(["npm", name, p.version]);
    }
    return out;
  }
  for (const block of text.split(/\n\n+/)) {
    const lines = block.split("\n").filter((l) => !l.startsWith("#"));
    const header = lines[0]?.replace(/:$/, "").split(",")[0]?.trim().replace(/^"|"$/g, "");
    const version = /^\s+version "([^"]+)"/m.exec(block)?.[1];
    const resolved = /^\s+resolved "([^"]+)"/m.exec(block)?.[1] ?? "";
    const at = header?.lastIndexOf("@") ?? -1;
    if (header && version && at > 0 && publicNpm.test(resolved)) out.push(["npm", header.slice(0, at), version]);
  }
  return out;
}

function composerLock(text: string): Entry[] {
  const lock = JSON.parse(text) as Record<string, { name?: string; version?: string }[] | undefined>;
  return [...(lock.packages ?? []), ...(lock["packages-dev"] ?? [])]
    .filter((p) => p.name && p.version && !p.version.startsWith("dev-"))
    .map((p): Entry => ["Packagist", p.name!.toLowerCase(), p.version!.replace(/^v/, "")]);
}

// Exact == pins only: a range does not say which version is installed.
function requirements(text: string): Entry[] {
  const out: Entry[] = [];
  // A custom index may host private names, and the file does not say which ones.
  if (process.env.PIP_INDEX_URL || process.env.PIP_EXTRA_INDEX_URL || /^\s*(?:-i|--index-url|--extra-index-url|-f|--find-links)/m.test(text)) return out;
  for (const line of text.split("\n")) {
    const m = /^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.!+-]+)\s*(?:[;#\\]|$)/.exec(line.trim());
    if (m) out.push(["PyPI", m[1].toLowerCase().replace(/[_.]+/g, "-"), m[2]]);
  }
  return out;
}

// Go semantics: a pattern of N slash elements is glob-matched against the first N elements of the module path.
function goPrefixMatch(pattern: string, path: string) {
  const want = pattern.split("/");
  const have = path.split("/");
  if (have.length < want.length) return false;
  return want.every((w, i) => new RegExp(`^${w.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")}$`).test(have[i]));
}

function goSum(text: string): Entry[] {
  const out: Entry[] = [];
  const priv = [process.env.GOPRIVATE, process.env.GONOPROXY, process.env.GONOSUMDB].flatMap((v) => (v ?? "").split(",")).map((g) => g.trim()).filter(Boolean);
  for (const line of text.split("\n")) {
    const [name, version] = line.split(/\s+/);
    if (name && priv.some((g) => goPrefixMatch(g, name))) continue;
    if (name && version?.startsWith("v") && !version.endsWith("/go.mod")) out.push(["Go", name, version.slice(1)]);
  }
  return out;
}

const parsers: [RegExp, (text: string) => Entry[]][] = [
  [/^package-lock\.json$/, npmLock],
  [/^pnpm-lock\.yaml$/, pnpmLock],
  [/^yarn\.lock$/, yarnLock],
  [/^composer\.lock$/, composerLock],
  [/^requirements[^/\\]*\.txt$/, requirements],
  [/^go\.sum$/, goSum],
];

export function collectPackages(files: string[]) {
  const packages: Pkg[] = [];
  const warnings: string[] = [];
  const seen = new Set<string>();
  for (const path of files) {
    const name = basename(path);
    const parse = parsers.find(([re]) => re.test(name))?.[1];
    if (!parse) continue;
    const file = relative(".", path);
    try {
      if (statSync(path).size > maxLockBytes) throw new Error("file too large");
      const text = readFileSync(path, "utf8");
      const lines = text.split("\n");
      for (const [ecosystem, pkg, version] of parse(text)) {
        const key = `${file}\0${ecosystem}\0${pkg}\0${version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        // shortcut: first line that mentions the name, not the exact entry; upgrade if line numbers matter to users.
        const hit = lines.findIndex((l) => l.includes(pkg) && l.includes(version));
        const any = hit >= 0 ? hit : lines.findIndex((l) => l.includes(pkg));
        packages.push({ ecosystem, name: pkg, version, file, line: any + 1 || 1 });
      }
    } catch (error) {
      warnings.push(`${file}: could not read lockfile: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return { packages, warnings };
}

type Vuln = {
  id: string;
  aliases?: string[];
  summary?: string;
  database_specific?: { severity?: string };
  affected?: { package?: { name?: string; ecosystem?: string }; ranges?: { events?: { fixed?: string }[] }[] }[];
};

const severityOf = (v: Vuln): FindingSeverity => {
  switch (v.database_specific?.severity?.toUpperCase()) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "LOW": return "low";
    default: return "medium"; // shortcut: no CVSS vector scoring, so unrated advisories read as medium.
  }
};

async function osvFetch(fetchImpl: typeof fetch, url: string, body?: unknown) {
  const res = await fetchImpl(url, {
    method: body ? "POST" : "GET",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`${url} answered HTTP ${res.status}`);
  return (await res.json()) as unknown;
}

// Throws on any network or HTTP failure: a scan that could not check must not look clean.
export async function lookupCves(packages: Pkg[], fetchImpl: typeof fetch = fetch): Promise<CveFinding[]> {
  const hits: [Pkg, string][] = [];
  for (let i = 0; i < packages.length; i += batchSize) {
    const chunk = packages.slice(i, i + batchSize);
    const data = (await osvFetch(fetchImpl, `${osv}/querybatch`, {
      queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })),
    })) as { results?: { vulns?: { id: string }[] }[] };
    if (data.results?.length !== chunk.length) throw new Error("OSV returned an unexpected batch result");
    chunk.forEach((p, j) => data.results![j].vulns?.forEach((v) => hits.push([p, v.id])));
  }
  const ids = [...new Set(hits.map(([, id]) => id))];
  const details = new Map<string, Vuln>();
  for (let i = 0; i < ids.length; i += detailParallelism) {
    await Promise.all(
      ids.slice(i, i + detailParallelism).map(async (id) => {
        details.set(id, (await osvFetch(fetchImpl, `${osv}/vulns/${encodeURIComponent(id)}`)) as Vuln);
      }),
    );
  }
  // One advisory often has GHSA, GO and PYSEC records for the same CVE: keep one per CVE, at its worst severity.
  const byCve = new Map<string, CveFinding>();
  for (const [p, id] of hits) {
    const v = details.get(id)!;
    const display = v.aliases?.find((a) => a.startsWith("CVE-")) ?? id;
    const fixed = [
      ...new Set(
        (v.affected ?? [])
          .filter((a) => a.package?.name?.toLowerCase() === p.name.toLowerCase() && a.package.ecosystem === p.ecosystem)
          .flatMap((a) => a.ranges ?? [])
          .flatMap((r) => r.events ?? [])
          .map((e) => e.fixed)
          .filter(Boolean),
      ),
    ];
    const finding: CveFinding = {
      severity: severityOf(v),
      category: "security",
      ruleId: "CVE001",
      title: `${display} in ${p.name}@${p.version}`,
      detail: v.summary ?? `${id} affects ${p.name}@${p.version}.`,
      remediation: fixed.length ? `Upgrade ${p.name} to a fixed version: ${fixed.slice(0, 4).join(", ")}${fixed.length > 4 ? ", ..." : ""}.` : `No fixed version of ${p.name} is published yet. Check ${id} on osv.dev.`,
      resource: `${p.name}@${p.version} ${display}`,
      location: { line: p.line, column: 1, path: p.name },
      file: p.file,
    };
    const key = `${p.file}\0${finding.resource}`;
    const seen = byCve.get(key);
    if (!seen || severityRank[finding.severity] > severityRank[seen.severity]) byCve.set(key, finding);
  }
  return [...byCve.values()];
}
