import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, describe, it } from "node:test";
import { runScan } from "./cli.js";
import { collectPackages, lookupCves, type Pkg } from "./cves.js";

const dir = mkdtempSync(join(tmpdir(), "sa-cve-"));
const write = (name: string, text: string) => {
  const path = join(dir, name);
  writeFileSync(path, text);
  return path;
};
const npm = "https://registry.npmjs.org/";

describe("collectPackages", () => {
  it("reads npm v3 locks and skips private, linked and git packages", () => {
    const file = write("package-lock.json", JSON.stringify({
      packages: {
        "": { name: "app" },
        "node_modules/lodash": { version: "4.17.20", resolved: `${npm}lodash/-/lodash-4.17.20.tgz` },
        "node_modules/a/node_modules/@s/b": { version: "1.0.0", resolved: `${npm}@s/b/-/b-1.0.0.tgz` },
        "node_modules/internal": { version: "1.0.0", resolved: "https://npm.corp.example/internal.tgz" },
        "node_modules/local": { resolved: "../local", link: true },
        "node_modules/gitdep": { version: "1.0.0", resolved: "git+ssh://git@github.com/x/y.git" },
      },
    }));
    const { packages } = collectPackages([file]);
    assert.deepEqual(packages.map((p) => `${p.name}@${p.version}`), ["lodash@4.17.20", "@s/b@1.0.0"]);
    assert.ok(packages[0].line >= 1);
  });

  it("reads npm v1 locks", () => {
    const file = write("package-lock.json", JSON.stringify({
      dependencies: { a: { version: "1.0.0", resolved: `${npm}a/-/a-1.0.0.tgz`, dependencies: { b: { version: "2.0.0", resolved: `${npm}b/-/b-2.0.0.tgz` } } } },
    }));
    assert.deepEqual(collectPackages([file]).packages.map((p) => p.name), ["a", "b"]);
  });

  it("reads pnpm keys from v5, v6 and v9 and skips tarball sources", () => {
    const file = write("pnpm-lock.yaml", `packages:\n  /old/1.0.0:\n    resolution: {integrity: x}\n  /@s/mid@2.0.0(peer@1.0.0):\n    resolution: {integrity: x}\n  new@3.0.0:\n    resolution: {integrity: x}\n  odd@4.0.0:\n    resolution: {tarball: https://x.example/odd.tgz}\n`);
    assert.deepEqual(collectPackages([file]).packages.map((p) => `${p.name}@${p.version}`), ["old@1.0.0", "@s/mid@2.0.0", "new@3.0.0"]);
  });

  it("reads yarn v1 and berry locks", () => {
    const v1 = write("yarn.lock", `# yarn lockfile v1\n\n"@s/x@^1.0.0", "@s/x@^1.1.0":\n  version "1.2.0"\n  resolved "https://registry.yarnpkg.com/@s/x/-/x-1.2.0.tgz#abc"\n\ncorp@^1.0.0:\n  version "1.0.0"\n  resolved "https://npm.corp.example/corp.tgz"\n`);
    assert.deepEqual(collectPackages([v1]).packages.map((p) => `${p.name}@${p.version}`), ["@s/x@1.2.0"]);
    const dirBerry = mkdtempSync(join(tmpdir(), "sa-cve-berry-"));
    const berry = join(dirBerry, "yarn.lock");
    writeFileSync(berry, `__metadata:\n  version: 8\n\n"lodash@npm:^4.17.0":\n  version: 4.17.20\n  resolution: "lodash@npm:4.17.20"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n`);
    assert.deepEqual(collectPackages([berry]).packages.map((p) => `${p.name}@${p.version}`), ["lodash@4.17.20"]);
  });

  it("reads composer, requirements pins and go.sum", () => {
    const composer = write("composer.lock", JSON.stringify({ packages: [{ name: "Laravel/Framework", version: "v10.0.0" }, { name: "x/y", version: "dev-main" }], "packages-dev": [{ name: "p/q", version: "1.0.0" }] }));
    assert.deepEqual(collectPackages([composer]).packages.map((p) => `${p.name}@${p.version}`), ["laravel/framework@10.0.0", "p/q@1.0.0"]);
    const req = write("requirements.txt", "# c\nDjango==3.2.0\nrequests[security]==2.0.0 ; python_version>'3'\nflask>=2\n-r other.txt\nPyYAML == 5.3 # pin\n");
    assert.deepEqual(collectPackages([req]).packages.map((p) => `${p.name}@${p.version}`), ["django@3.2.0", "requests@2.0.0", "pyyaml@5.3"]);
    const sum = write("go.sum", "golang.org/x/text v0.3.5 h1:a\ngolang.org/x/text v0.3.5/go.mod h1:b\n");
    assert.deepEqual(collectPackages([sum]).packages.map((p) => `${p.name}@${p.version}`), ["golang.org/x/text@0.3.5"]);
  });

  it("sends no names from a custom-index requirements file or GOPRIVATE modules", () => {
    const req = write("requirements-private.txt", "--extra-index-url https://pypi.corp.example/simple\ncorp-lib==1.0.0\n");
    const sum = write("go.sum", "corp.example/x/y v1.0.0 h1:a\ngolang.org/x/text v0.3.5 h1:a\n");
    process.env.GOPRIVATE = "corp.example/*";
    try {
      assert.deepEqual(collectPackages([req, sum]).packages.map((p) => p.name), ["golang.org/x/text"]);
    } finally {
      delete process.env.GOPRIVATE;
    }
  });

  it("warns on a malformed lockfile and ignores other files", () => {
    const bad = write("package-lock.json", "{nope");
    const other = write("main.tf", "x");
    const out = collectPackages([bad, other]);
    assert.equal(out.packages.length, 0);
    assert.equal(out.warnings.length, 1);
  });
});

const pkg = (name: string, version = "1.0.0"): Pkg => ({ ecosystem: "npm", name, version, file: "package-lock.json", line: 3 });
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe("lookupCves", () => {
  it("maps severity, prefers the CVE alias and lists fixed versions", async () => {
    const calls: string[] = [];
    const stub = (async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method} ${url}`);
      if (url.endsWith("/querybatch")) return json({ results: [{ vulns: [{ id: "GHSA-1" }, { id: "GHSA-2" }] }, {}] });
      if (url.endsWith("GHSA-1")) return json({ id: "GHSA-1", aliases: ["CVE-2021-1"], summary: "bad", database_specific: { severity: "HIGH" }, affected: [{ package: { name: "a", ecosystem: "npm" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "1.0.1" }] }] }] });
      return json({ id: "GHSA-2", database_specific: { severity: "MODERATE" } });
    }) as typeof fetch;
    const found = await lookupCves([pkg("a"), pkg("b")], stub);
    assert.deepEqual(found.map((f) => [f.severity, f.ruleId, f.title, f.resource]), [
      ["high", "CVE001", "CVE-2021-1 in a@1.0.0", "a@1.0.0 CVE-2021-1"],
      ["medium", "CVE001", "GHSA-2 in a@1.0.0", "a@1.0.0 GHSA-2"],
    ]);
    assert.match(found[0].remediation!, /1\.0\.1/);
    assert.match(found[1].remediation!, /No fixed version/);
    assert.equal(calls.length, 3);
  });

  it("collapses GHSA and GO records of one CVE into the worst severity", async () => {
    const stub = (async (url: string) =>
      url.endsWith("/querybatch")
        ? json({ results: [{ vulns: [{ id: "GHSA-1" }, { id: "GO-1" }] }] })
        : json({ id: url.split("/").pop(), aliases: ["CVE-2021-9"], database_specific: url.endsWith("GO-1") ? { severity: "CRITICAL" } : undefined })) as typeof fetch;
    const found = await lookupCves([pkg("a")], stub);
    assert.deepEqual(found.map((f) => f.severity), ["critical"]);
  });

  it("sends 1000 packages per batch", async () => {
    const sizes: number[] = [];
    const stub = (async (_u: string, init?: RequestInit) => {
      const n = JSON.parse(String(init?.body)).queries.length;
      sizes.push(n);
      return json({ results: Array.from({ length: n }, () => ({})) });
    }) as typeof fetch;
    const many = Array.from({ length: 2500 }, (_, i) => pkg(`p${i}`));
    assert.deepEqual(await lookupCves(many, stub), []);
    assert.deepEqual(sizes, [1000, 1000, 500]);
  });

  it("throws on an HTTP error or a short result", async () => {
    await assert.rejects(lookupCves([pkg("a")], (async () => json({}, 503)) as typeof fetch), /HTTP 503/);
    await assert.rejects(lookupCves([pkg("a")], (async () => json({ results: [] })) as typeof fetch), /unexpected/);
  });
});

describe("scan --cves", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });
  const project = () => {
    const root = mkdtempSync(join(tmpdir(), "sa-cve-cli-"));
    const lock = join(root, "package-lock.json");
    writeFileSync(lock, JSON.stringify({ packages: { "node_modules/a": { version: "1.0.0", resolved: `${npm}a/-/a-1.0.0.tgz` } } }));
    return { root, lock };
  };
  const osvStub = (async (url: string) =>
    url.endsWith("/querybatch") ? json({ results: [{ vulns: [{ id: "GHSA-1" }] }] }) : json({ id: "GHSA-1", database_specific: { severity: "CRITICAL" } })) as typeof fetch;

  it("exits 1 on a critical CVE, and 0 when a baseline accepts it", async () => {
    const { root, lock } = project();
    globalThis.fetch = osvStub;
    const quiet = console.log;
    console.log = () => {};
    try {
      assert.equal(await runScan(["--cves", "--fail-on", "high", lock]), 1);
      const baseline = join(root, "baseline.json");
      writeFileSync(baseline, JSON.stringify({ version: 1, findings: [`CVE001|${relative(".", lock)}|a@1.0.0 GHSA-1`] }));
      assert.equal(await runScan(["--cves", "--fail-on", "high", "--baseline", baseline, lock]), 0);
    } finally {
      console.log = quiet;
    }
  });

  it("exits 2 when the lookup fails, and never calls the network without --cves", async () => {
    const { lock } = project();
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      throw new Error("offline");
    }) as typeof fetch;
    const quiet = [console.log, console.error];
    console.log = console.error = () => {};
    try {
      assert.equal(await runScan(["--cves", lock]), 2);
      assert.equal(calls, 1);
      assert.equal(await runScan([lock]), 0);
      assert.equal(calls, 1);
    } finally {
      [console.log, console.error] = quiet;
    }
  });
});
