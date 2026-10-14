import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { scanSecrets } from "./secrets.js";

// Built at runtime so secret scanners do not flag this test file.
const awsKey = ["AKIA", "ABCDEFGHIJKLMNOP"].join("");
const ghToken = ["ghp", "_", "a".repeat(36)].join("");

describe("scanSecrets", () => {
  const dir = mkdtempSync(join(tmpdir(), "sa-secret-"));
  const write = (name: string, text: string) => {
    const path = join(dir, name);
    writeFileSync(path, text);
    return path;
  };

  it("finds known token formats, never prints the value, and reports the line", () => {
    const file = write("app.js", `const a = 1;\nconst key = "${awsKey}";\nconst t = "${ghToken}";\n`);
    const { findings } = scanSecrets([file]);
    assert.deepEqual(findings.map((f) => [f.location?.line, f.ruleId]), [[2, "SECRET001"], [3, "SECRET001"]]);
    assert.ok(!JSON.stringify(findings).includes(awsKey));
    assert.ok(!JSON.stringify(findings).includes(ghToken));
    assert.notEqual(findings[0].resource, findings[1].resource);
  });

  it("honours skaleagents-ignore, skips binary and lock files, and ignores look-alikes", () => {
    const ignored = write("a.txt", `# skaleagents-ignore SECRET001 documented example\n${awsKey}\n`);
    const binary = write("b.dat", `\0${awsKey}`);
    const lock = write("pnpm-lock.yaml", awsKey);
    const lookalike = write("c.txt", "AKIA-not-a-key and ghp_short");
    const result = scanSecrets([ignored, binary, lock, lookalike]);
    assert.equal(result.findings.length, 0);
    assert.equal(result.suppressed, 1);
  });
});
