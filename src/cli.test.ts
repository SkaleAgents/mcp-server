import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { scanFiles } from "./cli.js";
import { scanIac } from "./iac/scan.js";

const bucket = 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n';

describe("suppressions", () => {
  it("drops only the named rule on the next line and counts it", () => {
    const plain = scanIac(bucket);
    const ignored = scanIac(`# skaleagents-ignore DATA001 public site\n${bucket}`);
    assert.ok(plain.findings.some((f) => f.ruleId === "DATA001"));
    assert.ok(!ignored.findings.some((f) => f.ruleId === "DATA001"));
    assert.equal(ignored.findings.length, plain.findings.length - 1);
    assert.equal(ignored.suppressedFindings, 1);
    assert.equal(scanIac(`# skaleagents-ignore DATA0011\n${bucket}`).suppressedFindings, 0);
  });

  it("uses per-file lines in multi-file input", () => {
    const content = `----- skaleagents-file: a.tf -----\n# skaleagents-ignore DATA001\n${bucket}----- skaleagents-file: b.tf -----\n${bucket.replace('"b"', '"c"')}`;
    const result = scanIac(content);
    assert.equal(result.suppressedFindings, 1);
    assert.ok(result.findings.some((f) => f.ruleId === "DATA001" && f.resource?.startsWith("b.tf:")));
  });
});

describe("scanFiles", () => {
  it("maps findings back to relative file paths and skips non-IaC JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "sa-cli-"));
    mkdirSync(join(dir, "infra"));
    writeFileSync(join(dir, "infra", "main.tf"), bucket);
    writeFileSync(join(dir, "infra", "settings.json"), '{"a":1}');
    const { findings } = scanFiles([join(dir, "infra", "main.tf"), join(dir, "infra", "settings.json")]);
    const finding = findings.find((f) => f.ruleId === "DATA001");
    assert.ok(finding?.file.endsWith(join("infra", "main.tf")));
    assert.equal(finding?.resource, "aws_s3_bucket.b");
    assert.equal(finding?.location?.line, 1);
  });
});

describe("suppression parsing", () => {
  it("does not treat rule-like words in the reason as rule IDs", () => {
    const result = scanIac(`# skaleagents-ignore DATA003 see DATA001\n${bucket}`);
    assert.equal(result.suppressedFindings, 1);
    assert.ok(result.findings.some((f) => f.ruleId === "DATA001"));
  });
});
