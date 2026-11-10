import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { readRules, ruleFindings, type HouseRule } from "./house-rules.js";

const tf = `resource "aws_s3_bucket" "logs" {
  tags = { owner = "ops" }
  versioning { enabled = true }
}
resource "aws_s3_bucket" "raw" {
  acl = "public-read"
}
# skaleagents-ignore HOUSE001 scratch bucket
resource "aws_s3_bucket" "scratch" {
  acl = "public-read"
}
resource "aws_s3_bucket" "shared" {
  tags = var.tags
}
`;
const rules: HouseRule[] = [
  { kind: "require_attribute", resourceType: "aws_s3_bucket", attribute: "versioning.enabled", severity: "medium" },
  { kind: "require_tag", resourceType: "aws_s3_bucket", attribute: "owner", severity: "low" },
  { kind: "forbid_value", resourceType: "aws_s3_bucket", attribute: "acl", value: "public-read", severity: "high" },
];
const dir = mkdtempSync(join(tmpdir(), "rules-"));
const write = (name: string, text: string) => { const file = join(dir, name); writeFileSync(file, text); return file; };

describe("house rules", () => {
  it("flags missing attributes and tags and forbidden values, honours ignore comments and skips computed values", () => {
    const result = ruleFindings([write("main.tf", tf)], rules);
    assert.deepEqual(result.findings.map((f) => [f.resource, f.severity, f.title]), [
      ["aws_s3_bucket.raw", "medium", "House rule: aws_s3_bucket must set versioning.enabled"],
      ["aws_s3_bucket.shared", "medium", "House rule: aws_s3_bucket must set versioning.enabled"],
      ["aws_s3_bucket.raw", "low", "House rule: aws_s3_bucket must have the tag owner"],
      ["aws_s3_bucket.raw", "high", "House rule: aws_s3_bucket must not set acl to public-read"],
    ]);
    assert.equal(result.suppressed, 3);
    assert.match(result.warnings.join(), /1 house rule check skipped/);
  });

  it("does nothing without rules or for non-Terraform files", () => {
    assert.equal(ruleFindings([write("a.tf", tf)], []).findings.length, 0);
    assert.equal(ruleFindings([write("a.yaml", tf)], rules).findings.length, 0);
  });

  it("reads a rules file and rejects a malformed one loudly", () => {
    assert.equal(readRules(join(dir, "missing.json")).length, 0);
    assert.equal(readRules(write("ok.json", JSON.stringify({ rules }))).length, 3);
    assert.throws(() => readRules(write("bad.json", JSON.stringify({ rules: [{ kind: "require_tag", resourceType: "Bad Type", attribute: "x", severity: "low" }] }))), /rule 1 is not valid/);
    assert.throws(() => readRules(write("bad2.json", "{}")), /"rules" list/);
  });
});

describe("scan integration", () => {
  it("applies .skaleagents-rules.json automatically and fails on a malformed file", async () => {
    const { runScan } = await import("./cli.js");
    const repo = mkdtempSync(join(tmpdir(), "rules-repo-"));
    writeFileSync(join(repo, "main.tf"), 'resource "aws_s3_bucket" "x" {\n  bucket = "x"\n}\n');
    const previous = process.cwd();
    const log = console.log;
    console.log = () => {};
    process.chdir(repo);
    try {
      assert.equal(await runScan(["--fail-on", "high"]), 0);
      writeFileSync(join(repo, ".skaleagents-rules.json"), JSON.stringify({ rules: [{ kind: "require_tag", resourceType: "aws_s3_bucket", attribute: "owner", severity: "high" }] }));
      assert.equal(await runScan(["--fail-on", "high"]), 1);
      writeFileSync(join(repo, ".skaleagents-rules.json"), "{ nope");
      assert.equal(await runScan(["--fail-on", "high"]), 2);
    } finally {
      process.chdir(previous);
      console.log = log;
    }
  });
});
