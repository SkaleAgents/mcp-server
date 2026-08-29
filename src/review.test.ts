import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cannedFindings, countIacResources } from "./review.js";

describe("cannedFindings", () => {
  it("always includes a stub info finding", () => {
    const findings = cannedFindings("hello", "general");
    assert.equal(findings[0]?.severity, "info");
  });

  it("flags wide-open CIDR", () => {
    const findings = cannedFindings('cidr_blocks = ["0.0.0.0/0"]', "security");
    assert.ok(findings.some((f) => f.severity === "high"));
  });

  it("flags possible AWS keys", () => {
    const findings = cannedFindings("AKIAIOSFODNN7EXAMPLE", "security");
    assert.ok(findings.some((f) => f.severity === "critical"));
  });
});

describe("countIacResources", () => {
  it("counts terraform resource keywords", () => {
    const n = countIacResources(`
      resource "aws_s3_bucket" "a" {}
      resource "aws_s3_bucket" "b" {}
    `);
    assert.equal(n, 2);
  });
});
