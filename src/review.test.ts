import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { architectureFindings, countIacResources } from "./review.js";

describe("architectureFindings", () => {
  it("always includes a structured review info finding", () => {
    const findings = architectureFindings("hello", "general");
    assert.equal(findings[0]?.severity, "info");
    assert.equal(findings[0]?.title, "Structured review completed");
  });

  it("flags wide-open CIDR", () => {
    const findings = architectureFindings('cidr_blocks = ["0.0.0.0/0"]', "security");
    assert.ok(findings.some((f) => f.severity === "high"));
  });

  it("flags possible AWS keys", () => {
    const findings = architectureFindings("AKIAIOSFODNN7EXAMPLE", "security");
    assert.ok(findings.some((f) => f.severity === "critical"));
  });

  it("flags hardcoded credentials and privileged containers", () => {
    const findings = architectureFindings(
      'password = "super-secret-value"\nprivileged: true',
      "security",
    );
    assert.ok(findings.some((f) => f.title === "Hardcoded credential-like value"));
    assert.ok(findings.some((f) => f.title === "Elevated container privileges"));
  });

  it("limits findings to the selected focus", () => {
    const findings = architectureFindings('debug: true\n0.0.0.0/0', "reliability");
    assert.ok(findings.some((f) => f.title === "Debug mode enabled"));
    assert.ok(!findings.some((f) => f.title === "Broad network exposure"));
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
