import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { architectureFindings } from "./review.js";

describe("architectureFindings", () => {
  it("distinguishes HTTPS and loopback from external HTTP without hostname prefix bypasses", () => {
    for (const url of [
      "https://example.com",
      "http://localhost:3000/",
      "http://127.0.0.1:80/",
      "http://[::1]/",
    ]) {
      assert.ok(
        !architectureFindings(`url = "${url}"`, "security").some(
          (f) => f.title === "Unencrypted HTTP endpoint",
        ),
      );
    }
    for (const url of [
      "http://example.com",
      "http://localhost.attacker.example",
      "http://127.0.0.1.attacker.example",
    ]) {
      assert.ok(
        architectureFindings(`url = "${url}"`, "security").some(
          (f) => f.title === "Unencrypted HTTP endpoint",
        ),
      );
    }
  });
  it("does not let an unrelated environment reference hide a literal credential", () => {
    const findings = architectureFindings(
      'const apiKey = process.env.API_KEY;\nconst password = "example-test-only";',
      "security",
    );
    const credential = findings.find(
      (f) => f.title === "Hardcoded credential-like value",
    );
    assert.equal(credential?.location?.line, 2);
    assert.ok(credential?.remediation);
    assert.ok(!JSON.stringify(findings).includes("example-test-only"));
    assert.ok(
      !architectureFindings('password = "${var.password}"', "security").some(
        (f) => f.title === "Hardcoded credential-like value",
      ),
    );
  });
  it("always includes a structured review info finding", () => {
    const findings = architectureFindings("hello", "general");
    assert.equal(findings[0]?.severity, "info");
    assert.equal(findings[0]?.title, "Structured review completed");
  });

  it("flags wide-open CIDR", () => {
    const findings = architectureFindings(
      'cidr_blocks = ["0.0.0.0/0"]',
      "security",
    );
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
    assert.ok(
      findings.some((f) => f.title === "Hardcoded credential-like value"),
    );
    assert.ok(
      findings.some((f) => f.title === "Elevated container privileges"),
    );
  });

  it("limits findings to the selected focus", () => {
    const findings = architectureFindings(
      "debug: true\n0.0.0.0/0",
      "reliability",
    );
    assert.ok(findings.some((f) => f.title === "Debug mode enabled"));
    assert.ok(!findings.some((f) => f.title === "Broad network exposure"));
  });
});
