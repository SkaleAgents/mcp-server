import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import { once } from "node:events";
import { test } from "node:test";
import { buildProjection, withSavedReview } from "./saved-review.js";

test("a saved projection drops diffs and keeps the repository path", () => {
  const projection = buildProjection({
    tool: "scan_iac",
    target: { repository: "owner/name", path: "infra/main.tf", revision: "abc123" },
    submittedPaths: ["infra/main.tf"],
  }, {
    summary: "Fix these first: Database publicly accessible.",
    rulesEvaluated: ["DB001"],
    warnings: ["raw warning that must not be stored"],
    truncated: false,
    findings: [{
      ruleId: "DB001",
      severity: "high",
      title: "Database publicly accessible",
      detail: "The database enables public network access.",
      remediation: "Disable public accessibility.",
      resource: "aws_db_instance.app",
      location: { line: 1, path: "resource.aws_db_instance.app.publicly_accessible" },
      proposedChange: { from: "true", to: "false", diff: "---" },
    }],
  });

  assert.equal(projection.findings[0].path, "infra/main.tf");
  assert.equal("proposedChange" in projection.findings[0], false);
  assert.deepEqual(projection.checked, ["DB001"]);
  assert.deepEqual(projection.skipped, ["The scanner reported 1 warning."]);
  assert.equal(JSON.stringify(projection).includes("raw warning"), false);
});

test("a failed save still returns the finding payload", async () => {
  const original = process.env.SKALEAGENTS_OAUTH_ENABLED;
  process.env.SKALEAGENTS_OAUTH_ENABLED = "false";
  delete process.env.SKALEAGENTS_API_TOKEN;
  const output = await withSavedReview({
    status: "completed",
    summary: "No findings. That does not prove the system is secure.",
    findings: [],
  }, {
    tool: "review_architecture",
    target: null,
    submittedPaths: [""],
  });

  assert.equal(output.status, "completed");
  assert.equal((output.savedReview as { saved: boolean }).saved, false);
  assert.equal((output.savedReview as { shareUrl: null }).shareUrl, null);
  if (original === undefined) delete process.env.SKALEAGENTS_OAUTH_ENABLED;
  else process.env.SKALEAGENTS_OAUTH_ENABLED = original;
});

test("a successful save merges the review url", async () => {
  const original = {
    url: process.env.PLATFORM_API_URL,
    token: process.env.SKALEAGENTS_API_TOKEN,
  };
  let body = "";
  const api = createHttpServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      body = Buffer.concat(chunks).toString("utf8");
      response.statusCode = 201;
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({
        savedReview: {
          saved: true,
          id: "review-id",
          ownerUrl: "https://skaleagents.com/org/personal/reviews/review-id",
          shareUrl: "https://skaleagents.com/reviews/s/token",
          shareExpiresAt: "2026-10-13T12:00:00Z",
          comparison: "first",
          headline: "First review of this target.",
          assistantInstruction: "Report the headline and the one recommended change.",
        },
      }));
    });
  });
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  const address = api.address();
  assert.ok(address && typeof address !== "string");
  process.env.PLATFORM_API_URL = `http://127.0.0.1:${address.port}`;
  process.env.SKALEAGENTS_API_TOKEN = "server-test-token";
  try {
    const output = await withSavedReview({
      summary: "Fix these first: Database publicly accessible.",
      findings: [{ ruleId: "DB001", severity: "high", title: "Database publicly accessible" }],
      rulesEvaluated: ["DB001"],
    }, {
      tool: "scan_iac",
      target: { repository: "owner/name", path: "infra/main.tf" },
      submittedPaths: ["infra/main.tf"],
    });
    const saved = output.savedReview as { saved: boolean; shareUrl: string };
    assert.equal(saved.saved, true);
    assert.equal(saved.shareUrl, "https://skaleagents.com/reviews/s/token");
    assert.equal(JSON.parse(body).tool, "scan_iac");
    assert.equal(JSON.parse(body).content, undefined);
  } finally {
    api.closeAllConnections();
    await new Promise<void>((resolve) => api.close(() => resolve()));
    for (const [key, value] of Object.entries({ PLATFORM_API_URL: original.url, SKALEAGENTS_API_TOKEN: original.token })) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
