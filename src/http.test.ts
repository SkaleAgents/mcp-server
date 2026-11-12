import assert from "node:assert/strict";
import { after, before, mock, test } from "node:test";
import { handleMcpRequest, protectedResourceMetadata } from "./http.js";

process.env.MCP_HTTP_WORKERS = "0";
const realFetch = globalThis.fetch;
const url = "https://skaleagents.com";
let active = true;
let audience = `${url}/mcp`;
let unavailable = false;
let expiresAt: number | undefined;
let osvDown = false;
let usage: "ok" | "limit" | "down" | "other" = "ok";
let calls: { url: string; authorization: string | null }[] = [];
const tokenChecks = () => calls.filter((c) => c.url.endsWith("/api/oauth/mcp-token")).length;
before(async () => {
  globalThis.fetch = async (input, init) => {
    const target = String(input);
    if (target === `${url}/mcp`)
      return handleMcpRequest(new Request(target, init));
    calls.push({
      url: target,
      authorization: new Headers(init?.headers).get("Authorization"),
    });
    if (target.endsWith("/api/oauth/mcp-token"))
      return Response.json(
        {
          active,
          resource: audience,
          scope: "mcp",
          expiresAt: expiresAt ?? Date.now() / 1000 + 3600,
        },
        { status: unavailable ? 503 : active ? 200 : 401 },
      );
    if (target.endsWith("/api/mcp/usage")) {
      if (usage === "down") throw new Error("API unreachable");
      if (usage === "other") return Response.json({ code: "something_else" }, { status: 429 });
      if (usage === "limit")
        return Response.json({ code: "mcp_scan_limit_reached", upgradeMessage: "You've used all 100 MCP scans on your plan this month." }, { status: 429 });
      return Response.json({ used: 1, limit: 100, enforced: true });
    }
    if (target.endsWith("/api/bots")) return Response.json({ bots: [] });
    if (target.startsWith("https://api.osv.dev/")) {
      if (osvDown) return new Response("down", { status: 503 });
      if (target.endsWith("/querybatch")) {
        const { queries } = JSON.parse(String(init?.body));
        return Response.json({ results: queries.map((q: { package: { name: string } }) => (q.package.name === "lodash" ? { vulns: [{ id: "GHSA-1" }] } : {})) });
      }
      return Response.json({ id: "GHSA-1", aliases: ["CVE-2021-23337"], database_specific: { severity: "HIGH" } });
    }
    throw new Error("Unexpected outbound request");
  };
});
after(async () => {
  globalThis.fetch = realFetch;
});

function call(method: string, params: unknown, token = "remote-test") {
  return fetch(`${url}/mcp`, {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
}

test("unauthenticated remote clients discover OAuth through the challenge", async () => {
  const response = await fetch(`${url}/mcp`);
  assert.equal(response.status, 401);
  assert.match(
    response.headers.get("www-authenticate")!,
    /resource_metadata=.*oauth-protected-resource\/mcp/,
  );
  const metadata = await protectedResourceMetadata().json();
  assert.equal(metadata.resource, audience);
  assert.deepEqual(metadata.authorization_servers, [
    "https://api.skaleagents.com",
  ]);
});

test("authenticated stateless clients initialize list and call shared review tools", async () => {
  calls = [];
  const initialization = await call("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "test", version: "1" },
  });
  assert.equal(initialization.status, 200);
  assert.equal(
    (await initialization.json()).result.serverInfo.name,
    "skaleagents-swarm",
  );
  const tools = await (await call("tools/list", {})).json();
  assert.deepEqual(
    tools.result.tools.map((tool: { name: string }) => tool.name).sort(),
    [
      "plan_architecture_review",
      "review_application_architecture",
      "review_architecture",
      "scan_dependencies",
      "scan_iac",
      "scan_iac_stub",
    ],
  );
  // Tools that save a review to the account write data, so they are not read-only.
  assert.deepEqual(
    Object.fromEntries(
      tools.result.tools.map(
        (tool: { name: string; annotations: { readOnlyHint: boolean } }) => [
          tool.name,
          tool.annotations.readOnlyHint,
        ],
      ),
    ),
    {
      plan_architecture_review: true,
      review_application_architecture: false,
      review_architecture: false,
      scan_dependencies: true,
      scan_iac: false,
      scan_iac_stub: false,
    },
  );
  const review = await (
    await call("tools/call", {
      name: "review_architecture",
      arguments: { content: 'cidr_blocks = ["0.0.0.0/0"]', focus: "security" },
    })
  ).json();
  assert.equal(review.result.isError, undefined);
  assert.ok(
    JSON.parse(review.result.content[0].text).findings.some(
      (finding: { title: string }) =>
        finding.title === "Broad network exposure",
    ),
  );
  assert.equal(
    calls.find((c) => c.url.endsWith("/api/oauth/mcp-token"))?.authorization,
    "Bearer remote-test",
  );
  assert.equal(
    calls.find((c) => c.url.endsWith("/api/bots"))?.authorization,
    null,
  );
});

test("scanner and compatibility alias return parsed findings and structured content", async () => {
  for (const name of ["scan_iac", "scan_iac_stub", "review_architecture"]) {
    const response = await (
      await call("tools/call", {
        name,
        arguments: {
          content:
            'resource "aws_db_instance" "test" { publicly_accessible = true }',
          format: "terraform",
          focus: "security",
        },
      })
    ).json();
    assert.equal(response.result.isError, undefined);
    const output = response.result.structuredContent;
    assert.equal(output.status, "completed");
    assert.equal(output.parsedResourceCount, 1);
    assert.equal(output.findings[0].ruleId, "DB001");
    assert.deepEqual(output, JSON.parse(response.result.content[0].text));
  }
});

test("whole-application consultation advances with context and exposes a reusable prompt", async () => {
  const initial = await (
    await call("tools/call", {
      name: "plan_architecture_review",
      arguments: { filePaths: ["package.json", "app/page.tsx"] },
    })
  ).json();
  assert.equal(initial.result.structuredContent.nextQuestions[0].id, "purpose");
  const reviewed = await (
    await call("tools/call", {
      name: "review_application_architecture",
      arguments: {
        files: [
          {
            path: "app/page.tsx",
            content:
              '"use client"; import fs from "node:fs"; export default function Page(){return <div/>}',
          },
        ],
        context: {
          purpose: "Customer portal",
          criticalFlows: "Sign in and view projects",
          accessControl: "API ownership checks",
        },
      },
    })
  ).json();
  const report = reviewed.result.structuredContent;
  assert.equal(report.verdict, "needs_changes");
  assert.ok(
    report.findings.some((f: { ruleId: string }) => f.ruleId === "NEXT001"),
  );
  assert.equal(report.nextQuestions[0].id, "data");
  assert.deepEqual(report, JSON.parse(reviewed.result.content[0].text));
  const unrelated = await (
    await call("tools/call", {
      name: "plan_architecture_review",
      arguments: { filePaths: [] },
    })
  ).json();
  assert.equal(
    unrelated.result.structuredContent.nextQuestions[0].id,
    "purpose",
  );
  const prompts = await (await call("prompts/list", {})).json();
  assert.ok(
    prompts.result.prompts.some(
      (p: { name: string }) => p.name === "architecture_consultation",
    ),
  );
  const prompt = await (
    await call("prompts/get", {
      name: "architecture_consultation",
      arguments: { goal: "Review this Next.js app" },
    })
  ).json();
  assert.match(
    prompt.result.messages[0].content.text,
    /review_application_architecture/,
  );
  assert.match(
    prompt.result.messages[0].content.text,
    /Review this Next\.js app/,
  );
});

test("consultation validates batch limits and rejects unauthorized requests", async () => {
  const files = Array.from({ length: 4 }, (_, i) => ({
    path: `part${i}.ts`,
    content: " ".repeat(130_000),
  }));
  const response = await (
    await call("tools/call", {
      name: "review_application_architecture",
      arguments: { files },
    })
  ).json();
  assert.equal(response.result.isError, true);
  assert.match(response.result.content[0].text, /500,000/);
  active = false;
  try {
    assert.equal(
      (
        await call("tools/call", {
          name: "plan_architecture_review",
          arguments: { filePaths: [] },
        }, "revoked-consult")
      ).status,
      401,
    );
  } finally {
    active = true;
  }
});

test("tool errors reject malformed IaC, whitespace, invalid filters and excessive content", async () => {
  for (const arguments_ of [
    { content: "resource {", format: "terraform" },
    { content: "  \n" },
    { content: "x", format: "xml" },
    { content: "x", maxFindings: 0 },
    { content: "x", minSeverity: "urgent" },
    { content: "x".repeat(500_001) },
  ]) {
    const response = await (
      await call("tools/call", { name: "scan_iac", arguments: arguments_ })
    ).json();
    assert.equal(response.result?.isError ?? !!response.error, true);
  }
});

test("revoked credentials and wrong-audience credentials cannot call tools", async () => {
  active = false;
  assert.equal((await call("tools/list", {}, "revoked-tools")).status, 401);
  active = true;
  audience = "https://another.example/mcp";
  assert.equal((await call("tools/list", {}, "wrong-audience")).status, 401);
  audience = `${url}/mcp`;
});

test("caches successful validations for 60 seconds and never beyond token expiry", async (t) => {
  t.mock.timers.enable({ apis: ["Date"] });
  const before = tokenChecks();
  const token = "cache-expiry";
  assert.equal((await call("tools/list", {}, token)).status, 200);
  assert.equal(tokenChecks(), before + 1);
  t.mock.timers.tick(59_000);
  assert.equal((await call("tools/list", {}, token)).status, 200);
  assert.equal(tokenChecks(), before + 1, "cache hit within the TTL");
  t.mock.timers.tick(2_000);
  assert.equal((await call("tools/list", {}, token)).status, 200);
  assert.equal(tokenChecks(), before + 2, "revalidates after the TTL");

  const short = "cache-short-life";
  expiresAt = Date.now() / 1000 + 10;
  try {
    assert.equal((await call("tools/list", {}, short)).status, 200);
    t.mock.timers.tick(10_000);
    assert.equal((await call("tools/list", {}, short)).status, 401);
  } finally {
    expiresAt = undefined;
  }
});

test("does not cache rejected or unavailable validations", async () => {
  const token = "not-cached-failure";
  active = false;
  try {
    assert.equal((await call("tools/list", {}, token)).status, 401);
    assert.equal((await call("tools/list", {}, token)).status, 401);
  } finally {
    active = true;
  }
  const before = tokenChecks();
  assert.equal((await call("tools/list", {}, token)).status, 200);
  assert.equal(tokenChecks(), before + 1, "the rejected token was validated again");
  const outage = "not-cached-outage";
  unavailable = true;
  try {
    assert.equal((await call("tools/list", {}, outage)).status, 503);
  } finally {
    unavailable = false;
  }
  assert.equal((await call("tools/list", {}, outage)).status, 200);
});

test("fails closed when authorization is unavailable and rejects malformed or oversized requests", async () => {
  unavailable = true;
  assert.equal((await call("tools/list", {}, "outage-check")).status, 503);
  unavailable = false;
  const headers = {
    Authorization: "Bearer remote-test",
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  assert.equal(
    (await fetch(`${url}/mcp`, { method: "POST", headers, body: "{" })).status,
    400,
  );
  assert.equal(
    (
      await fetch(`${url}/mcp`, {
        method: "POST",
        headers,
        body: "x".repeat(2_100_001),
      })
    ).status,
    413,
  );
  assert.equal(
    (await fetch(`${url}/mcp`, { method: "GET", headers })).status,
    405,
  );
  const notified = await fetch(`${url}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    }),
  });
  assert.equal(notified.status, 202);
});

test("rejects untrusted origins and supports connector preflight", async () => {
  assert.equal(
    (await fetch(`${url}/mcp`, { headers: { Origin: "https://evil.example" } }))
      .status,
    403,
  );
  const preflight = await fetch(`${url}/mcp`, {
    method: "OPTIONS",
    headers: { Origin: "https://claude.ai" },
  });
  assert.equal(preflight.status, 204);
  assert.match(
    preflight.headers.get("access-control-allow-headers")!,
    /Authorization/,
  );
});

test("scan_dependencies reports CVEs from a pasted lockfile and never a clean result when OSV is down", async () => {
  const lock = JSON.stringify({
    packages: {
      "node_modules/lodash": { version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
      "node_modules/other": { version: "1.0.0", resolved: "https://registry.npmjs.org/other/-/other-1.0.0.tgz" },
      "node_modules/private": { version: "1.0.0", resolved: "https://npm.corp.example/private.tgz" },
    },
  });
  const run = async (arguments_: unknown) =>
    (await (await call("tools/call", { name: "scan_dependencies", arguments: arguments_ })).json()).result;
  const ok = await run({ content: lock, filename: "package-lock.json" });
  assert.equal(ok.isError, undefined);
  assert.equal(ok.structuredContent.packagesChecked, 2);
  assert.deepEqual(ok.structuredContent.findings.map((f: { title: string }) => f.title), ["CVE-2021-23337 in lodash@4.17.20"]);
  assert.ok(!JSON.stringify(ok).includes("corp.example"));
  assert.equal((await run({ content: "{nope", filename: "package-lock.json" })).isError, true);
  assert.equal((await run({ content: lock, filename: "Gemfile.lock" })).isError ?? true, true);
  osvDown = true;
  try {
    const down = await run({ content: lock, filename: "package-lock.json" });
    assert.equal(down.isError, true);
    assert.match(down.content[0].text, /lookup_failed/);
  } finally {
    osvDown = false;
  }
});

const usageCalls = () => calls.filter((c) => c.url.endsWith("/api/mcp/usage"));
const scanCall = () => call("tools/call", { name: "scan_iac", arguments: { content: 'resource "aws_db_instance" "a" {\n  publicly_accessible = true\n}\n', format: "terraform" } });

test("each tools/call is counted once and the other methods are free", async () => {
  usage = "ok";
  calls = [];
  await call("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "test", version: "1" } });
  await call("tools/list", {});
  assert.equal(usageCalls().length, 0);
  const response = await scanCall();
  assert.equal(response.status, 200);
  assert.equal(usageCalls().length, 1);
  assert.equal(usageCalls()[0].authorization, "Bearer remote-test");
});

test("a call over the monthly allowance returns a tool error with the upgrade text and does not run", async () => {
  usage = "limit";
  const response = await scanCall();
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.id, 1);
  assert.equal(body.result.isError, true);
  const error = JSON.parse(body.result.content[0].text);
  assert.equal(error.error, "mcp_scan_limit_reached");
  assert.match(error.message, /used all 100 MCP scans/);
  assert.equal(body.result.structuredContent, undefined);
});

test("an outage or an unrelated answer from the usage endpoint lets the call run", async () => {
  for (const mode of ["down", "other"] as const) {
    usage = mode;
    const body = await (await scanCall()).json();
    assert.equal(body.result.isError, undefined, mode);
    assert.equal(JSON.parse(body.result.content[0].text).status, "completed", mode);
  }
  usage = "ok";
});
