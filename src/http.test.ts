import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { handleMcpRequest, protectedResourceMetadata } from "./http.js";

const realFetch = globalThis.fetch;
const url = "https://skaleagents.com";
let active = true;
let audience = `${url}/mcp`;
let unavailable = false;
let calls: { url: string; authorization: string | null }[] = [];
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
          expiresAt: Date.now() / 1000 + 3600,
        },
        { status: unavailable ? 503 : active ? 200 : 401 },
      );
    if (target.endsWith("/api/bots")) return Response.json({ bots: [] });
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
    ["review_architecture", "scan_iac", "scan_iac_stub"],
  );
  calls = [];
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
  assert.equal((await call("tools/list", {})).status, 401);
  active = true;
  audience = "https://another.example/mcp";
  assert.equal((await call("tools/list", {})).status, 401);
  audience = `${url}/mcp`;
});

test("fails closed when authorization is unavailable and rejects malformed or oversized requests", async () => {
  unavailable = true;
  assert.equal((await call("tools/list", {})).status, 503);
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
