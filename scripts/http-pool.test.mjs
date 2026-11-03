import assert from "node:assert/strict";
import { test } from "node:test";

process.env.MCP_HTTP_WORKERS = "1";
process.env.MCP_HTTP_TIMEOUT_MS = "4000";
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  if (String(input).endsWith("/api/oauth/mcp-token"))
    return Response.json({ active: true, resource: "https://skaleagents.com/mcp", scope: "mcp", expiresAt: Date.now() / 1000 + 3600 });
  return realFetch(input, init);
};
const { handleMcpRequest } = await import("../dist/http.js");

function call(params, token = "pool-test", method = "tools/call") {
  return handleMcpRequest(new Request("https://skaleagents.com/mcp", {
    method: "POST",
    headers: { Accept: "application/json, text/event-stream", "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  }));
}

// Many small resources make the scan slow without hitting the 500 KB cap.
const heavy = Array.from({ length: 6000 }, (_, i) =>
  `resource "aws_db_instance" "db${i}" {\n  publicly_accessible = true\n}\n`).join("").slice(0, 490_000);

test("a slow scan runs off the event loop and times out without taking the site down", async () => {
  let ticks = 0;
  const ticker = setInterval(() => ticks++, 20);
  const started = Date.now();
  const slow = await call({ name: "scan_iac", arguments: { content: heavy, format: "terraform" } }, "slow-token");
  clearInterval(ticker);
  const elapsed = Date.now() - started;
  // The main thread kept ticking while the worker scanned.
  assert.ok(ticks >= Math.floor(elapsed / 20) * 0.5, `event loop blocked: ${ticks} ticks in ${elapsed} ms`);
  assert.ok([200, 504].includes(slow.status));

  const list = await call({}, "pool-test", "tools/list");
  assert.equal(list.status, 200);
  assert.match(await list.text(), /scan_iac/);
});

test("one token can have at most two requests in flight", async () => {
  const small = { name: "scan_iac", arguments: { content: heavy, format: "terraform" } };
  const replies = await Promise.all([call(small, "busy"), call(small, "busy"), call(small, "busy")]);
  assert.deepEqual(replies.map((reply) => reply.status).filter((status) => status === 429), [429]);
});
