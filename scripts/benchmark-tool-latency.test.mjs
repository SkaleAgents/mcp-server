import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, test } from "node:test";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

const entry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const servers = [];

after(async () => {
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
});

async function apiServer() {
  const calls = { user: 0, bots: 0 };
  const server = createServer((request, response) => {
    response.setHeader("Content-Type", "application/json");
    if (request.url === "/api/user") {
      calls.user++;
      response.statusCode = request.headers.authorization === "Bearer benchmark-test-token" ? 200 : 401;
      response.end(JSON.stringify(response.statusCode === 200 ? { id: "test-account" } : { message: "Unauthorized" }));
      return;
    }
    if (request.url === "/api/bots") {
      calls.bots++;
      response.end(JSON.stringify({ bots: [] }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ message: "Not found" }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  servers.push(server);
  return { url: `http://127.0.0.1:${server.address().port}`, calls };
}

test("times successful full MCP tool calls through API validation and bot lookup", async () => {
  const { runBenchmark } = await import("./benchmark-tool-latency.mjs").catch(() => {
    assert.fail("benchmark tool harness is missing");
  });
  const api = await apiServer();
  const result = await runBenchmark({
    apiUrl: api.url,
    token: "benchmark-test-token",
    entry,
    warmup: 1,
    samples: 3,
  });

  assert.equal(result.tool, "review_architecture");
  assert.equal(result.transport, "stdio");
  assert.equal(result.sampleCount, 3);
  assert.equal(result.warmupCount, 1);
  assert.equal(result.successCount, 3);
  assert.ok(result.p95Ms > 0);
  assert.ok(result.p95Ms <= result.maxMs);
  assert.equal(result.fetchTimingBoundary, "request to response headers");
  assert.equal(result.fetchTimings["/api/user"].sampleCount, 3);
  assert.equal(result.fetchTimings["/api/bots"].sampleCount, 3);
  assert.ok(result.fetchTimings["/api/user"].p95Ms > 0);
  assert.ok(result.fetchTimings["/api/bots"].p95Ms > 0);
  assert.equal(result.otherToolCallMs.sampleCount, 3);
  assert.ok(result.otherToolCallMs.p95Ms >= 0);
  assert.deepEqual(api.calls, { user: 4, bots: 4 });
  assert.equal(result.apiOrigin, api.url);
  assert.doesNotMatch(JSON.stringify(result), /benchmark-test-token|test-account/);
});

test("rejects invalid credentials instead of timing an unauthorized response", async () => {
  const { runBenchmark } = await import("./benchmark-tool-latency.mjs").catch(() => {
    assert.fail("benchmark tool harness is missing");
  });
  const api = await apiServer();
  await assert.rejects(
    runBenchmark({ apiUrl: api.url, token: "bad-token", entry, warmup: 0, samples: 1 }),
    /tool call failed|unauthorized/i,
  );
  assert.equal(api.calls.bots, 0);
});
