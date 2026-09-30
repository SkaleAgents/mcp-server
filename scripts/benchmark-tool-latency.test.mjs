import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, test } from "node:test";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const entry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const servers = [];

after(async () => {
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
});

async function apiServer({ userDelayMs = 0, botsDelayMs = 0 } = {}) {
  const calls = { user: 0, bots: 0 };
  const server = createServer((request, response) => {
    response.setHeader("Content-Type", "application/json");
    if (request.url === "/api/user") {
      calls.user++;
      response.statusCode = request.headers.authorization === "Bearer benchmark-test-token" ? 200 : 401;
      setTimeout(() => response.end(JSON.stringify(response.statusCode === 200 ? { id: "test-account" } : { message: "Unauthorized" })), userDelayMs);
      return;
    }
    if (request.url === "/api/bots") {
      calls.bots++;
      setTimeout(() => response.end(JSON.stringify({ bots: [] })), botsDelayMs);
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
  assert.equal(api.calls.user, 1);
});

test("counts overlapping fetch intervals once and preserves gaps outside fetches", async () => {
  const { fetchIntervalUnionMs } = await import("./benchmark-tool-latency.mjs");
  assert.equal(typeof fetchIntervalUnionMs, "function");
  assert.equal(fetchIntervalUnionMs([{ startedMs: 100, endedMs: 200 }, { startedMs: 150, endedMs: 250 }]), 150);
  assert.equal(fetchIntervalUnionMs([{ startedMs: 300, endedMs: 350 }, { startedMs: 100, endedMs: 200 }]), 150);
  assert.equal(fetchIntervalUnionMs([{ startedMs: 100, endedMs: 300 }, { startedMs: 150, endedMs: 200 }]), 200);
});

test("measures concurrent API fetches when the bot lookup finishes before validation", async () => {
  const { runBenchmark } = await import("./benchmark-tool-latency.mjs");
  const api = await apiServer({ userDelayMs: 80, botsDelayMs: 40 });
  const result = await runBenchmark({ apiUrl: api.url, token: "benchmark-test-token", entry, warmup: 1, samples: 2 });
  assert.equal(result.successCount, 2);
  assert.ok(result.fetchOverlapMs.p50Ms > 20);
  assert.ok(result.otherToolCallMs.p50Ms >= 0);
  assert.equal(result.fetchTimings["/api/user"].sampleCount, 2);
  assert.equal(result.fetchTimings["/api/bots"].sampleCount, 2);
});

test("times a supplied application source without emitting its contents", async () => {
  const { runBenchmark } = await import("./benchmark-tool-latency.mjs");
  const api = await apiServer();
  const content = 'export function privateFixtureMarker(value: number) { return value * 2; }';
  const result = await runBenchmark({
    apiUrl: api.url,
    token: "benchmark-test-token",
    entry,
    content,
    warmup: 1,
    samples: 2,
  });
  assert.equal(result.input, "provided application source");
  assert.equal(result.inputBytes, Buffer.byteLength(content));
  assert.equal(result.inputSha256, createHash("sha256").update(content).digest("hex"));
  assert.equal(result.successCount, 2);
  assert.deepEqual(api.calls, { user: 3, bots: 3 });
  assert.doesNotMatch(JSON.stringify(result), /privateFixtureMarker|benchmark-test-token/);
});

test("rejects empty supplied application source before starting the tool", async () => {
  const { runBenchmark } = await import("./benchmark-tool-latency.mjs");
  const api = await apiServer();
  await assert.rejects(runBenchmark({ apiUrl: api.url, token: "benchmark-test-token", entry, content: "  " }), /content/i);
  assert.deepEqual(api.calls, { user: 0, bots: 0 });
});
