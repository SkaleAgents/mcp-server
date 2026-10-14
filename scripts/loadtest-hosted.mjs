// Drives the hosted MCP handler in-process against a stub token API. No network, no production traffic.
// Usage: node scripts/loadtest-hosted.mjs [seconds=15] [concurrency=20] [tokens=50]
import http from "node:http";
import { performance } from "node:perf_hooks";

const seconds = Number(process.argv[2] ?? 15);
const concurrency = Number(process.argv[3] ?? 20);
const tokenCount = Number(process.argv[4] ?? 50);

let validations = 0;
const stub = http.createServer((req, res) => {
  validations++;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ active: true, resource: "https://skaleagents.com/mcp", scope: "mcp", expiresAt: Math.floor(Date.now() / 1000) + 3600 }));
});
await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
process.env.PLATFORM_API_URL = `http://127.0.0.1:${stub.address().port}`;
const { handleMcpRequest } = await import("../dist/http.js");

const terraform = 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'.repeat(40).replace(/"b"/g, (m, i) => `"b${i}"`);
const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "scan_iac", arguments: { content: terraform, format: "terraform" } } });
const latencies = [];
let errors = 0;
const end = performance.now() + seconds * 1000;
async function worker(id) {
  for (let n = 0; performance.now() < end; n++) {
    const started = performance.now();
    const response = await handleMcpRequest(new Request("https://skaleagents.com/mcp", {
      method: "POST",
      headers: { authorization: `Bearer token-${(id + n) % tokenCount}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
      body,
    }));
    const text = await response.text();
    if (response.status !== 200 || !text.includes("findings")) errors++;
    latencies.push(performance.now() - started);
  }
}
await Promise.all(Array.from({ length: concurrency }, (_, id) => worker(id)));
latencies.sort((a, b) => a - b);
const pick = (f) => latencies[Math.min(latencies.length - 1, Math.ceil(latencies.length * f) - 1)].toFixed(1);
console.log(JSON.stringify({ requests: latencies.length, rpm: Math.round((latencies.length / seconds) * 60), errors, tokenValidations: validations, p50Ms: pick(0.5), p95Ms: pick(0.95), maxMs: pick(1), rssMb: Math.round(process.memoryUsage().rss / 1048576) }));
stub.close();
process.exit(errors ? 1 : 0);
