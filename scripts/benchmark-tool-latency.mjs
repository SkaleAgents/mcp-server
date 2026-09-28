import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const defaultEntry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const fixture = 'export function loadStatus() { return fetch("http://example.com/status"); }';

function count(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function percentile(sorted, fraction) {
  return sorted[Math.ceil(sorted.length * fraction) - 1];
}

export async function runBenchmark({
  apiUrl,
  token,
  entry = defaultEntry,
  warmup = 5,
  samples = 50,
}) {
  if (typeof token !== "string" || token.trim() === "") {
    throw new Error("Set SKALEAGENTS_API_TOKEN in the environment; the benchmark does not start OAuth");
  }
  const origin = new URL(apiUrl).origin;
  count(warmup, "warmup", 0, 20);
  count(samples, "samples", 1, 200);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry],
    env: {
      PLATFORM_API_URL: origin,
      SKALEAGENTS_API_TOKEN: token,
      SKALEAGENTS_OAUTH_ENABLED: "false",
    },
    stderr: "pipe",
  });
  const client = new Client({ name: "skaleagents-latency-probe", version: "1" });
  const durations = [];

  try {
    await client.connect(transport);
    for (let index = 0; index < warmup + samples; index++) {
      const started = performance.now();
      const result = await client.callTool(
        {
          name: "review_architecture",
          arguments: { content: fixture, focus: "security", format: "application" },
        },
        undefined,
        { timeout: 20_000 },
      );
      const elapsed = performance.now() - started;
      const review = result.structuredContent;
      if (
        result.isError ||
        review?.status !== "completed" ||
        review?.format !== "application" ||
        !review.findings?.some((finding) => finding.title === "Unencrypted HTTP endpoint")
      ) {
        throw new Error("MCP tool call failed or returned an incomplete review");
      }
      if (index >= warmup) durations.push(elapsed);
    }
  } finally {
    await client.close();
  }

  const sorted = durations.toSorted((a, b) => a - b);
  return {
    observedAtUtc: new Date().toISOString(),
    apiOrigin: origin,
    tool: "review_architecture",
    transport: "stdio",
    input: "synthetic application snippet",
    auth: "existing bearer token validated on every call",
    timingBoundary: "JSON-RPC tools/call request to complete response; excludes process startup and initial MCP handshake",
    warmupCount: warmup,
    sampleCount: samples,
    successCount: durations.length,
    p50Ms: percentile(sorted, 0.5),
    p95Ms: percentile(sorted, 0.95),
    p99Ms: percentile(sorted, 0.99),
    maxMs: sorted.at(-1),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await runBenchmark({
      apiUrl: process.env.PLATFORM_API_URL || "https://api.skaleagents.com",
      token: process.env.SKALEAGENTS_API_TOKEN,
      warmup: Number(process.env.BENCHMARK_WARMUP ?? 5),
      samples: Number(process.env.BENCHMARK_SAMPLES ?? 50),
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    process.stderr.write(`Benchmark failed: ${message}\n`);
    process.exitCode = 1;
  }
}
