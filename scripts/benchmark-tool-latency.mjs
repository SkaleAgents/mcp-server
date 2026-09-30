import { performance } from "node:perf_hooks";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const defaultEntry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const fetchSpanModule = new URL("./benchmark-fetch-spans.mjs", import.meta.url).href;
const defaultFixture = 'export function loadStatus() { return fetch("http://example.com/status"); }';

function count(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function percentile(sorted, fraction) {
  return sorted[Math.ceil(sorted.length * fraction) - 1];
}

function summary(values) {
  const sorted = values.toSorted((a, b) => a - b);
  return {
    sampleCount: sorted.length,
    p50Ms: percentile(sorted, 0.5),
    p95Ms: percentile(sorted, 0.95),
    maxMs: sorted.at(-1),
  };
}

export async function runBenchmark({
  apiUrl,
  token,
  entry = defaultEntry,
  content,
  warmup = 5,
  samples = 50,
}) {
  if (typeof token !== "string" || token.trim() === "") {
    throw new Error("Set SKALEAGENTS_API_TOKEN in the environment; the benchmark does not start OAuth");
  }
  const origin = new URL(apiUrl).origin;
  const input = content === undefined ? defaultFixture : content;
  if (typeof input !== "string" || input.trim() === "" || input.length > 500_000) {
    throw new Error("content must be nonempty application source of at most 500,000 characters");
  }
  count(warmup, "warmup", 0, 20);
  count(samples, "samples", 1, 200);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry],
    env: {
      PLATFORM_API_URL: origin,
      SKALEAGENTS_API_TOKEN: token,
      SKALEAGENTS_OAUTH_ENABLED: "false",
      NODE_OPTIONS: `--import=${fetchSpanModule}`,
    },
    stderr: "pipe",
  });
  const client = new Client({ name: "skaleagents-latency-probe", version: "1" });
  const durations = [];
  const fetchSpans = [];
  let stderrBuffer = "";
  const expectedSpans = (warmup + samples) * 2;
  let resolveSpans;
  transport.stderr?.on("data", (chunk) => {
    stderrBuffer += chunk.toString();
    let end;
    while ((end = stderrBuffer.indexOf("\n")) !== -1) {
      const line = stderrBuffer.slice(0, end);
      stderrBuffer = stderrBuffer.slice(end + 1);
      if (!line.startsWith("T79_FETCH_SPAN ")) continue;
      fetchSpans.push(JSON.parse(line.slice("T79_FETCH_SPAN ".length)));
      if (fetchSpans.length >= expectedSpans) resolveSpans?.();
    }
  });

  try {
    await client.connect(transport);
    for (let index = 0; index < warmup + samples; index++) {
      const started = performance.now();
      const result = await client.callTool(
        {
          name: "review_architecture",
          arguments: { content: input, focus: "security", format: "application" },
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
        !Array.isArray(review.findings) ||
        (content === undefined && !review.findings.some((finding) => finding.title === "Unencrypted HTTP endpoint"))
      ) {
        throw new Error("MCP tool call failed or returned an incomplete review");
      }
      if (index >= warmup) durations.push(elapsed);
    }
    if (fetchSpans.length < expectedSpans) {
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error("Incomplete fetch timing spans")), 2000);
        resolveSpans = () => {
          clearTimeout(timeout);
          resolve();
        };
      });
    }
  } finally {
    await client.close();
  }

  if (fetchSpans.length !== expectedSpans) throw new Error("Unexpected fetch timing span count");
  const userFetches = [];
  const botFetches = [];
  const otherToolCall = [];
  for (let index = warmup; index < warmup + samples; index++) {
    const user = fetchSpans[index * 2];
    const bots = fetchSpans[index * 2 + 1];
    if (user.path !== "/api/user" || bots.path !== "/api/bots" || user.status !== 200 || bots.status !== 200) {
      throw new Error("Unexpected fetch timing span order or status");
    }
    userFetches.push(user.durationMs);
    botFetches.push(bots.durationMs);
    otherToolCall.push(durations[index - warmup] - user.durationMs - bots.durationMs);
  }

  const sorted = durations.toSorted((a, b) => a - b);
  return {
    observedAtUtc: new Date().toISOString(),
    apiOrigin: origin,
    tool: "review_architecture",
    transport: "stdio",
    input: content === undefined ? "synthetic application snippet" : "provided application source",
    inputBytes: Buffer.byteLength(input),
    inputSha256: createHash("sha256").update(input).digest("hex"),
    auth: "existing bearer token validated on every call",
    timingBoundary: "JSON-RPC tools/call request to complete response; excludes process startup and initial MCP handshake",
    warmupCount: warmup,
    sampleCount: samples,
    successCount: durations.length,
    p50Ms: percentile(sorted, 0.5),
    p95Ms: percentile(sorted, 0.95),
    p99Ms: percentile(sorted, 0.99),
    maxMs: sorted.at(-1),
    fetchTimingBoundary: "request to response headers",
    fetchTimings: {
      "/api/user": summary(userFetches),
      "/api/bots": summary(botFetches),
    },
    otherToolCallMs: summary(otherToolCall),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await runBenchmark({
      apiUrl: process.env.PLATFORM_API_URL || "https://api.skaleagents.com",
      token: process.env.SKALEAGENTS_API_TOKEN,
      content: process.env.BENCHMARK_INPUT_FILE ? await readFile(process.env.BENCHMARK_INPUT_FILE, "utf8") : undefined,
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
