import { performance } from "node:perf_hooks";

const originalFetch = globalThis.fetch;
const measuredPaths = new Set(["/api/user", "/api/bots"]);

globalThis.fetch = async (...args) => {
  let path;
  try {
    const input = args[0];
    path = new URL(input instanceof Request ? input.url : String(input)).pathname;
  } catch {
    return originalFetch(...args);
  }
  if (!measuredPaths.has(path)) return originalFetch(...args);

  const started = performance.now();
  try {
    const response = await originalFetch(...args);
    process.stderr.write(`T79_FETCH_SPAN ${JSON.stringify({ path, durationMs: performance.now() - started, status: response.status })}\n`);
    return response;
  } catch (error) {
    process.stderr.write(`T79_FETCH_SPAN ${JSON.stringify({ path, durationMs: performance.now() - started, status: 0 })}\n`);
    throw error;
  }
};
