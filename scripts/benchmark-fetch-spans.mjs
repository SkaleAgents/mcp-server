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
  const record = (status) => {
    const ended = performance.now();
    process.stderr.write(`T79_FETCH_SPAN ${JSON.stringify({ path, startedMs: started, endedMs: ended, durationMs: ended - started, status })}\n`);
  };
  try {
    const response = await originalFetch(...args);
    record(response.status);
    return response;
  } catch (error) {
    record(0);
    throw error;
  }
};
