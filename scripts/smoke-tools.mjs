/**
 * Smoke: mock Google token from Laravel api, then tools/list + review_architecture over stdio.
 */
const API_URL = (
  process.env.PLATFORM_API_URL ?? "http://localhost:8082"
).replace(/\/$/, "");

async function main() {
  const auth = await fetch(`${API_URL}/api/auth/google/callback`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      code: "mcp-smoke",
      displayName: "MCP Smoke",
      email: "mcp-smoke@example.com",
    }),
  });
  if (!auth.ok) {
    console.error("auth failed", await auth.text());
    process.exit(1);
  }
  const { token } = /** @type {{ token: string }} */ (await auth.json());

  const { spawn } = await import("node:child_process");
  const path = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const root = path.dirname(fileURLToPath(import.meta.url));
  const entry = path.join(root, "../src/index.ts");

  const child = spawn("npx", ["tsx", entry], {
    env: {
      ...process.env,
      SKALEAGENTS_API_TOKEN: token,
      PLATFORM_API_URL: API_URL,
    },
    stdio: ["pipe", "pipe", "inherit"],
  });

  const send = (msg) => {
    child.stdin.write(JSON.stringify(msg) + "\n");
  };

  let buf = "";
  const responses = [];
  const waiters = new Map();
  let stopping = false;

  function waitForResponse(id, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        waiters.delete(id);
        reject(new Error(`timed out waiting for JSON-RPC response ${id}`));
      }, timeoutMs);
      waiters.set(id, {
        resolve: (response) => {
          clearTimeout(timer);
          resolve(response);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
    });
  }

  child.stdout.on("data", (chunk) => {
    buf += chunk.toString();
    const lines = buf.split("\n");
    buf = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const response = JSON.parse(line);
        responses.push(response);
        const waiter = waiters.get(response.id);
        if (waiter) {
          waiters.delete(response.id);
          waiter.resolve(response);
        }
      } catch {
        /* ignore */
      }
    }
  });

  child.on("error", (error) => {
    for (const waiter of waiters.values()) waiter.reject(error);
    waiters.clear();
  });

  child.on("exit", (code, signal) => {
    if (stopping) return;
    const error = new Error(
      `MCP child exited before completing smoke (code=${code}, signal=${signal})`,
    );
    for (const waiter of waiters.values()) waiter.reject(error);
    waiters.clear();
  });

  try {
    send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "smoke", version: "0.0.1" },
      },
    });

    await waitForResponse(1);
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list" });

    const toolList = await waitForResponse(2);
    send({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "review_architecture",
        arguments: {
          content:
            'resource "aws_security_group" "x" { cidr_blocks = ["0.0.0.0/0"] }',
          focus: "security",
        },
      },
    });

    const toolCall = await waitForResponse(3);

    console.log(
      JSON.stringify(
        {
          initializeOk: Boolean(responses.find((r) => r.id === 1)),
          tools: toolList?.result?.tools?.map((t) => t.name),
          reviewPreview: toolCall?.result?.content?.[0]?.text?.slice(0, 240),
        },
        null,
        2,
      ),
    );

    if (!toolList?.result?.tools?.length || !toolCall?.result) {
      throw new Error("MCP smoke response was incomplete");
    }
  } finally {
    stopping = true;
    child.kill("SIGTERM");
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
