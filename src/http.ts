import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createServer } from "./server.js";
import { getApiUrl } from "./config.js";

const resource = process.env.MCP_RESOURCE_URL ?? "https://skaleagents.com/mcp";
const metadataUrl = `${new URL(resource).origin}/.well-known/oauth-protected-resource/mcp`;
const allowedOrigins = new Set([
  "https://claude.ai",
  "https://chatgpt.com",
  "https://platform.openai.com",
  new URL(resource).origin,
]);
const headers = {
  "Cache-Control": "no-store",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID",
  "Access-Control-Expose-Headers":
    "WWW-Authenticate, MCP-Session-Id, MCP-Protocol-Version",
};

function json(status: number, body: unknown, extraHeaders = {}) {
  return Response.json(body, {
    status,
    headers: { ...headers, ...extraHeaders },
  });
}

function challenge() {
  return json(
    401,
    { error: "unauthorized" },
    {
      "WWW-Authenticate": `Bearer resource_metadata="${metadataUrl}", scope="mcp"`,
    },
  );
}

export function protectedResourceMetadata(): Response {
  return json(200, {
    resource,
    authorization_servers: [getApiUrl()],
    scopes_supported: ["mcp"],
    bearer_methods_supported: ["header"],
    resource_documentation: "https://skaleagents.com/settings",
  });
}

export async function handleMcpRequest(request: Request): Promise<Response> {
  const origin = request.headers.get("origin");
  if (origin && !allowedOrigins.has(origin))
    return json(403, { error: "origin_not_allowed" });
  if (request.method === "OPTIONS")
    return new Response(null, { status: 204, headers });
  const authorization = request.headers.get("authorization");
  if (!authorization || !/^Bearer [^\s]+$/i.test(authorization))
    return challenge();

  try {
    // Validate the opaque token with its issuer, including the MCP audience.
    const validation = await fetch(`${getApiUrl()}/api/oauth/mcp-token`, {
      headers: { Authorization: authorization, Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
      redirect: "error",
      cache: "no-store",
    });
    if (validation.status === 401 || validation.status === 403)
      return challenge();
    if (!validation.ok)
      return json(503, { error: "authorization_unavailable" });
    const token = (await validation.json()) as {
      active?: boolean;
      resource?: string;
      scope?: string;
      expiresAt?: number;
    };
    if (
      !token.active ||
      token.resource !== resource ||
      token.scope !== "mcp" ||
      !token.expiresAt ||
      token.expiresAt * 1000 <= Date.now()
    ) {
      return challenge();
    }
  } catch {
    return json(503, { error: "authorization_unavailable" });
  }

  if (request.method !== "POST")
    return json(
      405,
      { error: "method_not_allowed" },
      { Allow: "POST, OPTIONS" },
    );
  if (!request.headers.get("content-type")?.startsWith("application/json"))
    return json(415, { error: "expected_json" });
  let body: unknown;
  try {
    const reader = request.body?.getReader();
    if (!reader) return json(400, { error: "missing_body" });
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 2_100_000) {
          await reader.cancel();
          return json(413, { error: "request_too_large" });
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return json(400, {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Invalid JSON" },
    });
  }

  const server = createServer(true);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  try {
    await server.connect(transport);
    const response = await transport.handleRequest(request, {
      parsedBody: body,
    });
    // Finish the JSON response before closing this request-scoped transport.
    const responseBody = await response.arrayBuffer();
    const responseHeaders = new Headers(response.headers);
    for (const [key, value] of Object.entries(headers))
      responseHeaders.set(key, value);
    return new Response(responseBody.byteLength ? responseBody : null, {
      status: response.status,
      headers: responseHeaders,
    });
  } catch {
    return json(500, { error: "mcp_request_failed" });
  } finally {
    await server.close();
  }
}
