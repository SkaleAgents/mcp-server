import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createServer } from "./server.js";
import { requestAuthorization } from "./saved-review.js";

export type ServedReply = { status: number; headers: [string, string][]; body: ArrayBuffer | null };

/** Runs one already-authorized, already-parsed MCP request. Used inline and inside the worker pool. */
export async function serveParsed(
  authorization: string,
  url: string,
  headers: [string, string][],
  body: unknown,
): Promise<ServedReply> {
  return requestAuthorization.run(authorization, async () => {
    const server = createServer(true);
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    try {
      await server.connect(transport);
      const response = await transport.handleRequest(
        new Request(url, { method: "POST", headers }),
        { parsedBody: body },
      );
      // Finish the JSON response before closing this request-scoped transport.
      const responseBody = await response.arrayBuffer();
      return {
        status: response.status,
        headers: [...response.headers.entries()],
        body: responseBody.byteLength ? responseBody : null,
      };
    } finally {
      await server.close();
    }
  });
}
