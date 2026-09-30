import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import { once } from "node:events";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "./server.js";

async function reviewWithApi({ overlap = false, userStatus = 200, botsStatus = 200, calls = 1 } = {}) {
  const original = {
    url: process.env.PLATFORM_API_URL,
    token: process.env.SKALEAGENTS_API_TOKEN,
    oauth: process.env.SKALEAGENTS_OAUTH_ENABLED,
  };
  let userCalls = 0;
  let botCalls = 0;
  let botAuthorization: string | undefined;
  let releaseUser: (() => void) | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const api = createHttpServer((request, response) => {
    response.setHeader("Content-Type", "application/json");
    if (request.url === "/api/user") {
      userCalls++;
      assert.equal(request.headers.authorization, "Bearer server-test-token");
      const reply = () => {
        response.statusCode = userStatus;
        response.end(JSON.stringify(userStatus === 200 ? { id: "test-account" } : { message: "Unauthorized" }));
      };
      if (overlap && botCalls < userCalls) {
        releaseUser = reply;
        timer = setTimeout(() => {
          response.statusCode = 503;
          response.end(JSON.stringify({ message: "Public lookup did not overlap validation" }));
          releaseUser = undefined;
        }, 500);
      } else reply();
      return;
    }
    if (request.url === "/api/bots") {
      botCalls++;
      botAuthorization = request.headers.authorization;
      response.statusCode = botsStatus;
      response.end(JSON.stringify({ bots: [
        { name: "Public specialist", status: "published", visibility: "public" },
        { name: "Private specialist", status: "published", visibility: "private" },
        { name: "Draft specialist", status: "draft", visibility: "public" },
      ] }));
      if (releaseUser) {
        clearTimeout(timer);
        releaseUser();
        releaseUser = undefined;
      }
      return;
    }
    response.statusCode = 404;
    response.end("{}");
  });
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  const address = api.address();
  assert.ok(address && typeof address !== "string");
  process.env.PLATFORM_API_URL = `http://127.0.0.1:${address.port}`;
  process.env.SKALEAGENTS_API_TOKEN = "server-test-token";
  process.env.SKALEAGENTS_OAUTH_ENABLED = "false";
  const server = createServer();
  const client = new Client({ name: "server-test", version: "1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const results = [];
    for (let index = 0; index < calls; index++) {
      results.push(await client.callTool({ name: "review_architecture", arguments: {
        content: 'export const endpoint = "http://example.com";', format: "application", focus: "security",
      } }));
    }
    return { results, userCalls, botCalls, botAuthorization };
  } finally {
    await client.close();
    await server.close();
    clearTimeout(timer);
    api.closeAllConnections();
    await new Promise<void>((resolve) => api.close(() => resolve()));
    for (const [key, value] of Object.entries({ PLATFORM_API_URL: original.url, SKALEAGENTS_API_TOKEN: original.token, SKALEAGENTS_OAUTH_ENABLED: original.oauth })) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test("reviews overlap validation with a credential-free public lookup on every call", async () => {
  const observed = await reviewWithApi({ overlap: true, calls: 2 });
  assert.equal(observed.userCalls, 2);
  assert.equal(observed.botCalls, 2);
  assert.equal(observed.botAuthorization, undefined);
  for (const result of observed.results) {
    assert.equal(result.isError, undefined);
    assert.equal(result.structuredContent?.status, "completed");
    assert.deepEqual(result.structuredContent?.botHints, ["Public specialist"]);
  }
});

test("a completed public lookup cannot authorize a rejected account", async () => {
  const observed = await reviewWithApi({ overlap: true, userStatus: 401 });
  assert.equal(observed.results[0].isError, true);
  assert.match(JSON.stringify(observed.results[0].content), /unauthorized/i);
  assert.equal(observed.results[0].structuredContent, undefined);
});

test("public lookup failure still permits an authenticated review with empty hints", async () => {
  const observed = await reviewWithApi({ overlap: true, botsStatus: 503 });
  assert.equal(observed.results[0].isError, undefined);
  assert.equal(observed.results[0].structuredContent?.status, "completed");
  assert.deepEqual(observed.results[0].structuredContent?.botHints, []);
});

test("a completed public lookup cannot bypass unavailable account validation", async () => {
  const observed = await reviewWithApi({ overlap: true, userStatus: 503 });
  assert.equal(observed.results[0].isError, true);
  assert.match(JSON.stringify(observed.results[0].content), /api unavailable/i);
  assert.equal(observed.results[0].structuredContent, undefined);
});
