import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { requireApiAuth } from "./auth.js";

const originalFetch = globalThis.fetch;
const originalToken = process.env.SKALEAGENTS_API_TOKEN;
const originalUrl = process.env.PLATFORM_API_URL;

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalToken === undefined) delete process.env.SKALEAGENTS_API_TOKEN;
  else process.env.SKALEAGENTS_API_TOKEN = originalToken;
  if (originalUrl === undefined) delete process.env.PLATFORM_API_URL;
  else process.env.PLATFORM_API_URL = originalUrl;
});

describe("requireApiAuth", () => {
  it("rejects missing token", async () => {
    delete process.env.SKALEAGENTS_API_TOKEN;
    const result = await requireApiAuth();
    assert.deepEqual(result, { ok: false, reason: "missing_token" });
  });

  it("rejects invalid token when API returns 401", async () => {
    process.env.SKALEAGENTS_API_TOKEN = "bad";
    process.env.PLATFORM_API_URL = "http://localhost:8082";
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ message: "Unauthenticated." }), {
        status: 401,
      });
    const result = await requireApiAuth();
    assert.deepEqual(result, { ok: false, reason: "unauthorized" });
  });

  it("accepts valid token", async () => {
    process.env.SKALEAGENTS_API_TOKEN = "good";
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ id: "user-1", displayName: "Rayhan" }), {
        status: 200,
      });
    const result = await requireApiAuth();
    assert.deepEqual(result, { ok: true, userId: "user-1" });
  });

  it("rejects when the API is unavailable", async () => {
    process.env.SKALEAGENTS_API_TOKEN = "any";
    globalThis.fetch = async () => {
      throw new Error("network down");
    };
    const result = await requireApiAuth();
    assert.deepEqual(result, { ok: false, reason: "api_unavailable" });
  });
});
