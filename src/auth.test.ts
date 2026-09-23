import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { afterEach, describe, it } from "node:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { requireApiAuth } from "./auth.js";

const originalFetch = globalThis.fetch;
const originalToken = process.env.SKALEAGENTS_API_TOKEN;
const originalUrl = process.env.PLATFORM_API_URL;
const originalOAuthEnabled = process.env.SKALEAGENTS_OAUTH_ENABLED;
const originalOAuthCache = process.env.SKALEAGENTS_OAUTH_CACHE;

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalToken === undefined) delete process.env.SKALEAGENTS_API_TOKEN;
  else process.env.SKALEAGENTS_API_TOKEN = originalToken;
  if (originalUrl === undefined) delete process.env.PLATFORM_API_URL;
  else process.env.PLATFORM_API_URL = originalUrl;
  if (originalOAuthEnabled === undefined) delete process.env.SKALEAGENTS_OAUTH_ENABLED;
  else process.env.SKALEAGENTS_OAUTH_ENABLED = originalOAuthEnabled;
  if (originalOAuthCache === undefined) delete process.env.SKALEAGENTS_OAUTH_CACHE;
  else process.env.SKALEAGENTS_OAUTH_CACHE = originalOAuthCache;
});

describe("requireApiAuth", () => {
  it("rejects missing token", async () => {
    delete process.env.SKALEAGENTS_API_TOKEN;
    process.env.SKALEAGENTS_OAUTH_ENABLED = "false";
    const result = await requireApiAuth();
    assert.deepEqual(result, { ok: false, reason: "oauth_required" });
  });

  it("rejects invalid token when API returns 401", async () => {
    process.env.SKALEAGENTS_API_TOKEN = "bad";
    process.env.PLATFORM_API_URL = "http://localhost:8082";
    globalThis.fetch = async (url) => {
      assert.equal(String(url), "http://localhost:8082/api/user");
      return new Response(JSON.stringify({ message: "Unauthenticated." }), {
        status: 401,
      });
    };
    const result = await requireApiAuth();
    assert.deepEqual(result, { ok: false, reason: "unauthorized" });
  });

  it("uses the production API without a URL override or with a blank override", async () => {
    process.env.SKALEAGENTS_API_TOKEN = "good";
    const calls: string[] = [];
    globalThis.fetch = async (url) => {
      calls.push(String(url));
      return new Response(JSON.stringify({ id: "user-1", displayName: "Rayhan" }), {
        status: 200,
      });
    };
    for (const override of [undefined, "", "  "]) {
      if (override === undefined) delete process.env.PLATFORM_API_URL;
      else process.env.PLATFORM_API_URL = override;
      assert.deepEqual(await requireApiAuth(), { ok: true, userId: "user-1" });
    }
    assert.deepEqual(calls, Array(3).fill("https://api.skaleagents.com/api/user"));
  });

  it("rejects when the API is unavailable", async () => {
    process.env.SKALEAGENTS_API_TOKEN = "any";
    globalThis.fetch = async () => {
      throw new Error("network down");
    };
    const result = await requireApiAuth();
    assert.deepEqual(result, { ok: false, reason: "api_unavailable" });
  });

  it("does not call an unhealthy API an auth failure", async () => {
    process.env.SKALEAGENTS_API_TOKEN = "any";
    globalThis.fetch = async () => new Response("upstream failed", { status: 503 });
    const result = await requireApiAuth();
    assert.deepEqual(result, { ok: false, reason: "api_unavailable" });
  });

  it("refreshes an expired cached OAuth connection", async () => {
    const directory = await mkdtemp(join(tmpdir(), "skaleagents-oauth-"));
    const cachePath = join(directory, "oauth.json");
    process.env.PLATFORM_API_URL = "http://localhost:8082";
    process.env.SKALEAGENTS_OAUTH_CACHE = cachePath;
    delete process.env.SKALEAGENTS_API_TOKEN;

    await writeFile(
      cachePath,
      JSON.stringify({
        apiUrl: "http://localhost:8082",
        accessToken: "expired-access",
        refreshToken: "refresh-one",
        expiresAt: Date.now() - 1_000,
      }),
    );

    const calls: string[] = [];
    globalThis.fetch = async (input, init) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/.well-known/oauth-authorization-server")) {
        return new Response(
          JSON.stringify({
            authorization_endpoint: "http://localhost:8082/oauth/authorize",
            token_endpoint: "http://localhost:8082/api/oauth/token",
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/api/oauth/token")) {
        assert.equal(init?.method, "POST");
        return new Response(
          JSON.stringify({
            access_token: "fresh-access",
            refresh_token: "refresh-two",
            expires_in: 3_600,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/api/user")) {
        assert.equal(
          new Headers(init?.headers).get("Authorization"),
          "Bearer fresh-access",
        );
        return new Response(JSON.stringify({ id: "user-1" }), { status: 200 });
      }
      throw new Error(`unexpected request: ${url}`);
    };

    try {
      assert.deepEqual(await requireApiAuth(), { ok: true, userId: "user-1" });
      assert.deepEqual(calls, [
        "http://localhost:8082/.well-known/oauth-authorization-server",
        "http://localhost:8082/api/oauth/token",
        "http://localhost:8082/api/user",
      ]);
      const saved = JSON.parse(await readFile(cachePath, "utf8")) as {
        accessToken: string;
        refreshToken: string;
      };
      assert.equal(saved.accessToken, "fresh-access");
      assert.equal(saved.refreshToken, "refresh-two");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
