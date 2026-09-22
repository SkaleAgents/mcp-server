import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { getApiToken, getApiUrl, getOAuthCachePath, isOAuthEnabled } from "./config.js";

type OAuthMetadata = {
  authorization_endpoint: string;
  token_endpoint: string;
};

type OAuthCredentials = {
  apiUrl: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
};

type OAuthTokenResponse = {
  access_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
};

export type AuthResult =
  | { ok: true; userId?: string }
  | {
      ok: false;
      reason: "oauth_required" | "oauth_failed" | "unauthorized" | "api_unavailable";
    };

let cachedCredentials: OAuthCredentials | null = null;
let authenticationInFlight: Promise<string> | null = null;

/**
 * Validate the API bearer token before running any tool. OAuth starts in the
 * user's browser when no legacy SKALEAGENTS_API_TOKEN is configured.
 */
export async function requireApiAuth(): Promise<AuthResult> {
  const token = await getAccessToken();
  if (!token) {
    return {
      ok: false,
      reason: isOAuthEnabled() ? "oauth_failed" : "oauth_required",
    };
  }

  try {
    let res = await fetchApiUser(token);
    if ((res.status === 401 || res.status === 403) && !getApiToken()) {
      const replacementToken = await reauthorizeAfterRejection();
      if (replacementToken) {
        res = await fetchApiUser(replacementToken);
      }
    }
    if (res.status === 401 || res.status === 403) {
      return { ok: false, reason: "unauthorized" };
    }
    if (!res.ok) {
      return { ok: false, reason: "api_unavailable" };
    }
    const user = (await res.json()) as { id?: string };
    return { ok: true, userId: user.id };
  } catch {
    return { ok: false, reason: "api_unavailable" };
  }
}

export async function getApiAccessToken(): Promise<string | null> {
  return getAccessToken();
}

export function unauthorizedContent(reason: AuthResult & { ok: false }) {
  const text =
    reason.reason === "oauth_required"
      ? "MCP OAuth is disabled. Set SKALEAGENTS_API_TOKEN or enable OAuth."
      : reason.reason === "oauth_failed"
        ? "MCP sign-in could not be completed. Check the browser window and try again."
        : reason.reason === "unauthorized"
          ? "unauthorized: the SkaleAgents connection was rejected"
          : "api unavailable: could not validate the SkaleAgents connection";
  return {
    isError: true as const,
    content: [{ type: "text" as const, text }],
  };
}

async function getAccessToken(): Promise<string | null> {
  const legacyToken = getApiToken();
  if (legacyToken) return legacyToken;
  if (!isOAuthEnabled()) return null;

  if (!authenticationInFlight) {
    authenticationInFlight = getOAuthAccessToken().finally(() => {
      authenticationInFlight = null;
    });
  }

  try {
    return await authenticationInFlight;
  } catch {
    return null;
  }
}

async function fetchApiUser(token: string): Promise<Response> {
  return fetch(`${getApiUrl()}/api/user`, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
  });
}

async function reauthorizeAfterRejection(): Promise<string | null> {
  cachedCredentials = null;
  await removeCredentials();
  return getAccessToken();
}

async function getOAuthAccessToken(): Promise<string> {
  const apiUrl = getApiUrl();
  const metadata = await getMetadata(apiUrl);
  const stored = await readCredentials(apiUrl);

  if (stored && stored.expiresAt > Date.now() + 30_000) {
    cachedCredentials = stored;
    return stored.accessToken;
  }

  if (stored?.refreshToken) {
    try {
      const refreshed = await exchangeRefreshToken(metadata.token_endpoint, stored.refreshToken);
      await saveCredentials(apiUrl, refreshed);
      return refreshed.accessToken;
    } catch {
      cachedCredentials = null;
      await removeCredentials();
    }
  }

  const authorizationCode = await authorizeInBrowser(metadata.authorization_endpoint);
  const exchanged = await exchangeAuthorizationCode(
    metadata.token_endpoint,
    authorizationCode.code,
    authorizationCode.redirectUri,
    authorizationCode.verifier,
  );
  await saveCredentials(apiUrl, exchanged);
  return exchanged.accessToken;
}

async function getMetadata(apiUrl: string): Promise<OAuthMetadata> {
  const response = await fetch(`${apiUrl}/.well-known/oauth-authorization-server`, {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`OAuth metadata request failed with status ${response.status}`);
  }

  const metadata = (await response.json()) as Partial<OAuthMetadata>;
  if (
    typeof metadata.authorization_endpoint !== "string" ||
    typeof metadata.token_endpoint !== "string"
  ) {
    throw new Error("OAuth metadata is incomplete");
  }

  return metadata as OAuthMetadata;
}

async function authorizeInBrowser(authorizationEndpoint: string): Promise<{
  code: string;
  redirectUri: string;
  verifier: string;
}> {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createCodeChallenge(verifier);
  const state = randomBytes(32).toString("base64url");

  return new Promise((resolve, reject) => {
    let settled = false;
    let redirectUri = "";
    const server = createServer((request, response) => {
      const requestUrl = new URL(
        request.url ?? "/",
        `http://${request.headers.host ?? "127.0.0.1"}`,
      );

      if (requestUrl.pathname !== "/oauth/callback") {
        response.writeHead(404);
        response.end("Not found");
        return;
      }

      const receivedState = requestUrl.searchParams.get("state");
      const error = requestUrl.searchParams.get("error");
      const code = requestUrl.searchParams.get("code");
      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      response.end(
        "<!doctype html><title>SkaleAgents connected</title>" +
          "<p>You can close this window and return to your AI client.</p>",
      );

      if (settled) return;
      settled = true;
      server.close();

      if (receivedState !== state) {
        reject(new Error("OAuth state validation failed"));
        return;
      }
      if (error || !code) {
        reject(new Error("OAuth authorization was denied"));
        return;
      }

      resolve({
        code,
        redirectUri,
        verifier,
      });
    });

    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = addressPort(server);
      redirectUri = `http://127.0.0.1:${port}/oauth/callback`;
      const url = new URL(authorizationEndpoint);
      url.search = new URLSearchParams({
        client_id: "skaleagents-mcp",
        response_type: "code",
        redirect_uri: redirectUri,
        scope: "mcp",
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();

      console.error("Opening SkaleAgents sign-in in your browser...");
      console.error(url.toString());
      openBrowser(url.toString());
    });
  });
}

async function exchangeAuthorizationCode(
  tokenEndpoint: string,
  code: string,
  redirectUri: string,
  verifier: string,
): Promise<OAuthCredentials> {
  const response = await fetchToken(tokenEndpoint, {
    grant_type: "authorization_code",
    client_id: "skaleagents-mcp",
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
  return parseTokenResponse(response);
}

async function exchangeRefreshToken(
  tokenEndpoint: string,
  refreshToken: string,
): Promise<OAuthCredentials> {
  const response = await fetchToken(tokenEndpoint, {
    grant_type: "refresh_token",
    client_id: "skaleagents-mcp",
    refresh_token: refreshToken,
  });
  return parseTokenResponse(response);
}

async function fetchToken(
  tokenEndpoint: string,
  values: Record<string, string>,
): Promise<OAuthTokenResponse> {
  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(values),
  });
  const payload = (await response.json().catch(() => ({}))) as OAuthTokenResponse;
  if (!response.ok) {
    throw new Error(`OAuth token request failed with status ${response.status}`);
  }
  return payload;
}

function parseTokenResponse(response: OAuthTokenResponse): OAuthCredentials {
  if (
    typeof response.access_token !== "string" ||
    typeof response.refresh_token !== "string" ||
    typeof response.expires_in !== "number"
  ) {
    throw new Error("OAuth token response is incomplete");
  }

  return {
    apiUrl: getApiUrl(),
    accessToken: response.access_token,
    refreshToken: response.refresh_token,
    expiresAt: Date.now() + response.expires_in * 1000,
  };
}

async function readCredentials(apiUrl: string): Promise<OAuthCredentials | null> {
  if (cachedCredentials?.apiUrl === apiUrl) return cachedCredentials;

  try {
    const parsed = JSON.parse(await readFile(getOAuthCachePath(), "utf8")) as Partial<OAuthCredentials>;
    if (
      parsed.apiUrl !== apiUrl ||
      typeof parsed.accessToken !== "string" ||
      typeof parsed.refreshToken !== "string" ||
      typeof parsed.expiresAt !== "number"
    ) {
      return null;
    }
    return parsed as OAuthCredentials;
  } catch {
    return null;
  }
}

async function saveCredentials(apiUrl: string, credentials: OAuthCredentials): Promise<void> {
  cachedCredentials = { ...credentials, apiUrl };
  const path = getOAuthCachePath();
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, JSON.stringify(cachedCredentials), { encoding: "utf8", mode: 0o600 });
  await chmod(path, 0o600);
}

async function removeCredentials(): Promise<void> {
  try {
    await unlink(getOAuthCachePath());
  } catch {
    /* Cache may not exist. */
  }
}

function createCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function addressPort(server: ReturnType<typeof createServer>): number {
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("OAuth callback server did not receive a port");
  }
  return address.port;
}

function openBrowser(url: string): void {
  const command =
    process.platform === "darwin"
      ? "open"
      : process.platform === "win32"
        ? "cmd"
        : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  const child = spawn(command, args, { detached: true, stdio: "ignore" });
  child.once("error", () => {
    console.error("Could not open a browser automatically. Open the URL printed above.");
  });
  child.unref();
}
