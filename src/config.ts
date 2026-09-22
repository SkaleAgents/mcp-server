import { homedir } from "node:os";
import { join } from "node:path";

export function getApiUrl(): string {
  return (
    process.env.PLATFORM_API_URL?.replace(/\/$/, "") ?? "http://localhost:8082"
  );
}

export function getApiToken(): string {
  return process.env.SKALEAGENTS_API_TOKEN?.trim() ?? "";
}

export function getOAuthCachePath(): string {
  return (
    process.env.SKALEAGENTS_OAUTH_CACHE?.trim() ??
    join(homedir(), ".config", "skaleagents", "oauth.json")
  );
}

export function isOAuthEnabled(): boolean {
  return process.env.SKALEAGENTS_OAUTH_ENABLED !== "false";
}
