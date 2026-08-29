import { getApiToken, getApiUrl } from "./config.js";

export type AuthResult =
  | { ok: true; offline?: boolean; userId?: string }
  | { ok: false; reason: "missing_token" | "unauthorized" };

/**
 * Fail closed without a token. When the API is reachable, require a valid bearer.
 * If the API is unreachable, allow tools to run offline with canned results.
 */
export async function requireApiAuth(): Promise<AuthResult> {
  const token = getApiToken();
  if (!token) {
    return { ok: false, reason: "missing_token" };
  }

  try {
    const res = await fetch(`${getApiUrl()}/api/user`, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
    });
    if (res.status === 401 || res.status === 403) {
      return { ok: false, reason: "unauthorized" };
    }
    if (!res.ok) {
      return { ok: false, reason: "unauthorized" };
    }
    const user = (await res.json()) as { id?: string };
    return { ok: true, userId: user.id };
  } catch {
    return { ok: true, offline: true };
  }
}

export function unauthorizedContent(reason: AuthResult & { ok: false }) {
  const text =
    reason.reason === "missing_token"
      ? "unauthorized: set SKALEAGENTS_API_TOKEN"
      : "unauthorized: invalid SKALEAGENTS_API_TOKEN";
  return {
    isError: true as const,
    content: [{ type: "text" as const, text }],
  };
}
