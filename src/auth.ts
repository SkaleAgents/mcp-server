import { getApiToken, getApiUrl } from "./config.js";

export type AuthResult =
  | { ok: true; userId?: string }
  | { ok: false; reason: "missing_token" | "unauthorized" | "api_unavailable" };

/**
 * Require the API to validate the bearer token before running any tool.
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
    return { ok: false, reason: "api_unavailable" };
  }
}

export function unauthorizedContent(reason: AuthResult & { ok: false }) {
  const text =
    reason.reason === "missing_token"
      ? "unauthorized: set SKALEAGENTS_API_TOKEN"
      : reason.reason === "unauthorized"
        ? "unauthorized: invalid SKALEAGENTS_API_TOKEN"
        : "api unavailable: could not validate SKALEAGENTS_API_TOKEN";
  return {
    isError: true as const,
    content: [{ type: "text" as const, text }],
  };
}
