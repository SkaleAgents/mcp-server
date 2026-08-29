export function getApiUrl(): string {
  return (
    process.env.PLATFORM_API_URL?.replace(/\/$/, "") ?? "http://localhost:8082"
  );
}

export function getApiToken(): string {
  return process.env.SKALEAGENTS_API_TOKEN?.trim() ?? "";
}
