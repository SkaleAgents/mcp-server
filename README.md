# @skaleagents/swarm

Stdio MCP server for SkaleAgents Phase 1 (`review_architecture`, `scan_iac_stub`).

Talks to Laravel `api` with `SKALEAGENTS_API_TOKEN` (Sanctum personal access token from mock Grok login).

## Local

```bash
npm install
cp .env.example .env
# Get a token:
# curl -s -X POST http://localhost:8082/api/auth/grok/callback \
#   -H 'Content-Type: application/json' \
#   -d '{"code":"mcp","displayName":"MCP"}'
npm run build
npm test
npm run smoke   # needs Sail API on :8082
```

## Cursor / Claude Code

```json
{
  "mcpServers": {
    "skaleagents": {
      "command": "npx",
      "args": ["tsx", "/absolute/path/to/mcp-server/src/index.ts"],
      "env": {
        "SKALEAGENTS_API_TOKEN": "<token from grok callback>",
        "PLATFORM_API_URL": "http://localhost:8082"
      }
    }
  }
}
```

Or after build: `"command": "node", "args": ["/absolute/path/to/mcp-server/dist/index.js"]`.

Hub contract: [docs/contracts/mcp/tools.md](https://github.com/SkaleAgents/workspace/blob/main/docs/contracts/mcp/tools.md)
