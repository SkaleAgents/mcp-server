# @skaleagents/swarm

Public stdio MCP server for SkaleAgents Phase 1. Talks to the Laravel **api**
(JSON only, no web UI) with a Sanctum bearer token.

Tools: `review_architecture`, `scan_iac_stub`.

`review_architecture` accepts application source or infrastructure text. Your AI
client reads the files in its workspace and sends the relevant content through
the MCP tool for a structured review.

## Prerequisites

1. **API running:** Sail on `http://localhost:8082` (or your hosted API URL later).
2. **Bearer token:** mint one in the web app: sign in → **MCP** → Create token.
   Or for local-only testing:
   ```bash
    curl -s -X POST http://localhost:8082/api/auth/google/callback \
      -H 'Content-Type: application/json' \
      -d '{"code":"mcp","displayName":"MCP User","email":"mcp@example.com"}' | jq -r .token
   ```

## Local development

```bash
git clone https://github.com/SkaleAgents/mcp-server.git
cd mcp-server
npm install
cp .env.example .env
# Set SKALEAGENTS_API_TOKEN=<token from web app or curl above>
npm run build
npm test
npm run smoke   # needs API on :8082
```

## Cursor

Add to `.cursor/mcp.json` (project) or Cursor Settings → MCP:

### Option A: local clone (recommended while API is local)

```json
{
  "mcpServers": {
    "skaleagents": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-server/dist/index.js"],
      "env": {
        "SKALEAGENTS_API_TOKEN": "<paste token from web app → API tokens>",
        "PLATFORM_API_URL": "http://localhost:8082"
      }
    }
  }
}
```

Dev without build:

```json
{
  "mcpServers": {
    "skaleagents": {
      "command": "npx",
      "args": ["tsx", "/absolute/path/to/mcp-server/src/index.ts"],
      "env": {
        "SKALEAGENTS_API_TOKEN": "<token>",
        "PLATFORM_API_URL": "http://localhost:8082"
      }
    }
  }
}
```

### Option B: after npm publish (hosted API)

```json
{
  "mcpServers": {
    "skaleagents": {
      "command": "npx",
      "args": ["-y", "@skaleagents/swarm"],
      "env": {
        "SKALEAGENTS_API_TOKEN": "<token>",
        "PLATFORM_API_URL": "https://api.skaleagents.com"
      }
    }
  }
}
```

Restart Cursor after saving. In Agent/Chat, tools should appear as `review_architecture` and `scan_iac_stub`.

## Claude Code

Same env vars; point `command`/`args` at `node …/dist/index.js` or `npx @skaleagents/swarm` once published.

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `SKALEAGENTS_API_TOKEN` | Yes | Sanctum bearer token (from the web **MCP** page) |
| `PLATFORM_API_URL` | No | Default `http://localhost:8082` |

## Auth behavior

- Missing/invalid token → tools return an **unauthorized** error (fail closed).
- Token is user-scoped; bot visibility follows `api` RBAC.

Hub contract: [docs/contracts/mcp/tools.md](https://github.com/SkaleAgents/workspace/blob/main/docs/contracts/mcp/tools.md)
