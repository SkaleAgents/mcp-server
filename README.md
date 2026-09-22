# @skaleagents/swarm

Public stdio MCP server for SkaleAgents Phase 1. Talks to the Laravel **api**
over JSON and uses browser OAuth for sign-in.

Tools: `review_architecture`, `scan_iac_stub`.

`review_architecture` accepts application source or infrastructure text. Your AI
client reads the files in its workspace and sends the relevant content through
the MCP tool for a structured review.

## Prerequisites

1. **API running:** Sail on `http://localhost:8082` (or your hosted API URL later).
2. A browser that can open the SkaleAgents sign-in page.

The first tool call opens browser sign-in. Approve MCP access there and return
to your AI client. The package stores the OAuth refresh credential locally and
refreshes access automatically. You do not need to create or paste an API key.
Active connections can be revoked from the web app's MCP settings page.

## Local development

```bash
git clone https://github.com/SkaleAgents/mcp-server.git
cd mcp-server
npm install
cp .env.example .env
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
        "PLATFORM_API_URL": "https://api.skaleagents.com"
      }
    }
  }
}
```

Restart Cursor after saving. In Agent/Chat, tools should appear as `review_architecture` and `scan_iac_stub`.

## Claude Code

Point `command`/`args` at `node .../dist/index.js` or `npx @skaleagents/swarm` once published. OAuth starts on the first tool call.

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `SKALEAGENTS_API_TOKEN` | No | Legacy Sanctum bearer-token override. OAuth is used when empty. |
| `PLATFORM_API_URL` | No | Default `http://localhost:8082` |
| `SKALEAGENTS_OAUTH_CACHE` | No | OAuth cache path. Default `~/.config/skaleagents/oauth.json`. |
| `SKALEAGENTS_OAUTH_ENABLED` | No | Set to `false` only to disable browser OAuth. |

## Auth behavior

- Missing bearer override → browser OAuth starts automatically.
- OAuth access and refresh credentials are stored with local-user-only file permissions.
- A rejected or revoked connection returns an auth error and does not run a tool.
- The connection is user-scoped; bot visibility follows `api` RBAC.

Hub contract: [docs/contracts/mcp/tools.md](https://github.com/SkaleAgents/workspace/blob/main/docs/contracts/mcp/tools.md)
