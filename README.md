# @skaleagents/swarm

SkaleAgents MCP server with local stdio and hosted Streamable HTTP transports.
Uses browser OAuth for sign-in.

Tools: `review_architecture`, `scan_iac`. The older `scan_iac_stub` name remains
an alias for the full scanner.

`review_architecture` accepts application source or infrastructure text. Your AI
client reads the files in its workspace and sends the relevant content through
the MCP tool for a structured review.

## Infrastructure scanning

`scan_iac` parses Terraform HCL/JSON, CloudFormation YAML/JSON, and Kubernetes
manifests, including multi-document YAML and Kubernetes Lists. It returns a
resource inventory and findings with stable rule IDs, severity, property paths,
line locations, and remediation. Findings never include matched secret values.

Checks cover public ingress, wildcard IAM, public storage, encryption settings,
bucket versioning, RDS protection, EC2 metadata, Kubernetes privileges, images,
resource requests, probes, replicas, inline Secrets, and RBAC. Literal credential
and HTTP URL checks also run against parsed resource properties.

Example tool arguments:

```json
{
  "content": "resource \"aws_db_instance\" \"app\" { publicly_accessible = true }",
  "format": "terraform",
  "focus": "security",
  "minSeverity": "medium",
  "maxFindings": 100
}
```

Both tools accept `focus` (`general`, `security`, `reliability`, or `cost`),
`minSeverity` (`info` through `critical`), and `maxFindings` (1 to 500, default
100). Content must contain 1 to 500,000 characters and cannot be whitespace.
`format` defaults to `auto`; only `review_architecture` accepts `application`.

Results are returned as JSON text and MCP `structuredContent`. `totalFindings`
and `totals` cover all findings matching the filters; `truncated` signals that
`maxFindings` limited the returned list. `rulesEvaluated` lists the IaC checks
that ran. Malformed input returns a tool error, not a clean scan.

IaC reviews use the same scanner through either tool. Application reviews use
text patterns. Neither mode inspects live infrastructure. Terraform expressions,
CloudFormation intrinsics, and external modules are not evaluated. HCL line
locations point to resource declarations; property paths identify the setting.
YAML aliases must be expanded before submission. Coverage limits are included
in every result. An empty finding list is not proof that a system is secure.

## Hosted connection

Use `https://skaleagents.com/mcp` in Claude Desktop or ChatGPT's custom connector
settings. Choose OAuth and leave client ID and secret fields blank. The client
registers itself, opens Google sign-in, and asks you to approve MCP access.
See [client setup](https://skaleagents.com/settings) for Cursor, Claude Code,
Claude Desktop, ChatGPT, and Codex instructions.

The web app hosts this endpoint using `handleMcpRequest` from
`@skaleagents/swarm/http`. It validates each bearer credential with the API's
`/api/oauth/mcp-token` endpoint before running a tool. Tokens are bound to the
MCP resource and cannot access unrelated API routes. Credentials are not
forwarded to the public bot directory.

`protectedResourceMetadata` exports the discovery response for
`/.well-known/oauth-protected-resource/mcp`.

## Local stdio prerequisites

1. Node.js 20 or newer. The client connects to `https://api.skaleagents.com` by default.
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

### Option B: published package (hosted API)

```json
{
  "mcpServers": {
    "skaleagents": {
      "command": "npx",
       "args": ["-y", "@skaleagents/swarm@0.5.0"]
    }
  }
}
```

Restart Cursor after saving. In Agent/Chat, tools should appear as `review_architecture`, `scan_iac`, and the compatibility alias `scan_iac_stub`.

## Claude Code

Use the published package configuration above in `.mcp.json`. OAuth starts on the first tool call. No API URL or keys are needed.

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `SKALEAGENTS_API_TOKEN` | No | Legacy Sanctum bearer-token override. OAuth is used when empty. |
| `PLATFORM_API_URL` | No | Defaults to `https://api.skaleagents.com`. Override only for local development or another API deployment. Empty values use the default. |
| `SKALEAGENTS_OAUTH_CACHE` | No | OAuth cache path. Default `~/.config/skaleagents/oauth.json`. |
| `SKALEAGENTS_OAUTH_ENABLED` | No | Set to `false` only to disable browser OAuth. |
| `MCP_RESOURCE_URL` | No | Hosted transport audience. Defaults to `https://skaleagents.com/mcp`; must match the API OAuth configuration. |

## Auth behavior

- Missing bearer override → browser OAuth starts automatically.
- OAuth access and refresh credentials are stored with local-user-only file permissions.
- A rejected or revoked connection returns an auth error and does not run a tool.
- The connection is user-scoped; bot visibility follows `api` RBAC.

Hub contract: [docs/contracts/mcp/tools.md](https://github.com/SkaleAgents/workspace/blob/main/docs/contracts/mcp/tools.md)
