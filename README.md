# @skaleagents/swarm

SkaleAgents MCP server. The hosted connection is `https://skaleagents.com/mcp`.

## Quick start

Copy `https://skaleagents.com/mcp` into your client and choose OAuth. Sign in
with Google and click Allow. Leave client ID and secret blank when the client
asks. Setup steps for Cursor, Claude Code, Claude Desktop, ChatGPT, and Codex
are on the [MCP config page](https://skaleagents.com/mcp-config).

Tools: `plan_architecture_review`, `review_application_architecture`,
`review_architecture`, and `scan_iac`. The older `scan_iac_stub` name remains
an alias for the IaC scanner.

`review_architecture` accepts application source or infrastructure text. Your AI
client reads the files in its workspace and sends the relevant content through
the MCP tool for a structured review.

## Whole-application consultation

Ask your connected assistant:

> Use SkaleAgents as an independent consultant to review this application's
> architecture. Read the relevant files, ask me about the important design
> decisions, and explain what is sound, what needs changes, and what needs
> more evidence.

The `architecture_consultation` MCP prompt provides this workflow for clients
that support prompts. The tools work directly in chat too:

1. `plan_architecture_review` takes a repository-relative `filePaths` inventory
   and optional `context`. It suggests files to read and asks up to three
   questions at a time.
2. The assistant reads related files through its own workspace tools and calls
   `review_application_architecture` with `files: [{ path, content }]` and the
   context collected so far.
3. Answer the follow-up questions. The assistant resubmits the relevant files
   and updated context, then uses the evidence to review the design and compare
   alternatives.

The review covers product fit, routing/rendering, module boundaries, data
access, authorization, reliability, testing/delivery, and deployment/cost.
JavaScript/TypeScript source is parsed into an import graph. Next.js checks
include transitive client imports, private environment access, async Client
Components, metadata exports, error boundaries, Server Action modules, and
explicit Edge runtime incompatibilities. Type-only imports and Server Action
boundaries are respected.

Context fields are `purpose`, `criticalFlows`, `accessControl`, `data`,
`rendering`, `deployment`, `reliability`, `testing`, and `constraints`. Each
holds the owner's answer as text. Calls are stateless: carry answers forward
instead of relying on a server-side conversation ID.

Submit up to 80 files, at most 150,000 characters per file and 500,000 combined.
Use paths relative to one application package root, including `package.json`
and `tsconfig.json` or `jsconfig.json`. Missing imports become evidence requests,
not invented findings. The intake accepts up to 3,000 file paths.

Results include an architecture map, referenced findings, an assessment agenda
for every review area, and the next questions. The MCP provides static evidence
and the connected assistant's model reasons through the architecture. No
separate hosted model is invoked, and the tools do not clone repositories or
run submitted code. A clean static check is not a whole-system correctness
verdict. The [MCP config page](https://skaleagents.com/mcp-config) has an interactive
review-brief builder.

## Infrastructure scanning

`scan_iac` parses Terraform HCL/JSON, CloudFormation YAML/JSON, and Kubernetes
manifests, including multi-document YAML and Kubernetes Lists. It also reads
Dockerfiles, GitHub Actions workflows, Helm templates, Ansible playbooks,
Bicep files, and ARM templates. It returns a
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

## Hosted transport

The web app hosts `https://skaleagents.com/mcp` using `handleMcpRequest` from
`@skaleagents/swarm/http`. Audit workers import `scanIac` from
`@skaleagents/swarm/scan`. It validates each bearer credential with the API's
`/api/oauth/mcp-token` endpoint before running a tool. Tokens are bound to the
MCP resource and cannot access unrelated API routes. Credentials are not
forwarded to the public bot directory.

`protectedResourceMetadata` exports the discovery response for
`/.well-known/oauth-protected-resource/mcp`.

## Local development

People working on this repo need Node.js 20 or newer. This is not the way to connect a client.

```bash
git clone https://github.com/SkaleAgents/mcp-server.git
cd mcp-server
npm install
npm run build
npm test
```

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `SKALEAGENTS_API_TOKEN` | No | Legacy override for CI only, not the way to connect. |
| `PLATFORM_API_URL` | No | Defaults to `https://api.skaleagents.com`. Override only for local development or another API deployment. Empty values use the default. |
| `SKALEAGENTS_OAUTH_CACHE` | No | OAuth cache path. Default `~/.config/skaleagents/oauth.json`. |
| `SKALEAGENTS_OAUTH_ENABLED` | No | Set to `false` only to disable browser OAuth. |
| `MCP_RESOURCE_URL` | No | Hosted transport audience. Defaults to `https://skaleagents.com/mcp`; must match the API OAuth configuration. |

## Steady-state tool latency probe

This probe uses the legacy `SKALEAGENTS_API_TOKEN` CI override. It is not how a client connects. With that variable already set, run
`npm run benchmark:tool`. The script builds this checkout, starts its stdio MCP
server, makes five warmup calls, then times 50 `review_architecture` calls on a
fixed synthetic application snippet. Set `BENCHMARK_WARMUP` from 0 to 20 and
`BENCHMARK_SAMPLES` from 1 to 200 to change those counts. It refuses to start
without the token and never opens an OAuth browser flow.
Set `BENCHMARK_INPUT_FILE` to an existing, non-secret application source file to
measure that source instead of the fixed snippet. Run separate samples for
different file sizes or code patterns. The output reports only the input byte
count and SHA-256 digest, not its path or contents. The supplied source must be
nonempty and at most 500,000 characters. Use the same local file and pinned
package commit when comparing runs.

Each timed call includes JSON-RPC transport, hosted API account validation,
static review, and the API bot-hint lookup. Process startup, the MCP handshake,
OAuth login or refresh, and a hosted MCP runtime are outside the timer. The
output contains aggregate p50/p95/p99/max latency, the API origin, and counts.
It also reports response-header timing for the `/api/user` and `/api/bots`
fetches, their overlap, and the remaining tool-call time after subtracting the
union of those intervals. Overlapping time is counted once.
That remainder includes response bodies, local work, and stdio overhead; it is
not a single server or network measurement. Output omits the credential,
account, and source text. A failed or unauthorized
call aborts instead of being counted as a successful sample. This short,
single-client diagnostic does not establish the platform's sub-second p95 or
monthly availability target.

## Auth behavior

- Missing bearer override → browser OAuth starts automatically.
- OAuth access and refresh credentials are stored with local-user-only file permissions.
- A rejected or revoked connection returns an auth error and does not run a tool.
- The connection is user-scoped; bot visibility follows `api` RBAC.

Hub contract: [docs/contracts/mcp/tools.md](https://github.com/SkaleAgents/workspace/blob/main/docs/contracts/mcp/tools.md)
