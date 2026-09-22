#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  getApiAccessToken,
  requireApiAuth,
  unauthorizedContent,
} from "./auth.js";
import {
  architectureFindings,
  countIacResources,
  fetchPublicBotHints,
} from "./review.js";

const server = new McpServer({
  name: "skaleagents-swarm",
  version: "0.3.0",
});

server.registerTool(
  "review_architecture",
  {
    title: "Review architecture",
    description:
      "Review application source or infrastructure text for security, reliability, and cost risks.",
    inputSchema: {
      content: z
        .string()
        .min(1)
        .max(500_000)
        .describe("Application source or IaC text to review"),
      focus: z
        .enum(["security", "reliability", "cost", "general"])
        .optional()
        .default("general")
        .describe("Review focus: security, reliability, cost, general"),
      format: z
        .enum(["terraform", "cloudformation", "kubernetes", "application", "auto"])
        .optional()
        .default("auto")
        .describe(
          "Content format: terraform, cloudformation, kubernetes, application, auto",
        ),
    },
  },
  async ({ content, focus, format }) => {
    const auth = await requireApiAuth();
    if (!auth.ok) return unauthorizedContent(auth);

    const token = await getApiAccessToken();
    if (!token) return unauthorizedContent({ ok: false, reason: "oauth_failed" });
    const botHints = await fetchPublicBotHints(token);
    const focusValue = focus ?? "general";
    const formatValue = format ?? "auto";

    const output = {
      summary: `Structured architecture review from @skaleagents/swarm (focus=${focusValue}, format=${formatValue})`,
      findings: architectureFindings(content, focusValue),
      botHints,
    };

    return {
      content: [{ type: "text", text: JSON.stringify(output, null, 2) }],
    };
  },
);

server.registerTool(
  "scan_iac_stub",
  {
    title: "Scan IaC (stub)",
    description: "Stub seam for Phase 2 DevSecOps IaC scanning.",
    inputSchema: {
      content: z
        .string()
        .min(1)
        .max(500_000)
        .describe("Terraform / CloudFormation / Kubernetes YAML"),
      format: z
        .string()
        .optional()
        .describe("terraform, cloudformation, kubernetes, auto"),
    },
  },
  async ({ content, format }) => {
    const auth = await requireApiAuth();
    if (!auth.ok) return unauthorizedContent(auth);

    const formatValue =
      format === "terraform" ||
      format === "cloudformation" ||
      format === "kubernetes" ||
      format === "auto"
        ? format
        : "auto";

    const output = {
      status: "stub",
      message: "Full IaC scanning lands in Phase 2 agent-swarm",
      format: formatValue,
      parsedResourceCount: countIacResources(content),
    };

    return {
      content: [{ type: "text", text: JSON.stringify(output, null, 2) }],
    };
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
