#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { requireApiAuth, unauthorizedContent } from "./auth.js";
import {
  cannedFindings,
  countIacResources,
  fetchPublicBotHints,
} from "./review.js";

const server = new McpServer({
  name: "skaleagents-swarm",
  version: "0.1.0",
});

server.registerTool(
  "review_architecture",
  {
    title: "Review architecture",
    description:
      "Request a high-level architecture / security review of a code or IaC snippet.",
    inputSchema: {
      content: z.string().describe("Source or IaC text to review"),
      focus: z
        .string()
        .optional()
        .describe("Review focus: security, reliability, cost, general"),
    },
  },
  async ({ content, focus }) => {
    const auth = await requireApiAuth();
    if (!auth.ok) return unauthorizedContent(auth);

    const botHints = await fetchPublicBotHints();
    const focusValue =
      focus === "security" ||
      focus === "reliability" ||
      focus === "cost" ||
      focus === "general"
        ? focus
        : "general";

    const output = {
      summary: "Phase 1 stub architecture review from @skaleagents/swarm",
      findings: cannedFindings(content, focusValue),
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
