import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  getApiAccessToken,
  requireApiAuth,
  unauthorizedContent,
} from "./auth.js";
import { architectureFindings, fetchPublicBotHints } from "./review.js";
import { looksLikeIac, ScanInputError } from "./iac/parse.js";
import { filterFindings, scanIac, summarize } from "./iac/scan.js";

const contentSchema = z
  .string()
  .min(1)
  .max(500_000)
  .refine((value) => value.trim().length > 0, "Content must not be whitespace");
const filters = {
  focus: z
    .enum(["security", "reliability", "cost", "general"])
    .default("general"),
  minSeverity: z
    .enum(["info", "low", "medium", "high", "critical"])
    .default("info")
    .describe("Lowest finding severity to return"),
  maxFindings: z
    .number()
    .int()
    .min(1)
    .max(500)
    .default(100)
    .describe(
      "Maximum findings returned; totals include all matching findings",
    ),
};

function result(output: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(output, null, 2) }],
    structuredContent: output,
  };
}

function inputError(error: unknown) {
  if (!(error instanceof ScanInputError)) throw error;
  return {
    isError: true,
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({
          error: "invalid_input",
          message: error.message,
        }),
      },
    ],
  };
}

export function createServer(remote = false) {
  const server = new McpServer({
    name: "skaleagents-swarm",
    version: "0.5.0",
  });

  server.registerTool(
    "review_architecture",
    {
      title: "Review architecture",
      description:
        "Review application source or parsed infrastructure for security, reliability, and cost risks. Returns located findings, rule IDs, remediation and coverage limits.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
      _meta: { securitySchemes: [{ type: "oauth2", scopes: ["mcp"] }] },
      inputSchema: {
        content: contentSchema.describe(
          "Application source or IaC text to review",
        ),
        ...filters,
        format: z
          .enum([
            "terraform",
            "cloudformation",
            "kubernetes",
            "application",
            "auto",
          ])
          .optional()
          .default("auto")
          .describe(
            "Content format: terraform, cloudformation, kubernetes, application, auto",
          ),
      },
    },
    async ({ content, focus, format, minSeverity, maxFindings }) => {
      let token: string | undefined;
      if (!remote) {
        const auth = await requireApiAuth();
        if (!auth.ok) return unauthorizedContent(auth);
        token = (await getApiAccessToken()) ?? undefined;
        if (!token)
          return unauthorizedContent({ ok: false, reason: "oauth_failed" });
      }
      try {
        const options = { focus, minSeverity, maxFindings };
        if (
          format !== "application" &&
          (format !== "auto" || looksLikeIac(content))
        ) {
          return result({
            ...scanIac(content, { ...options, format }),
            botHints: await fetchPublicBotHints(token),
          });
        }
        const findings = filterFindings(
          architectureFindings(content, focus).slice(1),
          options,
        );
        return result({
          status: "completed",
          engineVersion: "0.5.0",
          format: "application",
          focus,
          summary: `Application review completed; ${findings.length} findings match the selected filters.`,
          findings: findings.slice(0, maxFindings),
          totalFindings: findings.length,
          totals: summarize(findings),
          truncated: findings.length > maxFindings,
          limitations: [
            "Application checks are text patterns, not a language-aware or runtime analysis. Findings do not establish that code is safe.",
          ],
          botHints: await fetchPublicBotHints(token),
        });
      } catch (error) {
        return inputError(error);
      }
    },
  );

  for (const name of ["scan_iac", "scan_iac_stub"])
    server.registerTool(
      name,
      {
        title:
          name === "scan_iac"
            ? "Scan infrastructure"
            : "Scan infrastructure (compatibility alias)",
        description:
          (name === "scan_iac_stub"
            ? "Compatibility alias for scan_iac; runs the full scanner. "
            : "") +
          "Parse Terraform HCL/JSON, CloudFormation YAML/JSON, or Kubernetes manifests. Check security, reliability and cost rules with resource locations and remediation.",
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
        _meta: { securitySchemes: [{ type: "oauth2", scopes: ["mcp"] }] },
        inputSchema: {
          content: contentSchema.describe(
            "Terraform HCL/JSON, CloudFormation YAML/JSON, or Kubernetes YAML/JSON",
          ),
          format: z
            .enum(["terraform", "cloudformation", "kubernetes", "auto"])
            .default("auto"),
          ...filters,
        },
      },
      async ({ content, format, focus, minSeverity, maxFindings }) => {
        if (!remote) {
          const auth = await requireApiAuth();
          if (!auth.ok) return unauthorizedContent(auth);
        }

        try {
          return result(
            scanIac(content, { format, focus, minSeverity, maxFindings }),
          );
        } catch (error) {
          return inputError(error);
        }
      },
    );

  return server;
}
