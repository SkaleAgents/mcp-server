import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { requireApiAuth, unauthorizedContent } from "./auth.js";
import { architectureFindings, fetchPublicBotHints } from "./review.js";
import { looksLikeIac, ScanInputError } from "./iac/parse.js";
import { filterFindings, scanIac, summarize } from "./iac/scan.js";
import { registerConsultation } from "./application/tools.js";
import { VERSION } from "./version.js";

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
  const server = new McpServer(
    { name: "skaleagents-swarm", version: VERSION },
    {
      instructions:
        "For a whole application architecture consultation, start with plan_architecture_review, read relevant files with the client's workspace tools, then call review_application_architecture. Ask its follow-up questions and carry answers forward in context. Use review_architecture for individual source snippets and scan_iac for infrastructure. Ground conclusions in the returned evidence and coverage limits.",
    },
  );
  registerConsultation(server, remote);

  server.registerTool(
    "review_architecture",
    {
      title: "Review architecture",
      description:
        "Review individual source snippets or parsed infrastructure for security, reliability, and cost risks. Application checks include infrastructure bottlenecks: a disabled timeout, a one-connection pool, and an unbounded retry limit. For a whole application or Next.js architecture consultation, use plan_architecture_review and review_application_architecture instead.",
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
            "pulumi",
            "compose",
            "dockerfile",
            "github",
            "helm",
            "ansible",
            "bicep",
            "arm",
            "gitlab",
            "azure-pipelines",
            "cloudbuild",
            "tfvars",
            "application",
            "auto",
          ])
          .optional()
          .default("auto")
          .describe(
            "Content format: terraform, cloudformation, kubernetes, pulumi, compose, dockerfile, github, helm, ansible, bicep, arm, gitlab, azure-pipelines, cloudbuild, tfvars, application, auto.",
          ),
      },
    },
    async ({ content, focus, format, minSeverity, maxFindings }) => {
      const botHints = fetchPublicBotHints();
      if (!remote) {
        const auth = await requireApiAuth();
        if (!auth.ok) return unauthorizedContent(auth);
      }
      try {
        const options = { focus, minSeverity, maxFindings };
        if (
          format !== "application" &&
          (format !== "auto" || looksLikeIac(content))
        ) {
          return result({
            ...scanIac(content, { ...options, format }),
            botHints: await botHints,
          });
        }
        const findings = filterFindings(
          architectureFindings(content, focus).slice(1),
          options,
        );
        return result({
          status: "completed",
          engineVersion: VERSION,
          format: "application",
          focus,
          summary: `Application review completed; ${findings.length} findings match the selected filters.`,
          findings: findings.slice(0, maxFindings),
          totalFindings: findings.length,
          totals: summarize(findings),
          truncated: findings.length > maxFindings,
          limitations: [
            "Application checks are text patterns, not a language-aware or runtime analysis. Findings do not establish that code is safe.",
            "Infrastructure bottleneck checks cover a disabled timeout, a one-connection pool, and an unbounded retry limit.",
          ],
          botHints: await botHints,
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
          "Parse Terraform HCL/JSON, CloudFormation YAML/JSON, Kubernetes manifests, Pulumi YAML, Pulumi programs, or Docker Compose. Includes Dockerfile, GitHub Actions, Helm templates, Ansible playbooks, Bicep files, ARM templates, GitLab CI, Azure Pipelines, Cloud Build, and tfvars. Helm templates, Ansible facts, Bicep modules, ARM expressions, and pipelines are not executed. Terraform module sources are not fetched. Check security, reliability and cost rules with resource locations and remediation. Pulumi programs are scanned as text.",
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
        _meta: { securitySchemes: [{ type: "oauth2", scopes: ["mcp"] }] },
        inputSchema: {
          content: contentSchema.describe(
            "Terraform HCL/JSON, CloudFormation YAML/JSON, Kubernetes YAML/JSON, Pulumi YAML or program text, or Docker Compose. Includes Dockerfile, GitHub Actions, Helm templates, Ansible playbooks, Bicep files, ARM templates, GitLab CI, Azure Pipelines, Cloud Build, and tfvars.",
          ),
          format: z
            .enum([
              "terraform",
              "cloudformation",
              "kubernetes",
              "pulumi",
              "compose",
              "dockerfile",
              "github",
              "helm",
              "ansible",
              "bicep",
              "arm",
              "gitlab",
              "azure-pipelines",
              "cloudbuild",
              "tfvars",
              "auto",
            ])
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
