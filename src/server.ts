import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { requireApiAuth, unauthorizedContent } from "./auth.js";
import { architectureFindings, fetchPublicBotHints } from "./review.js";
import { looksLikeIac, ScanInputError } from "./iac/parse.js";
import { filterFindings, scanIac, summarize } from "./iac/scan.js";
import { registerConsultation } from "./application/tools.js";
import { lockfileNames, lookupCves, parseLockfile } from "./cves.js";
import { presentReview } from "./review-edits.js";
import { savedTargetSchema, withSavedReview } from "./saved-review.js";
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
        readOnlyHint: false,
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
            "serverless",
            "iam",
            "package",
            "application",
            "auto",
          ])
          .optional()
          .default("auto")
          .describe(
            "Content format: terraform, cloudformation, kubernetes, pulumi, compose, dockerfile, github, helm, ansible, bicep, arm, gitlab, azure-pipelines, cloudbuild, tfvars, serverless, iam, package, application, auto.",
          ),
        target: savedTargetSchema,
      },
    },
    async ({ content, focus, format, minSeverity, maxFindings, target }) => {
      const botHints = fetchPublicBotHints();
      if (!remote) {
        const auth = await requireApiAuth();
        if (!auth.ok) return unauthorizedContent(auth);
      }
      try {
        const options = { focus, minSeverity, maxFindings };
        const save = {
          tool: "review_architecture",
          target: target ?? null,
          submittedPaths: [target?.path ?? ""],
        };
        if (
          format !== "application" &&
          (format !== "auto" || looksLikeIac(content))
        ) {
          return result(await withSavedReview(presentReview(content, {
            ...scanIac(content, { ...options, format }),
            botHints: await botHints,
          }), save));
        }
        const findings = filterFindings(
          architectureFindings(content, focus).slice(1),
          options,
        );
        return result(await withSavedReview(presentReview(content, {
          status: "completed",
          engineVersion: VERSION,
          format: "application",
          focus,
          findings: findings.slice(0, maxFindings),
          totalFindings: findings.length,
          totals: summarize(findings),
          truncated: findings.length > maxFindings,
          limitations: [
            "Application checks are text patterns, not a language-aware or runtime analysis. Findings do not establish that code is safe.",
            "Infrastructure bottleneck checks cover a disabled timeout, a one-connection pool, and an unbounded retry limit.",
          ],
          botHints: await botHints,
        }), save));
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
          "Parse Terraform HCL/JSON, CloudFormation YAML/JSON, Kubernetes manifests, Pulumi YAML, Pulumi programs, or Docker Compose. Includes Dockerfile, GitHub Actions, Helm templates, Ansible playbooks, Bicep files, ARM templates, GitLab CI, Azure Pipelines, Cloud Build, tfvars, Serverless Framework, a standalone IAM policy, and package.json. Helm templates, Ansible facts, Bicep modules, ARM expressions, pipelines, Serverless Framework config, and IAM policies are not executed. Conditions are not evaluated. Terraform module sources are not fetched. Check security, reliability and cost rules with resource locations and remediation. Pulumi programs are scanned as text.",
        annotations: {
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
        _meta: { securitySchemes: [{ type: "oauth2", scopes: ["mcp"] }] },
        inputSchema: {
          content: contentSchema.describe(
            "Terraform HCL/JSON, CloudFormation YAML/JSON, Kubernetes YAML/JSON, Pulumi YAML or program text, or Docker Compose. Includes Dockerfile, GitHub Actions, Helm templates, Ansible playbooks, Bicep files, ARM templates, GitLab CI, Azure Pipelines, Cloud Build, tfvars, Serverless Framework, a standalone IAM policy, and package.json.",
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
              "serverless",
              "iam",
              "package",
              "auto",
            ])
            .default("auto"),
          ...filters,
          target: savedTargetSchema,
        },
      },
      async ({ content, format, focus, minSeverity, maxFindings, target }) => {
        if (!remote) {
          const auth = await requireApiAuth();
          if (!auth.ok) return unauthorizedContent(auth);
        }

        try {
          return result(await withSavedReview(presentReview(
            content,
            scanIac(content, { format, focus, minSeverity, maxFindings }),
          ), {
            tool: name,
            target: target ?? null,
            submittedPaths: [target?.path ?? ""],
          }));
        } catch (error) {
          return inputError(error);
        }
      },
    );

  server.registerTool(
    "scan_dependencies",
    {
      title: "Scan dependencies for known CVEs",
      description:
        "Check the exact package versions in one lockfile against OSV.dev and report known CVEs as CVE001 with severity and fixed versions. Accepts package-lock.json, pnpm-lock.yaml, yarn.lock, composer.lock, requirements.txt (exact == pins) or go.sum. Sends ecosystem, package name and version to api.osv.dev, never the lockfile or source. Skips npm packages not resolved from the public registry and requirements files with a custom index. Not covered: container images, OS packages, Cargo, Gemfile. A failed lookup is an error, never a clean result.",
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
      _meta: { securitySchemes: [{ type: "oauth2", scopes: ["mcp"] }] },
      inputSchema: {
        content: z.string().min(1).max(2_000_000).describe("Full text of the lockfile"),
        filename: z.enum(lockfileNames).describe("Which lockfile this is"),
        minSeverity: filters.minSeverity,
        maxFindings: filters.maxFindings,
      },
    },
    async ({ content, filename, minSeverity, maxFindings }) => {
      if (!remote) {
        const auth = await requireApiAuth();
        if (!auth.ok) return unauthorizedContent(auth);
      }
      const fail = (error: string, message: string) => ({
        isError: true,
        content: [{ type: "text" as const, text: JSON.stringify({ error, message }) }],
      });
      let packages: ReturnType<typeof parseLockfile>;
      try {
        packages = parseLockfile(filename, filename, content);
      } catch (error) {
        return fail("invalid_input", `${filename} could not be parsed: ${error instanceof Error ? error.message : String(error)}`);
      }
      if (packages.length > 5000) {
        return fail("invalid_input", `${packages.length} packages is over the hosted limit of 5000. Run skaleagents-swarm scan --cves locally.`);
      }
      try {
        // Answer before the hosted request limit so a slow OSV is reported, not a bare 504.
        const found = await lookupCves(packages, fetch, Date.now() + 15_000);
        const visible = filterFindings(found, { minSeverity, focus: "security" });
        return result({
          status: "completed",
          engineVersion: VERSION,
          source: "osv.dev",
          filename,
          packagesChecked: packages.length,
          summary: `Checked ${packages.length} packages; ${visible.length} known CVEs match the selected filters.`,
          findings: visible.slice(0, maxFindings),
          totals: summarize(visible),
          totalFindings: visible.length,
          truncated: visible.length > maxFindings,
          limitations: [
            "Only packages resolved from public registries are checked.",
            "Severity comes from the advisory rating; unrated advisories show as medium.",
            "Container images, OS packages, Cargo and Gemfile lockfiles are not covered.",
          ],
        });
      } catch (error) {
        return fail("lookup_failed", `CVE lookup failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  return server;
}
