import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { requireApiAuth, unauthorizedContent } from "../auth.js";
import { ScanInputError } from "../iac/parse.js";
import {
  contextSchema,
  fileSchema,
  planReview,
  consultationInstructions,
} from "./intake.js";
import { reviewApplication } from "./review.js";

async function run(remote: boolean, compute: () => Record<string, unknown>) {
  if (!remote) {
    const auth = await requireApiAuth();
    if (!auth.ok) return unauthorizedContent(auth);
  }
  try {
    const output = compute();
    return {
      content: [
        { type: "text" as const, text: JSON.stringify(output, null, 2) },
      ],
      structuredContent: output,
    };
  } catch (error) {
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
}

export function registerConsultation(server: McpServer, remote: boolean) {
  const annotations = {
    readOnlyHint: true,
    destructiveHint: false,
    openWorldHint: false,
  };
  const security = { securitySchemes: [{ type: "oauth2", scopes: ["mcp"] }] };
  server.registerTool(
    "plan_architecture_review",
    {
      title: "Plan a whole-application architecture review",
      description:
        "Start an interactive architecture consultation. Supply repository-relative file paths and known project context. Returns prioritized files to read, review areas, and up to three follow-up questions. Covers the whole application, including Next.js apps, not only infrastructure or scaling.",
      annotations,
      _meta: security,
      inputSchema: {
        filePaths: z
          .array(z.string().min(1).max(300))
          .max(3000)
          .describe(
            "Repository file inventory, relative to the application package root; use the client's workspace tools to list files",
          ),
        context: contextSchema,
      },
    },
    ({ filePaths, context }) =>
      run(remote, () => planReview(filePaths, context)),
  );
  server.registerTool(
    "review_application_architecture",
    {
      title: "Review whole-application architecture",
      description:
        "Review related source files as an application. Builds a JS/TS import graph, checks Next.js server/client and runtime boundaries, maps routes and mutations, and returns evidence-backed findings plus questions covering data, auth, reliability, tests, deployment and product fit. Pass answers in context on subsequent calls. No repository fetch or execution; the connected assistant reasons about system-level tradeoffs using the returned evidence.",
      annotations,
      _meta: security,
      inputSchema: {
        files: z
          .array(fileSchema)
          .min(1)
          .max(80)
          .describe(
            "Related source/config/test files with repository-relative paths; include package.json and tsconfig.json. At most 500,000 combined content characters",
          ),
        context: contextSchema,
      },
    },
    ({ files, context }) =>
      run(remote, () => reviewApplication(files, context)),
  );
  server.registerPrompt(
    "architecture_consultation",
    {
      title: "Independent application architecture consultation",
      description:
        "Guide a multi-turn whole-application review with source evidence, follow-up questions, and design tradeoffs.",
      argsSchema: {
        goal: z
          .string()
          .max(3000)
          .optional()
          .describe("The architecture question or business goal to assess"),
      },
    },
    ({ goal }) => ({
      description: "Evidence-led architecture consultation",
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `${consultationInstructions}\n\nReview goal: ${goal || "Assess the whole application's architecture and explain the highest-priority improvements."}`,
          },
        },
      ],
    }),
  );
}
