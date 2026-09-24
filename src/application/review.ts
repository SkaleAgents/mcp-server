import ts from "typescript";
import { builtinModules } from "node:module";
import { buildGraph, reference, type Module, type Reference } from "./graph.js";
import {
  areas,
  prepareFiles,
  unanswered,
  consultationInstructions,
  type Area,
  type ReviewContext,
  type SourceFile,
} from "./intake.js";
import { ScanInputError } from "../iac/parse.js";
import { VERSION } from "../version.js";

type Finding = {
  ruleId: string;
  area: Area;
  severity: "high" | "medium";
  confidence: "high" | "medium";
  title: string;
  detail: string;
  remediation: string;
  evidence: Reference[];
  importChain?: string[];
};
const serverPackages = new Set([
  "server-only",
  "next/headers",
  "next/server",
  "@prisma/client",
  "prisma",
  "pg",
  "mysql2",
  "better-sqlite3",
  "mongodb",
  "mongoose",
  "redis",
  "ioredis",
  "drizzle-orm/node-postgres",
  "drizzle-orm/postgres-js",
  "firebase-admin",
]);
const builtins = new Set(
  builtinModules.map((name) => name.replace(/^node:/, "")),
);
const hookNames = new Set([
  "useState",
  "useEffect",
  "useLayoutEffect",
  "useReducer",
  "useContext",
  "useRef",
  "useSyncExternalStore",
]);
const appFile = (path: string) => /^(?:src\/)?app\//.test(path);
const entryFile = (path: string) =>
  appFile(path) &&
  /\/(?:page|layout|route|error|global-error|not-found|loading|template)\.[cm]?[jt]sx?$/.test(
    path,
  );
const testFile = (path: string) =>
  /(?:\.(?:test|spec)\.[cm]?[jt]sx?$|(?:^|\/)(?:tests?|e2e|__tests__)\/)/.test(
    path,
  );

function serverDependency(name: string) {
  return (
    builtins.has(name.replace(/^node:/, "")) ||
    [...serverPackages].some(
      (pkg) => name === pkg || name.startsWith(pkg + "/"),
    )
  );
}

function collectServerPaths(modules: Map<string, Module>) {
  const paths = new Set<string>();
  const queue = [...modules.values()]
    .filter((m) => (entryFile(m.path) || m.server) && !m.client)
    .map((m) => m.path);
  while (queue.length) {
    const path = queue.shift()!;
    if (paths.has(path)) continue;
    paths.add(path);
    for (const dependency of modules.get(path)!.imports)
      if (dependency.resolved && !modules.get(dependency.resolved)!.client)
        queue.push(dependency.resolved);
  }
  return paths;
}

function containsJsx(node: ts.Node): boolean {
  if (
    ts.isJsxElement(node) ||
    ts.isJsxSelfClosingElement(node) ||
    ts.isJsxFragment(node)
  )
    return true;
  return ts.forEachChild(node, containsJsx) ?? false;
}

export function reviewApplication(
  inputFiles: SourceFile[],
  context: ReviewContext,
) {
  const files = prepareFiles(inputFiles);
  const manifestFile = files.find((file) => file.path === "package.json");
  let manifest: Record<string, unknown> = {};
  if (manifestFile) {
    try {
      manifest = JSON.parse(manifestFile.content);
    } catch {
      throw new ScanInputError("Cannot parse package.json.");
    }
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest))
      throw new ScanInputError("package.json must contain an object.");
  }
  const dependencies = {
    ...((manifest.dependencies as Record<string, unknown>) ?? {}),
    ...((manifest.devDependencies as Record<string, unknown>) ?? {}),
  };
  const nextVersion =
    typeof dependencies.next === "string" ? dependencies.next : null;
  const graph = buildGraph(files);
  const { modules, clientPaths } = graph;
  const isNext = !!nextVersion || [...modules.keys()].some(entryFile);
  const serverPaths = collectServerPaths(modules);
  const findings: Finding[] = [];
  const checked = new Set<string>();
  const add = (
    ruleId: string,
    area: Area,
    severity: "high" | "medium",
    title: string,
    detail: string,
    remediation: string,
    evidence: Reference[],
    importChain?: string[],
    confidence: "high" | "medium" = "high",
  ) => {
    findings.push({
      ruleId,
      area,
      severity,
      confidence,
      title,
      detail,
      remediation,
      evidence,
      ...(importChain ? { importChain } : {}),
    });
  };
  for (const module of modules.values()) {
    if (testFile(module.path)) continue;
    const client = clientPaths.has(module.path);
    if (isNext && client) {
      checked.add("NEXT001");
      for (const dependency of module.imports) {
        if (!dependency.resolved && serverDependency(dependency.specifier)) {
          add(
            "NEXT001",
            "module_boundaries",
            "high",
            "Server-only dependency in the client module graph",
            "A Client Component imports a module that depends on a server-only API or database driver.",
            "Move this dependency behind a server-only data-access module, Route Handler, or authenticated Server Action. Keep the interactive component's imports browser-compatible.",
            [dependency.reference],
            clientPaths.get(module.path),
          );
        }
      }
      checked.add("NEXT002");
      for (const variable of module.env) {
        if (
          !variable.name.startsWith("NEXT_PUBLIC_") &&
          variable.name !== "NODE_ENV"
        )
          add(
            "NEXT002",
            "data_access",
            "medium",
            "Server environment variable referenced in client code",
            "A client-reachable module reads an environment variable that Next.js does not normally expose to the browser. This does not establish that its value has leaked.",
            "Read private configuration on the server and pass only the public data the UI needs. Do not rename a secret with NEXT_PUBLIC_.",
            [variable.reference],
            clientPaths.get(module.path),
          );
      }
      checked.add("NEXT003");
      const defaultExport = module.exports.find(
        (e) => e.name === "default" && e.function && e.async,
      );
      if (defaultExport && containsJsx(module.source))
        add(
          "NEXT003",
          "routing_rendering",
          "high",
          "Async Client Component",
          "An async default component is part of the client module graph.",
          "Keep the async component on the server and move interactive controls into a synchronous Client Component.",
          [reference(module, defaultExport.node)],
          clientPaths.get(module.path),
        );
    }
    if (isNext && appFile(module.path)) {
      checked.add("NEXT004");
      for (const exported of module.exports) {
        if (
          module.client &&
          ["metadata", "generateMetadata"].includes(exported.name)
        )
          add(
            "NEXT004",
            "routing_rendering",
            "high",
            "Metadata exported from a Client Component",
            "App Router metadata exports belong in Server Components.",
            "Keep page or layout metadata in a server file and render a separate interactive Client Component beneath it.",
            [reference(module, exported.node)],
          );
        if (
          ["getServerSideProps", "getStaticProps", "getStaticPaths"].includes(
            exported.name,
          )
        )
          add(
            "NEXT005",
            "routing_rendering",
            "high",
            "Pages Router data API used in the App Router",
            "This App Router module exports a Pages Router-only data function.",
            "Use App Router server data fetching and generateStaticParams where appropriate, following the installed Next.js version's documentation.",
            [reference(module, exported.node)],
          );
      }
      checked.add("NEXT005");
      checked.add("NEXT006");
      if (
        /\/(?:error|global-error)\.[jt]sx?$/.test(module.path) &&
        !module.client
      )
        add(
          "NEXT006",
          "reliability",
          "high",
          "Error boundary lacks a client directive",
          "Next.js error boundaries must be Client Components.",
          "Add a use client directive to the error boundary and keep its dependencies browser-compatible.",
          [{ file: module.path, line: 1, column: 1 }],
        );
    }
    if (isNext && serverPaths.has(module.path)) {
      checked.add("NEXT007");
      for (const dependency of module.imports) {
        if (
          dependency.specifier === "client-only" ||
          (dependency.specifier === "react" &&
            dependency.symbols.some((name) => hookNames.has(name)))
        )
          add(
            "NEXT007",
            "module_boundaries",
            "high",
            "Client-only module used by a server entry point",
            "A module reachable from a Server Component imports client-only hooks or the client-only marker without a client boundary.",
            "Put interactive behavior behind a use client boundary. Keep server fetching and private data outside that module graph.",
            [dependency.reference],
          );
      }
    }
    if (isNext && module.server) {
      checked.add("NEXT008");
      for (const exported of module.exports) {
        const literal =
          ts.isVariableDeclaration(exported.node) &&
          exported.node.initializer &&
          [
            ts.SyntaxKind.StringLiteral,
            ts.SyntaxKind.NumericLiteral,
            ts.SyntaxKind.TrueKeyword,
            ts.SyntaxKind.FalseKeyword,
            ts.SyntaxKind.ObjectLiteralExpression,
            ts.SyntaxKind.ArrayLiteralExpression,
          ].includes(exported.node.initializer.kind);
        if ((exported.function && !exported.async) || literal)
          add(
            "NEXT008",
            "module_boundaries",
            "high",
            "Non-async value exported from a use server module",
            "A module-level use server directive makes its runtime exports Server Functions; a known export is not an async function.",
            "Keep constants and synchronous utilities in a separate module. Export only async Server Functions from this module.",
            [reference(module, exported.node)],
          );
      }
    }
    if (isNext && module.edge) {
      checked.add("NEXT009");
      const queue = [module.path];
      const visited = new Set<string>();
      while (queue.length) {
        const current = queue.shift()!;
        if (visited.has(current)) continue;
        visited.add(current);
        for (const dependency of modules.get(current)!.imports) {
          if (dependency.resolved) queue.push(dependency.resolved);
          else if (builtins.has(dependency.specifier.replace(/^node:/, "")))
            add(
              "NEXT009",
              "deployment_cost",
              "high",
              "Node.js API imported by an Edge runtime entry",
              "The entry explicitly selects the Edge runtime and imports a Node.js builtin through its dependency graph.",
              "Use the Node.js runtime or replace the dependency with an Edge-compatible implementation. Verify support against the target deployment platform.",
              [{ file: module.path, line: 1, column: 1 }, dependency.reference],
            );
        }
      }
    }
  }

  // Detect cycles without assuming that every legal JavaScript cycle is a defect.
  checked.add("MOD001");
  const visited = new Set<string>();
  const active = new Set<string>();
  const stack: string[] = [];
  const cycleKeys = new Set<string>();
  const walk = (path: string) => {
    if (visited.has(path)) return;
    visited.add(path);
    active.add(path);
    stack.push(path);
    for (const dependency of modules.get(path)!.imports) {
      if (
        !dependency.resolved ||
        (clientPaths.has(path) && modules.get(dependency.resolved)!.server)
      )
        continue;
      if (active.has(dependency.resolved)) {
        const cycle = [
          ...stack.slice(stack.indexOf(dependency.resolved)),
          dependency.resolved,
        ];
        const key = [...new Set(cycle)].sort().join("|");
        if (!cycleKeys.has(key)) {
          cycleKeys.add(key);
          add(
            "MOD001",
            "module_boundaries",
            "medium",
            "Circular module dependency needs review",
            "A runtime import cycle crosses the submitted modules. It may be intentional, but can make initialization and responsibility boundaries harder to reason about.",
            "Check the cycle's initialization behavior and ownership. Extract a shared contract or invert a dependency if the modules cannot be understood independently.",
            [dependency.reference],
            cycle,
            "medium",
          );
        }
      } else walk(dependency.resolved);
    }
    stack.pop();
    active.delete(path);
  };
  for (const path of modules.keys()) if (!testFile(path)) walk(path);

  const pending = unanswered(context);
  const evidenceGaps = [
    ...graph.unresolved.map((i) => ({
      kind: "missing_import",
      evidence: [i.reference],
      request: `Include the source for the unresolved local import ${i.specifier}.`,
    })),
    ...(!manifestFile
      ? [
          {
            kind: "framework_version",
            evidence: [],
            request:
              "Include package.json to establish the framework version and build/test scripts.",
          },
        ]
      : []),
    ...(!files.some((f) => testFile(f.path))
      ? [
          {
            kind: "tests_not_submitted",
            evidence: [],
            request:
              "Include tests for a critical flow, or describe the tests maintained in another repository.",
          },
        ]
      : []),
  ];
  const routeModules = [...modules.values()].filter(
    (m) => entryFile(m.path) || /^(?:src\/)?pages\//.test(m.path),
  );
  const mutationModules = [...modules.values()].filter(
    (m) =>
      m.server ||
      m.exports.some((e) =>
        ["POST", "PUT", "PATCH", "DELETE"].includes(e.name),
      ),
  );
  const dataModules = [...modules.values()].filter(
    (m) =>
      m.imports.some(
        (i) =>
          serverDependency(i.specifier) &&
          !["server-only", "next/headers", "next/server"].includes(i.specifier),
      ) || m.calls.some((c) => c.name === "fetch"),
  );
  const areaEvidence: Record<Area, Reference[]> = {
    purpose: [],
    routing_rendering: routeModules.map((m) => ({
      file: m.path,
      line: 1,
      column: 1,
    })),
    module_boundaries: [...modules.values()]
      .flatMap((m) => m.imports.map((i) => i.reference))
      .slice(0, 30),
    data_access: dataModules.map((m) => ({ file: m.path, line: 1, column: 1 })),
    authentication: mutationModules.map((m) => ({
      file: m.path,
      line: 1,
      column: 1,
    })),
    reliability: files
      .filter((f) => /(?:error|loading)\.[jt]sx?$/.test(f.path))
      .map((f) => ({ file: f.path, line: 1, column: 1 })),
    testing_delivery: files
      .filter((f) => testFile(f.path) || f.path.includes(".github/workflows/"))
      .map((f) => ({ file: f.path, line: 1, column: 1 })),
    deployment_cost: files
      .filter((f) =>
        /(?:next\.config\.|Dockerfile|railway\.toml|vercel\.json)/.test(f.path),
      )
      .map((f) => ({ file: f.path, line: 1, column: 1 })),
  };
  const assessments = areas.map((area) => {
    const areaFindings = findings.filter((f) => f.area === area);
    return {
      area,
      status: areaFindings.some(
        (f) => f.confidence === "high" && f.severity === "high",
      )
        ? "needs_changes"
        : "needs_contextual_review",
      evidence: areaEvidence[area],
      findingIds: [...new Set(areaFindings.map((f) => f.ruleId))],
      reviewTask: {
        purpose:
          "Trace the critical flows and judge the design against the product requirements.",
        routing_rendering:
          "Explain which routes render on the server or client and whether caching, SEO, and freshness match the requirements.",
        module_boundaries:
          "Check responsibility boundaries and coupling, including unresolved imports and shared contracts.",
        data_access:
          "Trace reads and writes through the API or data-access layer. Check ownership, validation, DTOs, transactions, and caching.",
        authentication:
          "Verify identity and object/tenant authorization at every protected read or mutation, including external backend services. Do not infer security from function names.",
        reliability:
          "Trace dependency failures and timeouts. Evaluate observability, recovery, and rollback against the stated targets.",
        testing_delivery:
          "Review test assertions for critical flows and inspect actual build/test outcomes. File presence is not a passing result.",
        deployment_cost:
          "Check runtime and hosting compatibility and compare complexity and cost against team and budget constraints.",
      }[area],
    };
  });
  findings.sort(
    (a, b) =>
      (a.severity === "high" ? 0 : 1) - (b.severity === "high" ? 0 : 1) ||
      a.evidence[0].file.localeCompare(b.evidence[0].file) ||
      a.evidence[0].line - b.evidence[0].line,
  );
  return {
    status: "reviewed",
    engineVersion: VERSION,
    reviewScope: "whole_application",
    verdict: findings.some(
      (f) => f.severity === "high" && f.confidence === "high",
    )
      ? "needs_changes"
      : pending.length || evidenceGaps.length
        ? "needs_more_evidence"
        : "ready_for_contextual_assessment",
    framework: {
      name: isNext ? "nextjs" : "javascript_typescript",
      declaredVersion: nextVersion,
      appRouter: [...modules.keys()].some(entryFile),
      pagesRouter: [...modules.keys()].some((path) =>
        /^(?:src\/)?pages\//.test(path),
      ),
    },
    filesReviewed: files.length,
    modulesParsed: modules.size,
    architecture: {
      routes: routeModules.map((m) => ({
        file: m.path,
        clientBoundary: m.client,
      })),
      clientEntries: [...modules.values()]
        .filter((m) => m.client)
        .map((m) => m.path),
      clientReachableModules: [...clientPaths.keys()],
      serverActionModules: [...modules.values()]
        .filter((m) => m.server)
        .map((m) => m.path),
      mutationEntryPoints: mutationModules.map((m) => m.path),
      dataAccessCandidates: dataModules.map((m) => m.path),
      importEdges: [...modules.values()].flatMap((m) =>
        m.imports
          .filter((i) => i.resolved)
          .map((i) => ({
            from: m.path,
            to: i.resolved,
            line: i.reference.line,
          })),
      ),
    },
    findings,
    assessments,
    rulesEvaluated: [...checked].sort(),
    evidenceGaps,
    nextQuestions: pending.slice(0, 3),
    remainingQuestions: pending.length,
    answeredTopics: Object.keys(context).filter(
      (key) => !!context[key as keyof ReviewContext],
    ),
    contextSource:
      "Answers supplied by the caller; not independently verified.",
    nextStep: pending.length
      ? "Ask the next questions, inspect requested evidence, and call this tool again with the updated context and relevant files."
      : "Use the evidence and area review tasks to assess end-to-end flows, compare tradeoffs, and produce a prioritized consultant report with file references.",
    instructions: consultationInstructions,
    limitations: [
      "This result combines static syntax/import checks with a contextual review agenda. The connected assistant supplies the architecture reasoning; no separate hosted model is invoked.",
      "Only submitted files are inspected. No repository, URL, dependency source, cloud account, build, or test is fetched or executed by this tool.",
      "Import resolution covers submitted relative modules and root tsconfig/jsconfig paths. Runtime module loading, bundler plugins, external packages, and inherited configs can leave gaps.",
      "Next.js-specific checks target App Router conventions. Pages Router and other frameworks require contextual review; framework-version-specific behavior must be checked against the project's installed documentation.",
      ...graph.warnings,
    ],
  };
}
