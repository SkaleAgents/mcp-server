import ts from "typescript";
import { posix } from "node:path";
import { ScanInputError } from "../iac/parse.js";
import type { SourceFile } from "./intake.js";

export type Reference = { file: string; line: number; column: number };
export type Import = {
  specifier: string;
  reference: Reference;
  resolved?: string;
  symbols: string[];
};
export type Module = {
  path: string;
  source: ts.SourceFile;
  imports: Import[];
  client: boolean;
  server: boolean;
  serverOnly: boolean;
  exports: { name: string; node: ts.Node; async: boolean; function: boolean }[];
  env: { name: string; reference: Reference }[];
  calls: { name: string; reference: Reference; literal?: string }[];
  edge: boolean;
};

export function reference(module: Module, node: ts.Node): Reference {
  const point = module.source.getLineAndCharacterOfPosition(
    node.getStart(module.source),
  );
  return {
    file: module.path,
    line: point.line + 1,
    column: point.character + 1,
  };
}

function modifiers(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return (
    ts.canHaveModifiers(node) &&
    !!ts.getModifiers(node)?.some((modifier) => modifier.kind === kind)
  );
}

export function parseModule(file: SourceFile): Module {
  const source = ts.createSourceFile(
    file.path,
    file.content,
    ts.ScriptTarget.Latest,
    true,
  );
  const diagnostics = (
    source as ts.SourceFile & { parseDiagnostics: ts.Diagnostic[] }
  ).parseDiagnostics;
  if (diagnostics.length) {
    const line =
      source.getLineAndCharacterOfPosition(diagnostics[0].start ?? 0).line + 1;
    throw new ScanInputError(
      `Cannot parse ${file.path} at line ${line}. Submit valid JavaScript or TypeScript.`,
    );
  }
  const directives: string[] = [];
  for (const statement of source.statements) {
    if (
      !ts.isExpressionStatement(statement) ||
      !ts.isStringLiteral(statement.expression)
    )
      break;
    directives.push(statement.expression.text);
  }
  const module: Module = {
    path: file.path,
    source,
    imports: [],
    client: directives.includes("use client"),
    server: directives.includes("use server"),
    serverOnly: false,
    exports: [],
    env: [],
    calls: [],
    edge: false,
  };
  const addImport = (
    specifier: string,
    node: ts.Node,
    symbols: string[] = [],
  ) =>
    module.imports.push({
      specifier,
      reference: reference(module, node),
      symbols,
    });
  const visit = (node: ts.Node) => {
    if (
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      const clause = node.importClause;
      const bindings = clause?.namedBindings;
      const named =
        bindings && ts.isNamedImports(bindings)
          ? bindings.elements.filter((e) => !e.isTypeOnly)
          : [];
      if (
        !clause?.isTypeOnly &&
        (!clause ||
          clause.name ||
          (bindings && ts.isNamespaceImport(bindings)) ||
          named.length)
      ) {
        addImport(
          node.moduleSpecifier.text,
          node,
          named.map((e) => (e.propertyName ?? e.name).text),
        );
      }
    }
    if (
      ts.isExportDeclaration(node) &&
      !node.isTypeOnly &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      const elements =
        node.exportClause && ts.isNamedExports(node.exportClause)
          ? node.exportClause.elements
          : undefined;
      if (!elements || elements.some((e) => !e.isTypeOnly))
        addImport(node.moduleSpecifier.text, node);
    }
    if (ts.isCallExpression(node)) {
      const name = ts.isIdentifier(node.expression)
        ? node.expression.text
        : node.expression.kind === ts.SyntaxKind.ImportKeyword
          ? "import"
          : "";
      const first = node.arguments[0];
      const literal =
        first && ts.isStringLiteralLike(first) ? first.text : undefined;
      if (name)
        module.calls.push({
          name,
          reference: reference(module, node),
          ...(literal !== undefined ? { literal } : {}),
        });
      if ((name === "import" || name === "require") && literal)
        addImport(literal, node);
    }
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === "process" &&
      node.expression.name.text === "env"
    ) {
      module.env.push({
        name: node.name.text,
        reference: reference(module, node),
      });
    }
    if (
      ts.isElementAccessExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === "process" &&
      node.expression.name.text === "env" &&
      ts.isStringLiteralLike(node.argumentExpression)
    ) {
      module.env.push({
        name: node.argumentExpression.text,
        reference: reference(module, node),
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  const addExport = (
    name: string,
    node: ts.Node,
    value: ts.Node | undefined,
  ) => {
    const fn =
      !!value &&
      (ts.isFunctionDeclaration(value) ||
        ts.isArrowFunction(value) ||
        ts.isFunctionExpression(value));
    module.exports.push({
      name,
      node,
      async: fn && modifiers(value!, ts.SyntaxKind.AsyncKeyword),
      function: fn,
    });
  };
  for (const statement of source.statements) {
    if (
      ts.isFunctionDeclaration(statement) &&
      modifiers(statement, ts.SyntaxKind.ExportKeyword)
    )
      addExport(
        modifiers(statement, ts.SyntaxKind.DefaultKeyword)
          ? "default"
          : (statement.name?.text ?? "default"),
        statement,
        statement,
      );
    if (
      ts.isVariableStatement(statement) &&
      modifiers(statement, ts.SyntaxKind.ExportKeyword)
    ) {
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        addExport(declaration.name.text, declaration, declaration.initializer);
        if (
          declaration.name.text === "runtime" &&
          declaration.initializer &&
          ts.isStringLiteral(declaration.initializer) &&
          declaration.initializer.text === "edge"
        )
          module.edge = true;
      }
    }
    if (ts.isExportAssignment(statement)) {
      let value: ts.Node | undefined = statement.expression;
      if (ts.isIdentifier(value)) {
        const name = value.text;
        value =
          source.statements.find(
            (s) => ts.isFunctionDeclaration(s) && s.name?.text === name,
          ) ??
          source.statements
            .flatMap((s) =>
              ts.isVariableStatement(s)
                ? [...s.declarationList.declarations]
                : [],
            )
            .find((d) => ts.isIdentifier(d.name) && d.name.text === name)
            ?.initializer;
      }
      addExport("default", statement, value);
    }
  }
  module.serverOnly = module.imports.some((i) => i.specifier === "server-only");
  return module;
}

export function buildGraph(files: SourceFile[]) {
  const modules = new Map(
    files
      .filter(
        (f) => /\.[cm]?[jt]sx?$/.test(f.path) && !/\.d\.[cm]?ts$/.test(f.path),
      )
      .map((file) => [file.path, parseModule(file)]),
  );
  const warnings: string[] = [];
  const configFile =
    files.find((f) => f.path === "tsconfig.json") ??
    files.find((f) => f.path === "jsconfig.json");
  let baseUrl = ".";
  let aliases: Record<string, string[]> = {};
  if (configFile) {
    const parsed = ts.parseConfigFileTextToJson(
      configFile.path,
      configFile.content,
    );
    if (parsed.error)
      throw new ScanInputError(`Cannot parse ${configFile.path}.`);
    const config = parsed.config;
    if (config?.extends)
      warnings.push(
        "Extended TypeScript configurations are not loaded. Include effective baseUrl and paths for complete alias resolution.",
      );
    if (typeof config?.compilerOptions?.baseUrl === "string")
      baseUrl = config.compilerOptions.baseUrl;
    if (
      config?.compilerOptions?.paths &&
      typeof config.compilerOptions.paths === "object"
    )
      aliases = config.compilerOptions.paths;
  }
  const candidates = (stem: string) => {
    const normalized = posix.normalize(stem);
    const extensionless = normalized.replace(/\.[cm]?jsx?$/, "");
    return [
      ...new Set([
        normalized,
        ...[extensionless, normalized].flatMap((base) =>
          [
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".mts",
            ".mjs",
            ".cts",
            ".cjs",
            "/index.ts",
            "/index.tsx",
            "/index.js",
            "/index.jsx",
          ].map((extension) => base + extension),
        ),
      ]),
    ];
  };
  const unresolved: Import[] = [];
  for (const module of modules.values()) {
    for (const dependency of module.imports) {
      const name = dependency.specifier;
      if (
        /\.(?:css|scss|sass|less|svg|png|jpg|jpeg|webp|gif|woff2?|json)$/.test(
          name,
        )
      )
        continue;
      let stems: string[] = [];
      let local = name.startsWith(".");
      if (local) stems = [posix.join(posix.dirname(module.path), name)];
      else {
        for (const [alias, targets] of Object.entries(aliases)) {
          if (!Array.isArray(targets)) continue;
          const [before, after = ""] = alias.split("*");
          const matches = alias.includes("*")
            ? name.startsWith(before) && name.endsWith(after)
            : name === alias;
          if (!matches) continue;
          local = true;
          const wildcard = name.slice(
            before.length,
            after.length ? -after.length : undefined,
          );
          stems.push(
            ...targets
              .filter((t) => typeof t === "string")
              .map((target) =>
                posix.join(baseUrl, target.replace("*", wildcard)),
              ),
          );
        }
        if (!stems.length && baseUrl !== ".")
          stems.push(posix.join(baseUrl, name));
      }
      dependency.resolved = stems
        .flatMap(candidates)
        .find((candidate) => modules.has(candidate));
      if (
        !dependency.resolved &&
        (local || name.startsWith("@/") || name.startsWith("~/"))
      )
        unresolved.push(dependency);
    }
  }
  const clientPaths = new Map<string, string[]>();
  const queue = [...modules.values()]
    .filter((m) => m.client)
    .map((m) => [m.path]);
  while (queue.length) {
    const path = queue.shift()!;
    const last = path.at(-1)!;
    if (clientPaths.has(last)) continue;
    clientPaths.set(last, path);
    for (const dependency of modules.get(last)!.imports) {
      if (
        dependency.resolved &&
        !modules.get(dependency.resolved)!.server &&
        !clientPaths.has(dependency.resolved)
      )
        queue.push([...path, dependency.resolved]);
    }
  }
  return { modules, clientPaths, unresolved, warnings };
}
