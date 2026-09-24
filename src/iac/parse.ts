import hcl from "hcl2-parser";
import { LineCounter, parseAllDocuments } from "yaml";

export type IacFormat = "terraform" | "cloudformation" | "kubernetes";
export type Path = (string | number)[];
export type Location = { line: number; column: number; path: string };
export type Resource = {
  id: string;
  type: string;
  value: Record<string, unknown>;
  locate: (path?: Path) => Location;
};
export type ParsedIac = {
  format: IacFormat;
  resources: Resource[];
  warnings: string[];
};

export class ScanInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanInputError";
  }
}

export function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value == null ? [] : [value];
}

// Reject deeply nested documents before rule traversal. Never return source text in errors.
function checkShape(
  value: unknown,
  depth = 0,
  budget = { remaining: 50_000 },
): void {
  if (depth > 80 || --budget.remaining < 0) {
    throw new ScanInputError(
      "Document exceeds the nesting or node limit. Split it into smaller inputs.",
    );
  }
  if (value && typeof value === "object") {
    for (const child of Object.values(value))
      checkShape(child, depth + 1, budget);
  }
}

export function looksLikeIac(content: string): boolean {
  if (content.trimStart().startsWith("{")) {
    try {
      const value = object(JSON.parse(content));
      if (value.resource || value.Resources || (value.apiVersion && value.kind))
        return true;
    } catch {
      /* Other format detection still applies to incomplete input. */
    }
  }
  return (
    /^\s*(?:resource|module|terraform|variable|provider)\s+["{]/m.test(
      content,
    ) ||
    /^\s*(?:["']?Resources["']?\s*:|apiVersion\s*:)/m.test(content) ||
    /^\s*\{\s*"(?:resource|Resources|apiVersion|AWSTemplateFormatVersion)"\s*:/.test(
      content,
    )
  );
}

export function parseIac(
  content: string,
  requested: IacFormat | "auto" = "auto",
): ParsedIac {
  if (!content.trim())
    throw new ScanInputError("Content must not be empty or whitespace.");
  const warnings: string[] = [];
  const resources: Resource[] = [];
  const isHcl =
    (requested === "terraform" && !content.trimStart().startsWith("{")) ||
    (requested === "auto" &&
      /^\s*(?:(?:resource|module|variable|provider|data|output)\s+"|(?:terraform|locals)\s*\{)/m.test(
        content,
      ));
  if (isHcl) {
    let data: unknown;
    try {
      const [parsed, error] = hcl.parseToObject(content);
      if (error || !parsed) throw new Error("parse");
      data = parsed;
    } catch {
      throw new ScanInputError(
        "Invalid Terraform HCL. Check block syntax and attribute separators.",
      );
    }
    checkShape(data);
    // The HCL parser preserves expressions but does not expose source ranges.
    // Report the resource declaration line and the exact parsed property path.
    const searchable = content.replace(
      /\/\*[\s\S]*?\*\/|(?:#|\/\/)[^\n]*/g,
      (match) => match.replace(/[^\n]/g, " "),
    );
    for (const [type, instances] of Object.entries(
      object(object(data).resource),
    )) {
      for (const [name, blocks] of Object.entries(object(instances))) {
        const declaration = new RegExp(
          `\\bresource\\s+"${escapeRegex(type)}"\\s+"${escapeRegex(name)}"`,
        ).exec(searchable);
        const offset = declaration?.index ?? 0;
        const before = content.slice(0, offset);
        resources.push({
          id: `${type}.${name}`,
          type,
          value: object(array(blocks)[0]),
          locate: (path = []) => ({
            line: before.split("\n").length,
            column: offset - before.lastIndexOf("\n"),
            path: ["resource", type, name, ...path].join("."),
          }),
        });
      }
    }
    if (object(data).module)
      warnings.push(
        "External Terraform modules are not expanded. Scan their source separately.",
      );
    if (JSON.stringify(data).includes("${"))
      warnings.push(
        "Terraform expressions are not evaluated. Findings use literal values and declared settings.",
      );
    if (!resources.length)
      warnings.push(
        "No resource declarations found. Variables, data sources, and outputs are not scanned as resources.",
      );
    return { format: "terraform", resources, warnings };
  }

  const lines = new LineCounter();
  const tags = [
    "Ref",
    "Sub",
    "GetAtt",
    "Join",
    "Select",
    "Split",
    "If",
    "Equals",
    "Not",
    "And",
    "Or",
    "FindInMap",
    "ImportValue",
    "GetAZs",
    "Base64",
    "Cidr",
    "Transform",
    "Length",
    "ToJsonString",
  ];
  let documents;
  try {
    documents = parseAllDocuments(content, {
      lineCounter: lines,
      prettyErrors: false,
      customTags: tags.flatMap((name) =>
        (["scalar", "seq", "map"] as const).map((kind) => ({
          tag: `!${name}`,
          ...(kind === "scalar" ? {} : { collection: kind }),
          resolve: () => ({ __intrinsic: name }),
        })),
      ),
    });
  } catch {
    throw new ScanInputError("Invalid YAML or JSON document.");
  }
  let format: IacFormat | undefined =
    requested === "auto" ? undefined : requested;
  for (const [documentIndex, doc] of documents.entries()) {
    if (doc.errors.length || doc.warnings.length) {
      const issue = doc.errors[0] ?? doc.warnings[0];
      const line = lines.linePos(issue.pos[0]).line;
      throw new ScanInputError(
        `Invalid or unsupported YAML/JSON syntax at line ${line}.`,
      );
    }
    let data: unknown;
    try {
      data = doc.toJS({ maxAliasCount: 0 });
    } catch {
      throw new ScanInputError(
        "YAML aliases are not supported. Expand anchors before scanning.",
      );
    }
    if (data == null) continue;
    checkShape(data);
    const root = object(data);
    const detected = root.Resources
      ? "cloudformation"
      : root.apiVersion && root.kind
        ? "kubernetes"
        : root.resource
          ? "terraform"
          : undefined;
    format ??= detected;
    if (!format || (detected && detected !== format))
      throw new ScanInputError(
        "Input format is unsupported or mixed. Submit one IaC format per scan.",
      );
    const add = (id: string, type: string, value: unknown, prefix: Path) => {
      resources.push({
        id,
        type,
        value: object(value),
        locate: (path = []) => {
          let node = doc.getIn([...prefix, ...path], true) as
            { range?: number[] } | undefined;
          if (!node?.range)
            node = doc.getIn(prefix, true) as { range?: number[] } | undefined;
          const position = lines.linePos(
            node?.range?.[0] ?? doc.range?.[0] ?? 0,
          );
          return {
            line: position.line,
            column: position.col,
            path: [documentIndex, ...prefix, ...path].join("."),
          };
        },
      });
    };
    if (format === "cloudformation") {
      if (
        !root.Resources ||
        Array.isArray(root.Resources) ||
        typeof root.Resources !== "object"
      )
        throw new ScanInputError(
          "CloudFormation requires a Resources mapping.",
        );
      for (const [name, raw] of Object.entries(object(root.Resources))) {
        const value = object(raw);
        if (typeof value.Type !== "string")
          throw new ScanInputError(
            "Each CloudFormation resource requires a Type.",
          );
        add(name, value.Type, value, ["Resources", name]);
      }
    } else if (format === "terraform") {
      if (
        !root.resource ||
        Array.isArray(root.resource) ||
        typeof root.resource !== "object"
      )
        throw new ScanInputError("Terraform JSON requires a resource mapping.");
      for (const [type, instances] of Object.entries(object(root.resource))) {
        for (const [name, value] of Object.entries(object(instances)))
          add(`${type}.${name}`, type, value, ["resource", type, name]);
      }
    } else {
      const manifests = root.kind === "List" ? array(root.items) : [root];
      for (const [index, raw] of manifests.entries()) {
        const value = object(raw);
        if (
          typeof value.apiVersion !== "string" ||
          typeof value.kind !== "string"
        )
          throw new ScanInputError(
            "Each Kubernetes manifest requires apiVersion and kind.",
          );
        if (
          [
            "Pod",
            "Deployment",
            "StatefulSet",
            "DaemonSet",
            "ReplicaSet",
            "ReplicationController",
            "Job",
            "CronJob",
          ].includes(value.kind)
        ) {
          let spec = object(value.spec);
          if (value.kind === "CronJob")
            spec = object(object(spec.jobTemplate).spec);
          if (value.kind !== "Pod") spec = object(object(spec.template).spec);
          if (
            !Array.isArray(spec.containers) ||
            !spec.containers.length ||
            spec.containers.some(
              (c) =>
                typeof object(c).name !== "string" ||
                typeof object(c).image !== "string",
            )
          ) {
            throw new ScanInputError(
              "Kubernetes workloads require a containers list with a name and image for each container.",
            );
          }
        }
        const metadata = object(value.metadata);
        add(
          `${value.kind}/${metadata.namespace ?? "default"}/${metadata.name ?? metadata.generateName ?? "unnamed"}`,
          value.kind,
          value,
          root.kind === "List" ? ["items", index] : [],
        );
      }
    }
  }
  if (!format)
    throw new ScanInputError(
      "No IaC document found. Choose Terraform, CloudFormation, or Kubernetes.",
    );
  if (!resources.length)
    warnings.push("No resources found in the submitted document.");
  if (/(?:!(?:Ref|Sub|GetAtt|If)\b|"(?:Ref|Fn::\w+)"\s*:|\$\{)/.test(content))
    warnings.push(
      "Intrinsic functions and expressions are not evaluated. Only literal configuration is checked.",
    );
  return { format, resources, warnings };
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
