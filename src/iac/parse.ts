import hcl from "hcl2-parser";
import { LineCounter, parseAllDocuments } from "yaml";

export type IacFormat =
  | "terraform"
  | "cloudformation"
  | "kubernetes"
  | "pulumi"
  | "compose"
  | "dockerfile"
  | "github"
  | "helm"
  | "ansible"
  | "bicep"
  | "arm"
  | "gitlab"
  | "azure-pipelines"
  | "cloudbuild"
  | "tfvars";
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
    ) ||
    looksLikePulumiYaml(content) ||
    looksLikePulumiProgram(content) ||
    looksLikeCompose(content) ||
    looksLikeDockerfile(content) ||
    looksLikeGithubWorkflow(content) ||
    looksLikeHelm(content) ||
    looksLikeAnsible(content) ||
    looksLikeBicep(content) ||
    looksLikeArm(content) ||
    looksLikePipeline(content) !== undefined ||
    looksLikeTfvars(content)
  );
}

export function looksLikePulumiProgram(content: string): boolean {
  return /(?:^|\n)\s*(?:import\s+\*\s+as\s+pulumi\b|import\s+pulumi\b|from\s+["']@pulumi\/)/.test(
    content,
  );
}

export function looksLikeCompose(content: string): boolean {
  return /^\s*services\s*:/m.test(content) && /^\s+image\s*:/m.test(content);
}

export function looksLikeDockerfile(content: string): boolean {
  return /^\s*FROM\s+\S+/m.test(content);
}

function topLevelKey(content: string, name: string): boolean {
  return new RegExp(`^(?:"${name}"|'${name}'|${name})\\s*:`, "m").test(content);
}

function playbookShape(content: string): boolean {
  if (topLevelKey(content, "hosts") && topLevelKey(content, "tasks")) return true;
  return /^\s*-\s+hosts\s*:/m.test(content) && /^\s*tasks\s*:/m.test(content);
}

export function looksLikeAnsible(content: string): boolean {
  if (looksLikeGithubWorkflow(content)) return false;
  if (topLevelKey(content, "apiVersion") && topLevelKey(content, "kind"))
    return false;
  return playbookShape(content);
}

export function looksLikeHelm(content: string): boolean {
  if (looksLikeGithubWorkflow(content) || looksLikeAnsible(content)) return false;
  const visible = maskNonCode(content);
  if (!visible.includes("{{")) return false;
  return /^\s*(?:apiVersion|kind)\s*:/m.test(visible);
}

export function looksLikeGithubWorkflow(content: string): boolean {
  if (topLevelKey(content, "apiVersion") || topLevelKey(content, "kind"))
    return false;
  const topOn = topLevelKey(content, "on");
  const composeOnly =
    topLevelKey(content, "services") &&
    /^\s+image\s*:/m.test(content) &&
    !topOn;
  if (composeOnly) return false;
  return topOn && topLevelKey(content, "jobs");
}

export function looksLikeTerraformHcl(content: string): boolean {
  return /^\s*(?:(?:resource|module|variable|provider|data|output)\s+"|(?:terraform|locals)\s*\{)/m.test(
    content,
  );
}

export function looksLikeBicep(content: string): boolean {
  const visible = maskIaCComments(content);
  if (looksLikeTerraformHcl(visible)) return false;
  return /^\s*resource\s+[A-Za-z_][A-Za-z0-9_]*\s+['"]Microsoft\./m.test(visible);
}

export function looksLikeArm(content: string): boolean {
  const visible = maskIaCComments(content).trim();
  if (!visible.startsWith("{")) return false;
  let value: unknown;
  try {
    value = JSON.parse(visible);
  } catch {
    return false;
  }
  const root = object(value);
  if (typeof root.AWSTemplateFormatVersion === "string") return false;
  if (
    Object.values(object(root.Resources)).some((item) =>
      String(object(item).Type ?? "").startsWith("AWS::"),
    )
  )
    return false;
  if ("resource" in root && !Array.isArray(root.resources)) return false;
  if (
    "format_version" in root ||
    "planned_values" in root ||
    "resource_changes" in root
  )
    return false;
  if (
    typeof root.$schema === "string" &&
    root.$schema.includes("deploymentTemplate")
  )
    return true;
  if (typeof root.contentVersion !== "string" || !Array.isArray(root.resources))
    return false;
  return root.resources.some((item) =>
    String(object(item).type ?? "").startsWith("Microsoft."),
  );
}

export function looksLikePulumiYaml(content: string): boolean {
  return (
    /^\s*resources\s*:/m.test(content) &&
    /^\s+type\s*:\s*[A-Za-z0-9_.-]+:\S+/m.test(content)
  );
}

export function parseIac(
  content: string,
  requested: IacFormat | "auto" = "auto",
): ParsedIac {
  if (!content.trim())
    throw new ScanInputError("Content must not be empty or whitespace.");
  // Detect these before HCL or a failing YAML parse so a Dockerfile is not classified as Terraform.
  if (
    requested === "dockerfile" ||
    ((requested === "auto" || requested === "terraform") &&
      looksLikeDockerfile(content))
  ) {
    return parseDockerfile(content);
  }
  if (
    requested === "github" ||
    (requested === "auto" && looksLikeGithubWorkflow(content))
  ) {
    return parseGithubWorkflow(content);
  }
  if (
    requested === "ansible" ||
    (requested === "auto" && looksLikeAnsible(content))
  ) {
    return parseAnsible(content);
  }
  if (
    requested === "helm" ||
    (requested === "auto" && looksLikeHelm(content))
  ) {
    return parseHelm(content);
  }
  const pipeline =
    requested === "gitlab" ||
    requested === "azure-pipelines" ||
    requested === "cloudbuild"
      ? requested
      : requested === "auto"
        ? looksLikePipeline(content)
        : undefined;
  if (pipeline) {
    if (!pipelineMatches(content, pipeline))
      throw new ScanInputError(pipelineShapeError(pipeline));
    return parsePipeline(content, pipeline);
  }
  if (requested === "tfvars") return parseTfvars(content);
  if (requested === "bicep" || (requested === "auto" && looksLikeBicep(content))) {
    if (!looksLikeBicep(content))
      throw new ScanInputError(
        "A Bicep file requires a Microsoft resource declaration.",
      );
    return parseAzure(content, "bicep");
  }
  if (requested === "arm" || (requested === "auto" && looksLikeArm(content))) {
    if (!looksLikeArm(content))
      throw new ScanInputError(
        "An ARM template requires a deploymentTemplate schema or contentVersion with Microsoft resources.",
      );
    return parseAzure(content, "arm");
  }
  if (
    requested !== "terraform" &&
    requested !== "compose" &&
    looksLikePulumiProgram(content) &&
    !looksLikePulumiYaml(content)
  ) {
    return parsePulumiProgram(content);
  }
  const warnings: string[] = [];
  const resources: Resource[] = [];
  const isHcl =
    (requested === "terraform" && !content.trimStart().startsWith("{")) ||
    (requested === "auto" && looksLikeTerraformHcl(content));
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
    for (const [name, blocks] of Object.entries(object(object(data).module))) {
      const declaration = new RegExp(
        `\\bmodule\\s+"${escapeRegex(name)}"`,
      ).exec(searchable);
      const offset = declaration?.index ?? 0;
      const before = content.slice(0, offset);
      resources.push({
        id: `module.${name}`,
        type: "terraform:module",
        value: object(array(blocks)[0]),
        locate: (path = []) => ({
          line: before.split("\n").length,
          column: offset - before.lastIndexOf("\n"),
          path: ["module", name, ...path].join("."),
        }),
      });
    }
    for (const [name, blocks] of Object.entries(object(object(data).variable))) {
      const body = object(array(blocks)[0]);
      if (!("default" in body)) continue;
      const declaration = new RegExp(
        `\\bvariable\\s+"${escapeRegex(name)}"`,
      ).exec(searchable);
      const offset = declaration?.index ?? 0;
      const before = content.slice(0, offset);
      resources.push({
        id: `variable.${name}`,
        type: "terraform:variable",
        value: { name, default: body.default },
        locate: (path = []) => ({
          line: before.split("\n").length,
          column: offset - before.lastIndexOf("\n"),
          path: ["variable", name, ...path].join("."),
        }),
      });
    }
    if (object(data).module)
      warnings.push(
        "External modules are not expanded. The module body was not loaded, and the module source is not fetched or evaluated.",
      );
    if (JSON.stringify(data).includes("${"))
      warnings.push(
        "Terraform expressions are not evaluated. Findings use literal values and declared settings.",
      );
    if (!resources.some((item) => item.type !== "terraform:module" && item.type !== "terraform:variable"))
      warnings.push(
        "No resource declarations found. Data sources and outputs are not scanned as resources.",
      );
    return { format: "terraform", resources, warnings };
  }

  if (requested === "auto" && looksLikeTfvars(content)) return parseTfvars(content);

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
    const pulumiResources = pulumiResourceMap(root);
    const services = composeServiceMap(root);
    let detected: IacFormat | undefined;
    if (requested === "pulumi" || (requested === "auto" && pulumiResources)) {
      if (!pulumiResources)
        throw new ScanInputError(
          "Pulumi YAML requires a resources mapping. Each resource needs a type token.",
        );
      detected = "pulumi";
    } else if (requested === "compose" || (requested === "auto" && services)) {
      if (!services)
        throw new ScanInputError(
          "Docker Compose requires a services mapping with an image, build, or ports field.",
        );
      detected = "compose";
    } else {
      detected = root.Resources
        ? "cloudformation"
        : root.apiVersion && root.kind
          ? "kubernetes"
          : root.resource
            ? "terraform"
            : undefined;
    }
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
    if (format === "compose") {
      for (const [name, raw] of Object.entries(services ?? {}))
        add(name, "compose:service", raw, ["services", name]);
    } else if (format === "pulumi") {
      for (const [name, raw] of Object.entries(pulumiResources ?? {})) {
        const value = object(raw);
        add(name, String(value.type), value, ["resources", name]);
      }
    } else if (format === "cloudformation") {
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
      "No IaC document found. Choose Terraform, CloudFormation, Kubernetes, Pulumi, Docker Compose, a Dockerfile, a GitHub Actions workflow, a Helm template, an Ansible playbook, Bicep, or an ARM template.",
    );
  if (!resources.length)
    warnings.push("No resources found in the submitted document.");
  if (/(?:!(?:Ref|Sub|GetAtt|If)\b|"(?:Ref|Fn::\w+)"\s*:|\$\{)/.test(content))
    warnings.push(
      "Intrinsic functions and expressions are not evaluated. Only literal configuration is checked.",
    );
  return { format, resources, warnings };
}

function programLocation(content: string, offset: number, path: string) {
  const before = content.slice(0, offset);
  return {
    line: before.split("\n").length,
    column: offset - before.lastIndexOf("\n"),
    path,
  };
}

function stripProgramComments(content: string): string {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, (match) => match.replace(/[^\n]/g, " "))
    .replace(/(^|[^:])\/\/[^\n]*/g, (match) => match.replace(/[^\n]/g, " "))
    .replace(/(^|\n)\s*#[^\n]*/g, (match) => match.replace(/[^\n]/g, " "));
}

function parsePulumiProgram(content: string): ParsedIac {
  const searchable = stripProgramComments(content);
  const resources: Resource[] = [];
  const addProgram = (
    id: string,
    type: string,
    value: Record<string, unknown>,
    offset: number,
    path: string,
  ) => {
    resources.push({
      id,
      type,
      value,
      locate: () => programLocation(content, offset, path),
    });
  };
  for (const match of searchable.matchAll(/(?:0\.0\.0\.0\/0|::\/0)/g)) {
    const offset = match.index ?? 0;
    const window = searchable.slice(Math.max(0, offset - 1500), offset);
    const ingressAt = window.toLowerCase().lastIndexOf("ingress");
    const egressAt = window.toLowerCase().lastIndexOf("egress");
    if (ingressAt < 0 || egressAt > ingressAt) continue;
    addProgram(
      `pulumi.program.ingress.${resources.length + 1}`,
      "pulumi:program/securityGroup:SecurityGroup",
      { properties: { ingress: [{ cidrBlocks: [match[0]] }] } },
      offset,
      "ingress.cidrBlocks",
    );
  }
  const database: Record<string, unknown> = {};
  const publicDb = /publicly_?accessible\s*[:=]\s*true\b/i.exec(searchable);
  const unencrypted = /storage_?encrypted\s*[:=]\s*false\b/i.exec(searchable);
  const noBackup = /backup_?retention_?period\s*[:=]\s*0\b/i.exec(searchable);
  if (publicDb) database.publicly_accessible = true;
  if (unencrypted) database.storage_encrypted = false;
  if (noBackup) database.backup_retention_period = 0;
  const databaseMatch = publicDb ?? unencrypted ?? noBackup;
  if (databaseMatch) {
    addProgram(
      "pulumi.program.database",
      "aws_db_instance",
      { properties: database },
      databaseMatch.index,
      "database",
    );
  }
  const publicAcl =
    /(?:acl|accessControl)\s*[:=]\s*["']public-read(?:-write)?["']/i.exec(
      searchable,
    );
  if (publicAcl) {
    addProgram(
      "pulumi.program.bucket",
      "aws_s3_bucket",
      { properties: { acl: "public-read" } },
      publicAcl.index,
      "acl",
    );
  }
  for (const match of searchable.matchAll(
    /actions?\s*[:=]\s*(?:\[\s*)?["']\*["']/gi,
  )) {
    const offset = match.index ?? 0;
    const before = searchable.slice(Math.max(0, offset - 300), offset);
    const effects = [
      ...before.matchAll(/(?:effect|Effect)\s*[:=]\s*["']?(Allow|Deny)["']?/gi),
    ];
    const nearest = effects.at(-1)?.[1] ?? "";
    if (!/^allow$/i.test(nearest)) continue;
    addProgram(
      "pulumi.program.policy",
      "pulumi:program/iam:Policy",
      { properties: { effect: "Allow", actions: ["*"] } },
      offset,
      "actions",
    );
    break;
  }
  addProgram(
    "pulumi.program.source",
    "pulumi:program/source:Source",
    { program: searchable },
    0,
    "program",
  );
  return {
    format: "pulumi",
    resources,
    warnings: [
      "Pulumi programs are scanned as text. Computed values, stacks, and external modules are not evaluated.",
      "Database, storage, IAM, credential, and network checks use literal settings in the submitted program.",
    ],
  };
}

const submittedTextWarning =
  "The scan reads the submitted text and does not execute the image or the workflow.";

function logicalDockerfileLines(content: string): { line: number; text: string }[] {
  const raw = content.split(/\r?\n/);
  const lines: { line: number; text: string }[] = [];
  let buffer = "";
  let start = 1;
  for (let index = 0; index < raw.length; index++) {
    const current = raw[index].replace(/\s+$/, "");
    if (!buffer) start = index + 1;
    if (current.endsWith("\\")) {
      buffer += `${current.slice(0, -1)} `;
      continue;
    }
    buffer += current;
    const text = buffer.trim();
    buffer = "";
    if (!text || text.startsWith("#")) continue;
    lines.push({ line: start, text });
  }
  return lines;
}

function parseFromInstruction(
  text: string,
): { image: string; stage?: string } | undefined {
  if (!/^FROM\b/i.test(text)) return undefined;
  const parts = text.split(/\s+/);
  let index = 1;
  while (index < parts.length && parts[index].startsWith("--")) {
    if (!parts[index].includes("=")) index += 1;
    index += 1;
  }
  const image = parts[index];
  if (!image) return undefined;
  const stage = /^as$/i.test(parts[index + 1] ?? "")
    ? parts[index + 2]
    : undefined;
  return stage ? { image, stage } : { image };
}

function imageIsUnpinned(image: string, stages: Set<string>): boolean {
  if (
    image.includes("${") ||
    image.includes("@") ||
    stages.has(image) ||
    stages.has(image.toLowerCase()) ||
    image.toLowerCase() === "scratch"
  )
    return false;
  const slash = image.lastIndexOf("/");
  const colon = image.lastIndexOf(":");
  if (colon <= slash) return true;
  return image.slice(colon + 1) === "latest";
}

function parseUserName(text: string): string | undefined {
  if (!/^USER\b/i.test(text)) return undefined;
  const parts = text
    .split(/\s+/)
    .slice(1)
    .filter((part) => part && !part.startsWith("--"));
  const raw = parts[0];
  if (!raw) return undefined;
  return raw.replace(/^["']|["']$/g, "").split(":")[0];
}

function runPipesToShell(text: string): boolean {
  return (
    /^RUN\b/i.test(text) &&
    /\b(?:curl|wget)\b/i.test(text) &&
    /\|\s*(?:sudo\s+)?(?:\S*\/)?(?:ba)?sh\b/i.test(text)
  );
}

function copySources(text: string): string[] | undefined {
  if (!/^(?:COPY|ADD)\b/i.test(text)) return undefined;
  const rest = text.replace(/^(?:COPY|ADD)\b/i, "").trim();
  if (rest.startsWith("[")) {
    try {
      const parsed = JSON.parse(rest);
      if (!Array.isArray(parsed) || parsed.length < 2) return [];
      return parsed.slice(0, -1).map((item) => String(item));
    } catch {
      return [];
    }
  }
  const tokens: string[] = [];
  for (const match of rest.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)) {
    const token = match[1] ?? match[2] ?? match[3];
    if (token.startsWith("--")) continue;
    tokens.push(token);
  }
  if (tokens.length < 2) return [];
  return tokens.slice(0, -1);
}

function sourceIsSecret(source: string): boolean {
  const path = source.replace(/\\/g, "/").replace(/\/+$/, "");
  const base = path.split("/").filter(Boolean).at(-1) ?? path;
  if (base === ".env" || base === "id_rsa" || base === "id_ed25519") return true;
  if (base.endsWith(".pem")) return true;
  return base === "credentials";
}

function secretVariableName(name: string): boolean {
  const normalized = name.replace(/-/g, "_");
  return (
    /(?:^|_)(?:password|passwd|secret|token)$/i.test(normalized) ||
    /(?:^|_)(?:api_?key|auth_token|access_key|private_key)$/i.test(normalized)
  );
}

function isShellReference(value: string): boolean {
  return (
    /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(value) ||
    /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(value)
  );
}

function parseImageAssignments(
  kind: "ENV" | "ARG",
  rest: string,
): { name: string; value: string }[] {
  const trimmed = rest.trim();
  if (!trimmed) return [];
  if (kind === "ARG" && /^[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed))
    return [{ name: trimmed, value: "" }];
  if (!trimmed.includes("=")) {
    const spaced = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s+([\s\S]*)$/);
    if (!spaced) return [];
    return [{ name: spaced[1], value: unquoteAssignment(spaced[2].trim()) }];
  }
  const pairs: { name: string; value: string }[] = [];
  const pattern =
    /([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^\s]*))/g;
  for (const match of trimmed.matchAll(pattern)) {
    pairs.push({
      name: match[1],
      value: match[2] ?? match[3] ?? match[4] ?? "",
    });
  }
  return pairs;
}

function unquoteAssignment(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
    (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
  )
    return value.slice(1, -1);
  return value;
}

function workflowEnvIsLiteral(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (/^\$\{\{\s*secrets\.[^}]+\}\}$/i.test(trimmed)) return false;
  if (/^\$\{\{\s*github\.token\s*\}\}$/i.test(trimmed)) return false;
  return true;
}

function lineLocation(line: number, path: string): Location {
  return { line, column: 1, path };
}

type PipelineFormat = "gitlab" | "azure-pipelines" | "cloudbuild";

function stolenPipelineInput(content: string): boolean {
  return (
    looksLikeGithubWorkflow(content) ||
    looksLikeAnsible(content) ||
    looksLikeHelm(content) ||
    (topLevelKey(content, "apiVersion") && topLevelKey(content, "kind"))
  );
}

function azurePipelineShape(content: string): boolean {
  const poolOrTrigger =
    topLevelKey(content, "pool") || topLevelKey(content, "trigger");
  const stepsOrStages =
    topLevelKey(content, "steps") || topLevelKey(content, "stages");
  return poolOrTrigger && stepsOrStages;
}

function gitlabShape(content: string): boolean {
  if (!/\bimage\s*:/.test(content)) return false;
  if (topLevelKey(content, "stages")) return true;
  return /^\s*script\s*:/m.test(content);
}

function cloudBuildShape(content: string): boolean {
  if (!topLevelKey(content, "steps")) return false;
  if (topLevelKey(content, "on") && topLevelKey(content, "jobs")) return false;
  return /^\s*-\s*name\s*:/m.test(content);
}

function looksLikePipeline(content: string): PipelineFormat | undefined {
  if (stolenPipelineInput(content)) return undefined;
  const visible = maskIaCComments(content);
  if (azurePipelineShape(visible)) return "azure-pipelines";
  if (gitlabShape(visible)) return "gitlab";
  if (cloudBuildShape(visible)) return "cloudbuild";
  return undefined;
}

function pipelineMatches(content: string, format: PipelineFormat): boolean {
  if (stolenPipelineInput(content)) return false;
  const visible = maskIaCComments(content);
  if (format === "azure-pipelines") return azurePipelineShape(visible);
  if (format === "gitlab") return gitlabShape(visible);
  return cloudBuildShape(visible);
}

function pipelineShapeError(format: PipelineFormat): string {
  if (format === "gitlab")
    return "GitLab CI requires top-level stages or a job with script, and an image.";
  if (format === "azure-pipelines")
    return "Azure Pipelines requires a top-level pool or trigger, plus steps or stages.";
  return "Cloud Build requires top-level steps whose items have a name.";
}

const pipelineWarning =
  "The pipeline is not executed. Only literal text outside comments is checked.";

function scriptText(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.every((item) => typeof item === "string"))
    return value.join("\n");
  return undefined;
}

function pipelineScriptKey(key: string): boolean {
  return (
    key === "script" ||
    key === "before_script" ||
    key === "after_script" ||
    key === "bash" ||
    key === "pwsh" ||
    key === "powershell"
  );
}

function pipelinePrintsSecret(script: string): boolean {
  return script.split(/\n/).some((line) => {
    const code = line.replace(/(^|\s)#.*$/, "").trim();
    if (!/\b(?:echo|printf|print)\b/i.test(code)) return false;
    return /CI_JOB_TOKEN|secrets\.|\$\(secret|(?:^|[^A-Za-z0-9_])(?:password|passwd|api_key|apikey|auth_token|access_key|private_key|token)(?:[^A-Za-z0-9_]|$)/i.test(
      code,
    );
  });
}

type PipelineHit = {
  kind: "image" | "script" | "privileged";
  path: Path;
  image?: string;
  script?: string;
};

function collectPipelineHits(
  value: unknown,
  path: Path,
  format: PipelineFormat,
  hits: PipelineHit[],
): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      collectPipelineHits(item, [...path, index], format, hits),
    );
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(object(value))) {
    const childPath = [...path, key];
    if ((key === "image" || key === "container") && typeof child === "string")
      hits.push({ kind: "image", path: childPath, image: child });
    else if (
      key === "image" &&
      typeof object(child).name === "string"
    )
      hits.push({
        kind: "image",
        path: [...childPath, "name"],
        image: String(object(child).name),
      });
    if (key === "privileged" && child === true)
      hits.push({ kind: "privileged", path: childPath });
    const script = pipelineScriptKey(key) ? scriptText(child) : undefined;
    if (script) hits.push({ kind: "script", path: childPath, script });
    if (format === "cloudbuild" && key === "steps" && Array.isArray(child)) {
      child.forEach((step, index) => {
        const name = object(step).name;
        if (typeof name === "string")
          hits.push({
            kind: "image",
            path: [...childPath, index, "name"],
            image: name,
          });
        const args = scriptText(object(step).args);
        if (args)
          hits.push({
            kind: "script",
            path: [...childPath, index, "args"],
            script: args,
          });
      });
    }
    collectPipelineHits(child, childPath, format, hits);
  }
}

function parsePipeline(content: string, format: PipelineFormat): ParsedIac {
  const lines = new LineCounter();
  let documents;
  try {
    documents = parseAllDocuments(content, {
      lineCounter: lines,
      prettyErrors: false,
    });
  } catch {
    throw new ScanInputError(pipelineShapeError(format));
  }
  const resources: Resource[] = [];
  let found = false;
  for (const [documentIndex, doc] of documents.entries()) {
    if (doc.errors.length) throw new ScanInputError(pipelineShapeError(format));
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
    found = true;
    const hits: PipelineHit[] = [];
    collectPipelineHits(data, [], format, hits);
    const position = (path: Path) => {
      let node = doc.getIn(path, true) as { range?: number[] } | undefined;
      if (!node?.range)
        node = doc.getIn([], true) as { range?: number[] } | undefined;
      const at = lines.linePos(node?.range?.[0] ?? doc.range?.[0] ?? 0);
      return {
        line: at.line,
        column: at.col,
        path: [documentIndex, ...path].join("."),
      };
    };
    hits.forEach((hit, index) => {
      if (hit.kind === "image" && hit.image)
        resources.push({
          id: `pipeline.image.${index + 1}`,
          type: "pipeline:image",
          value: { unpinned: imageIsUnpinned(hit.image.trim(), new Set()) },
          locate: () => position(hit.path),
        });
      else if (hit.kind === "script" && hit.script)
        resources.push({
          id: `pipeline.script.${index + 1}`,
          type: "pipeline:script",
          value: { printsSecret: pipelinePrintsSecret(hit.script) },
          locate: () => position(hit.path),
        });
      else if (hit.kind === "privileged")
        resources.push({
          id: `pipeline.privileged.${index + 1}`,
          type: "pipeline:privileged",
          value: { present: true },
          locate: () => position(hit.path),
        });
    });
  }
  if (!found) throw new ScanInputError(pipelineShapeError(format));
  return { format, resources, warnings: [pipelineWarning] };
}

function looksLikeTfvars(content: string): boolean {
  const visible = maskIaCComments(content);
  if (/^\s*(?:resource|module|provider)\s+["']/m.test(visible)) return false;
  if (/^\s*(?:terraform|provider|module)\s*\{/m.test(visible)) return false;
  return /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S/m.test(visible);
}

function parseTfvars(content: string): ParsedIac {
  let data: unknown;
  try {
    const [parsed, error] = hcl.parseToObject(content);
    if (error || !parsed) throw new Error("parse");
    data = parsed;
  } catch {
    throw new ScanInputError("Invalid tfvars. Check assignment syntax.");
  }
  checkShape(data);
  const searchable = maskIaCComments(content);
  const resources: Resource[] = [];
  const skipped = new Set([
    "resource",
    "module",
    "terraform",
    "provider",
    "variable",
    "data",
    "output",
    "locals",
  ]);
  for (const [name, value] of Object.entries(object(data))) {
    if (skipped.has(name)) continue;
    const declaration = new RegExp(
      `(^|\\n)\\s*${escapeRegex(name)}\\s*=`,
    ).exec(searchable);
    const offset = declaration?.index ?? 0;
    const before = content.slice(0, offset);
    resources.push({
      id: `tfvars.${name}`,
      type: "tfvars:assignment",
      value: { name, value },
      locate: (path = []) => ({
        line: before.split("\n").length,
        column: 1,
        path: ["tfvars", name, ...path].join("."),
      }),
    });
  }
  return {
    format: "tfvars",
    resources,
    warnings: [
      "Terraform variable references are not evaluated. Findings use literal values.",
    ],
  };
}

function parseDockerfile(content: string): ParsedIac {
  const instructions = logicalDockerfileLines(content);
  const froms = instructions.flatMap((instruction) => {
    const parsed = parseFromInstruction(instruction.text);
    return parsed ? [{ ...instruction, ...parsed }] : [];
  });
  if (!froms.length)
    throw new ScanInputError("A Dockerfile requires a FROM instruction.");
  const stages = new Set<string>();
  const resources: Resource[] = [];
  froms.forEach((from, index) => {
    resources.push({
      id: `dockerfile.from.${index + 1}`,
      type: "dockerfile:from",
      value: { image: from.image, unpinned: imageIsUnpinned(from.image, stages) },
      locate: () => lineLocation(from.line, "image"),
    });
    if (from.stage) {
      stages.add(from.stage);
      stages.add(from.stage.toLowerCase());
    }
  });
  let lastUser: { line: number; name: string } | undefined;
  for (const instruction of instructions) {
    const name = parseUserName(instruction.text);
    if (name !== undefined) lastUser = { line: instruction.line, name };
  }
  const root =
    !lastUser || lastUser.name.toLowerCase() === "root" || lastUser.name === "0";
  resources.push({
    id: "dockerfile.user",
    type: "dockerfile:user",
    value: { user: lastUser?.name ?? "", root },
    locate: () => lineLocation(lastUser?.line ?? froms[0].line, "user"),
  });
  instructions.forEach((instruction, index) => {
    if (!/^RUN\b/i.test(instruction.text)) return;
    resources.push({
      id: `dockerfile.run.${index + 1}`,
      type: "dockerfile:run",
      value: { piped: runPipesToShell(instruction.text) },
      locate: () => lineLocation(instruction.line, "run"),
    });
  });
  instructions.forEach((instruction, index) => {
    const sources = copySources(instruction.text);
    if (!sources) return;
    resources.push({
      id: `dockerfile.copy.${index + 1}`,
      type: "dockerfile:copy",
      value: { secret: sources.some(sourceIsSecret) },
      locate: () => lineLocation(instruction.line, "copy"),
    });
  });
  instructions.forEach((instruction, index) => {
    const header = instruction.text.match(/^(ENV|ARG)\b\s*([\s\S]*)$/i);
    if (!header) return;
    const kind = header[1].toUpperCase() === "ARG" ? "ARG" : "ENV";
    const assignments = parseImageAssignments(kind, header[2] ?? "");
    const literal = assignments.some(
      (item) =>
        secretVariableName(item.name) &&
        item.value.trim() !== "" &&
        !isShellReference(item.value.trim()),
    );
    resources.push({
      id: `dockerfile.env.${index + 1}`,
      type: "dockerfile:env",
      value: { literal },
      locate: () => lineLocation(instruction.line, "env"),
    });
  });
  return {
    format: "dockerfile",
    resources,
    warnings: [submittedTextWarning],
  };
}

function triggersPullRequestTarget(value: unknown): boolean {
  if (value === "pull_request_target") return true;
  if (Array.isArray(value))
    return value.some((item) => item === "pull_request_target");
  return Object.prototype.hasOwnProperty.call(object(value), "pull_request_target");
}

function workflowChecksOutHead(jobs: unknown): boolean {
  for (const job of Object.values(object(jobs))) {
    for (const step of array(object(job).steps)) {
      const inputs = object(object(step).with);
      const text = [inputs.ref, inputs.sha]
        .filter((item) => typeof item === "string")
        .join("\n");
      if (text.includes("github.event.pull_request.head")) return true;
    }
  }
  return false;
}

function runPrintsSecret(script: string): boolean {
  const logical = script.replace(/\\\r?\n\s*/g, " ");
  return logical.split(/\n/).some((line) => {
    const code = line.replace(/(^|\s)#[^\n]*$/, "");
    return (
      /\b(?:echo|printf|print)\b/i.test(code) &&
      /\$\{\{\s*secrets\./.test(code)
    );
  });
}

function permissionsAreBroad(
  top: unknown,
  jobs: unknown,
  pullRequestTarget: boolean,
): boolean {
  const values = [
    top,
    ...Object.values(object(jobs)).map((job) => object(job).permissions),
  ];
  if (values.some((value) => value === "write-all")) return true;
  if (!pullRequestTarget) return false;
  return values.some((value) => object(value).contents === "write");
}

function parseGithubWorkflow(content: string): ParsedIac {
  const lines = new LineCounter();
  let documents;
  try {
    documents = parseAllDocuments(content, {
      lineCounter: lines,
      prettyErrors: false,
    });
  } catch {
    throw new ScanInputError("Invalid GitHub Actions workflow YAML.");
  }
  const resources: Resource[] = [];
  let found = false;
  for (const [documentIndex, doc] of documents.entries()) {
    if (doc.errors.length)
      throw new ScanInputError("Invalid GitHub Actions workflow YAML.");
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
    if (!("on" in root) || !("jobs" in root)) continue;
    found = true;
    const pullRequestTarget = triggersPullRequestTarget(root.on);
    const checksOutHead = workflowChecksOutHead(root.jobs);
    const broad = permissionsAreBroad(
      root.permissions,
      root.jobs,
      pullRequestTarget,
    );
    const position = (path: Path) => {
      let node = doc.getIn(path, true) as { range?: number[] } | undefined;
      if (!node?.range)
        node = doc.getIn(["on"], true) as { range?: number[] } | undefined;
      const at = lines.linePos(node?.range?.[0] ?? doc.range?.[0] ?? 0);
      return {
        line: at.line,
        column: at.col,
        path: [documentIndex, ...path].join("."),
      };
    };
    resources.push({
      id: "workflow.on",
      type: "github:trigger",
      value: { pullRequestTarget, checksOutHead },
      locate: () => position(["on"]),
    });
    resources.push({
      id: "workflow.permissions",
      type: "github:permissions",
      value: { broad },
      locate: () =>
        position(root.permissions != null ? ["permissions"] : ["on"]),
    });
    const addEnv = (envValue: unknown, path: Path) => {
      for (const [key, raw] of Object.entries(object(envValue))) {
        if (typeof raw !== "string" && raw != null) continue;
        if (!secretVariableName(key)) continue;
        const value = typeof raw === "string" ? raw : "";
        resources.push({
          id: `env.${[...path, key].join(".")}`,
          type: "github:env",
          value: { literal: workflowEnvIsLiteral(value) },
          locate: () => position([...path, key]),
        });
      }
    };
    addEnv(root.env, ["env"]);
    for (const [jobName, job] of Object.entries(object(root.jobs))) {
      addEnv(object(job).env, ["jobs", jobName, "env"]);
      array(object(job).steps).forEach((step, index) => {
        addEnv(object(step).env, ["jobs", jobName, "steps", index, "env"]);
      });
      array(object(job).steps).forEach((step, index) => {
        const uses = object(step).uses;
        if (typeof uses !== "string") return;
        const ref = uses.includes("@")
          ? uses.slice(uses.lastIndexOf("@") + 1)
          : "";
        resources.push({
          id: `jobs.${jobName}.steps.${index}`,
          type: "github:action",
          value: { uses, floating: ref === "main" || ref === "master" },
          locate: () => position(["jobs", jobName, "steps", index, "uses"]),
        });
      });
      array(object(job).steps).forEach((step, index) => {
        const run = object(step).run;
        if (typeof run !== "string") return;
        resources.push({
          id: `jobs.${jobName}.steps.${index}.run`,
          type: "github:run",
          value: { printsSecret: runPrintsSecret(run) },
          locate: () => position(["jobs", jobName, "steps", index, "run"]),
        });
      });
    }
  }
  if (!found)
    throw new ScanInputError(
      "A GitHub Actions workflow requires top-level on and jobs keys.",
    );
  return {
    format: "github",
    resources,
    warnings: [submittedTextWarning],
  };
}

function composeServiceMap(
  root: Record<string, unknown>,
): Record<string, unknown> | undefined {
  if (root.apiVersion || root.kind || root.Resources || root.resources)
    return undefined;
  const services = object(root.services);
  const entries = Object.entries(services);
  if (
    entries.length > 0 &&
    entries.every(([, raw]) => {
      const service = object(raw);
      return (
        "image" in service ||
        "build" in service ||
        "ports" in service ||
        "privileged" in service
      );
    })
  )
    return services;
  return undefined;
}

function pulumiResourceMap(
  root: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const resources = object(root.resources);
  const entries = Object.entries(resources);
  if (
    entries.length > 0 &&
    entries.every(([, raw]) => {
      const type = object(raw).type;
      return typeof type === "string" && type.includes(":");
    })
  )
    return resources;
  return undefined;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function maskNonCode(content: string): string {
  const withoutBlockComments = content
    .replace(/\{\{-?\s*\/\*[\s\S]*?\*\/\s*-?\}\}/g, (match) =>
      match.replace(/[^\n]/g, " "),
    )
    .replace(/\{#[\s\S]*?#\}/g, (match) => match.replace(/[^\n]/g, " "));
  return withoutBlockComments
    .split("\n")
    .map((line) => {
      let out = "";
      let templates = 0;
      let quote: string | undefined;
      for (let index = 0; index < line.length; index++) {
        const char = line[index];
        const next = line[index + 1];
        if (quote) {
          out += char;
          if (char === quote && line[index - 1] !== "\\") quote = undefined;
          continue;
        }
        if (templates === 0 && (char === '"' || char === "'")) {
          quote = char;
          out += char;
          continue;
        }
        if (char === "{" && next === "{") {
          templates += 1;
          out += char;
          continue;
        }
        if (char === "}" && next === "}" && templates > 0) {
          templates -= 1;
          out += char;
          continue;
        }
        if (templates === 0 && char === "#") {
          return out + " ".repeat(line.length - out.length);
        }
        out += char;
      }
      return out;
    })
    .join("\n");
}

function lineAt(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function firstLiteral(
  content: string,
  pattern: RegExp,
): { present: boolean; line: number } {
  const match = pattern.exec(content);
  if (!match || match.index === undefined) return { present: false, line: 1 };
  return { present: true, line: lineAt(content, match.index) };
}

function literalResource(
  id: string,
  type: string,
  match: { present: boolean; line: number },
  path: string,
): Resource {
  return {
    id,
    type,
    value: { present: match.present },
    locate: () => lineLocation(match.line, path),
  };
}

const helmTemplateWarning =
  "Helm templates are not executed. Only literal text outside comments is checked.";

const ansibleFactsWarning =
  "Ansible facts are not executed. Only literal text outside comments is checked.";

function parseHelm(content: string): ParsedIac {
  const visible = maskNonCode(content);
  const privileged = firstLiteral(visible, /privileged\s*:\s*["']?true["']?\b/);
  const hostNetwork = firstLiteral(visible, /hostNetwork\s*:\s*["']?true["']?\b/);
  const latest = firstLiteral(visible, /:latest\b/);
  const socket = firstLiteral(visible, /(?:hostPath|volumes?)\b[\s\S]{0,500}docker\.sock|docker\.sock[\s\S]{0,200}\b(?:hostPath|volumes?)\b/);
  return {
    format: "helm",
    resources: [
      literalResource("helm.privileged", "helm:privileged", privileged, "privileged"),
      literalResource("helm.hostNetwork", "helm:hostNetwork", hostNetwork, "hostNetwork"),
      literalResource("helm.image", "helm:image", latest, "image"),
      literalResource("helm.socket", "helm:socket", socket, "volume"),
    ],
    warnings: [helmTemplateWarning],
  };
}

function parseAnsible(content: string): ParsedIac {
  const visible = maskNonCode(content);
  const become = firstLiteral(
    visible,
    /(?:^|\n)\s*(?:-\s+)?become\s*:\s*["']?(?:true|yes)["']?(?=\s|$)/,
  );
  const cidr = firstLiteral(
    visible,
    /(?:cidr|source)\s*:\s*(?:\|\s*)?(?:\n\s*-\s*)?["']?0\.0\.0\.0\/0\b/,
  );
  return {
    format: "ansible",
    resources: [
      literalResource("ansible.become", "ansible:become", become, "become"),
      literalResource("ansible.cidr", "ansible:cidr", cidr, "cidr"),
    ],
    warnings: [ansibleFactsWarning],
  };
}

function maskIaCComments(content: string): string {
  const withoutBlock = content.replace(/\/\*[\s\S]*?\*\//g, (match) =>
    match.replace(/[^\n]/g, " "),
  );
  return withoutBlock
    .split("\n")
    .map((line) => {
      let out = "";
      let quote: string | undefined;
      for (let index = 0; index < line.length; index++) {
        const char = line[index];
        const next = line[index + 1];
        if (quote) {
          out += char;
          if (char === "\\" && quote === '"') {
            if (next) out += next;
            index += 1;
            continue;
          }
          if (char === quote) quote = undefined;
          continue;
        }
        if (char === '"' || char === "'") {
          quote = char;
          out += char;
          continue;
        }
        if (
          (char === "/" && next === "/") ||
          char === "#"
        ) {
          return out + " ".repeat(line.length - out.length);
        }
        out += char;
      }
      return out;
    })
    .join("\n");
}

function addressValueIsOpen(after: string): boolean {
  return /(?:^|[\s\[,])(?:"\*"|"0\.0\.0\.0\/0"|'\*'|'0\.0\.0\.0\/0'|\*|0\.0\.0\.0\/0)(?=$|[\s,\]}"'])/.test(
    after,
  );
}

function nearestScopeIsEgress(content: string, index: number): boolean {
  const windowStart = Math.max(0, index - 800);
  const windowEnd = Math.min(content.length, index + 400);
  const slice = content.slice(windowStart, windowEnd);
  const relative = index - windowStart;
  let nearest: { distance: number; egress: boolean } | undefined;
  for (const match of slice.matchAll(/\b(Inbound|Outbound|ingress|egress)\b/gi)) {
    const at = match.index ?? 0;
    const distance = Math.abs(at - relative);
    const egress = /^(?:outbound|egress)$/i.test(match[1] ?? "");
    if (!nearest || distance < nearest.distance) nearest = { distance, egress };
  }
  return nearest?.egress ?? false;
}

function firstOpenAddress(content: string): { present: boolean; line: number } {
  const pattern = /(source|destination)AddressPrefix(es)?["']?\s*[:=]/gi;
  for (const match of content.matchAll(pattern)) {
    const kind = (match[1] ?? "").toLowerCase();
    const index = match.index ?? 0;
    const after = content.slice(index + match[0].length, index + match[0].length + 240);
    if (!addressValueIsOpen(after)) continue;
    if (kind === "destination" && nearestScopeIsEgress(content, index)) continue;
    return { present: true, line: lineAt(content, index) };
  }
  return { present: false, line: 1 };
}

function enclosingAzureType(content: string, index: number): string {
  const before = content.slice(Math.max(0, index - 4000), index);
  const declarations = [
    ...before.matchAll(
      /resource\s+[A-Za-z_][\w]*\s+['"](Microsoft\.[^'"]+)['"]|(?:["']type["']|type)\s*:\s*["'](Microsoft\.[^"']+)["']/g,
    ),
  ];
  const last = declarations.at(-1);
  return last?.[1] ?? last?.[2] ?? "";
}

function firstPublicNetwork(content: string): { present: boolean; line: number } {
  const pattern =
    /publicNetworkAccess["']?\s*[:=]\s*(["']?)(Enabled|true|Disabled|false)\1(?![\w.-])/gi;
  for (const match of content.matchAll(pattern)) {
    if (!/^(?:enabled|true)$/i.test(match[2] ?? "")) continue;
    const index = match.index ?? 0;
    const type = enclosingAzureType(content, index);
    if (!/(?:database|storage|server)/i.test(type)) continue;
    return { present: true, line: lineAt(content, index) };
  }
  return { present: false, line: 1 };
}

const azureExpressionWarning =
  "Bicep modules and ARM expressions are not evaluated.";

function parseAzure(content: string, format: "bicep" | "arm"): ParsedIac {
  const visible = maskIaCComments(content);
  return {
    format,
    resources: [
      literalResource(
        "azure.exposure",
        "azure:exposure",
        firstOpenAddress(visible),
        "sourceAddressPrefix",
      ),
      literalResource(
        "azure.publicNetwork",
        "azure:publicNetwork",
        firstPublicNetwork(visible),
        "publicNetworkAccess",
      ),
    ],
    warnings: [azureExpressionWarning],
  };
}
