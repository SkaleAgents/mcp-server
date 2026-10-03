import hcl from "hcl2-parser";
import { LineCounter, parseAllDocuments } from "yaml";

export type IacFormat =
  | "terraform"
  | "cloudformation"
  | "kubernetes"
  | "pulumi"
  | "compose"
  | "dockerfile"
  | "github";
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
    looksLikeGithubWorkflow(content)
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
      "No IaC document found. Choose Terraform, CloudFormation, Kubernetes, Pulumi, Docker Compose, a Dockerfile, or a GitHub Actions workflow.",
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

function lineLocation(line: number, path: string): Location {
  return { line, column: 1, path };
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
    for (const [jobName, job] of Object.entries(object(root.jobs))) {
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
