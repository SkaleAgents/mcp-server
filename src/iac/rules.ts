import { array, object, terraformJsonencodeValue, type Path, type Resource } from "./parse.js";
import type { Finding, FindingSeverity } from "../review.js";
import { externalHttp, literalCredential } from "../review.js";

type Category = "security" | "reliability" | "cost";
type Rule = {
  category: Category;
  severity: FindingSeverity;
  title: string;
  detail: string;
  remediation: string;
};

export const rules: Record<string, Rule> = {
  SEC001: {
    category: "security",
    severity: "high",
    title: "Hardcoded credential-like value",
    detail: "A credential property contains a literal value.",
    remediation:
      "Move the value to a secret manager or runtime secret reference. Rotate any credential that has been exposed.",
  },
  SEC002: {
    category: "security",
    severity: "critical",
    title: "Possible AWS access key",
    detail: "A value matches an AWS access-key identifier pattern.",
    remediation:
      "Remove the key from source, rotate the credential, and check repository history.",
  },
  SEC003: {
    category: "security",
    severity: "critical",
    title: "Private key material in source",
    detail: "A value contains a private-key block.",
    remediation:
      "Revoke or rotate the key and load its replacement from a secret store.",
  },
  NET002: {
    category: "security",
    severity: "medium",
    title: "Unencrypted HTTP endpoint",
    detail: "A configured URL uses HTTP outside loopback.",
    remediation:
      "Use HTTPS for service traffic and keep certificate verification enabled.",
  },
  NET001: {
    category: "security",
    severity: "high",
    title: "Broad network exposure",
    detail: "An ingress rule allows every IPv4 or IPv6 source.",
    remediation:
      "Restrict ingress to approved CIDRs or source security groups. Keep intentional public web traffic behind an authenticated edge.",
  },
  IAM001: {
    category: "security",
    severity: "high",
    title: "Wildcard permission detected",
    detail: "An Allow statement grants a wildcard action.",
    remediation:
      "List the required actions explicitly, with resource and condition restrictions.",
  },
  IAM002: {
    category: "security",
    severity: "high",
    title: "Policy allows any principal",
    detail: "An Allow statement sets Principal to any AWS principal.",
    remediation:
      "Name the trusted principals explicitly instead of allowing any principal.",
  },
  DATA001: {
    category: "security",
    severity: "high",
    title: "Public data access",
    detail: "The storage configuration permits public access.",
    remediation:
      "Remove public ACLs and policies. Enable all public-access blocks unless this is an intentional public asset bucket.",
  },
  DATA002: {
    category: "security",
    severity: "high",
    title: "Storage encryption disabled",
    detail: "Encryption at rest is explicitly disabled.",
    remediation:
      "Enable encryption with a managed or customer-managed key and plan migration of existing unencrypted data.",
  },
  DATA003: {
    category: "reliability",
    severity: "medium",
    title: "Object versioning not enabled",
    detail:
      "This bucket has no enabled versioning configuration in the submitted input.",
    remediation:
      "Enable bucket versioning to recover overwritten or deleted objects. Configure lifecycle retention for older versions.",
  },
  DB001: {
    category: "security",
    severity: "high",
    title: "Database publicly accessible",
    detail: "The database enables public network access.",
    remediation:
      "Disable public accessibility and connect through private subnets and restricted security groups.",
  },
  DB002: {
    category: "reliability",
    severity: "high",
    title: "Database backups disabled",
    detail: "Automated database backup retention is set to zero.",
    remediation:
      "Set a nonzero retention period and test restoration against recovery objectives.",
  },
  DB003: {
    category: "reliability",
    severity: "medium",
    title: "Database deletion protection disabled",
    detail: "Deletion protection is explicitly disabled.",
    remediation:
      "Enable deletion protection for persistent databases and require a reviewed decommissioning process.",
  },
  DB004: {
    category: "reliability",
    severity: "medium",
    title: "Database lacks multi-zone failover",
    detail: "Multi-zone availability is explicitly disabled.",
    remediation:
      "Enable multi-zone failover for workloads that require continued service during a zone failure.",
  },
  VM001: {
    category: "security",
    severity: "high",
    title: "Instance metadata tokens not required",
    detail: "This EC2 instance does not explicitly require IMDSv2 tokens.",
    remediation:
      "Set metadata_options.http_tokens or MetadataOptions.HttpTokens to required. Verify the account-level metadata defaults too.",
  },
  COST001: {
    category: "cost",
    severity: "info",
    title: "Compute sizing needs review",
    detail: "The resource declares a compute size.",
    remediation:
      "Compare CPU and memory utilization with the chosen size before changing capacity or purchasing commitments.",
  },
  K8S001: {
    category: "security",
    severity: "critical",
    title: "Elevated container privileges",
    detail: "A container enables privileged mode or privilege escalation.",
    remediation:
      "Set privileged and allowPrivilegeEscalation to false. Isolate workloads that genuinely require elevated privileges.",
  },
  K8S002: {
    category: "security",
    severity: "high",
    title: "Host namespace access",
    detail: "The workload shares a host network, process, or IPC namespace.",
    remediation:
      "Disable hostNetwork, hostPID, and hostIPC unless required by a reviewed node-level component.",
  },
  K8S003: {
    category: "security",
    severity: "high",
    title: "Host filesystem mounted",
    detail: "A volume mounts a host path into the workload.",
    remediation:
      "Use a PersistentVolumeClaim or a scoped ephemeral volume instead of hostPath.",
  },
  K8S004: {
    category: "security",
    severity: "medium",
    title: "Non-root execution not enforced",
    detail:
      "Neither the container nor pod enforces runAsNonRoot, or the container selects UID 0.",
    remediation:
      "Set runAsNonRoot to true and use a nonzero UID supported by the image.",
  },
  K8S005: {
    category: "security",
    severity: "medium",
    title: "Writable container root filesystem",
    detail: "The container does not enforce a read-only root filesystem.",
    remediation:
      "Set readOnlyRootFilesystem to true and mount writable volumes only where needed.",
  },
  K8S006: {
    category: "security",
    severity: "high",
    title: "Dangerous Linux capabilities",
    detail: "The container adds ALL, SYS_ADMIN, NET_ADMIN, or SYS_PTRACE.",
    remediation:
      "Drop ALL capabilities and add back only those required by the process.",
  },
  K8S007: {
    category: "reliability",
    severity: "medium",
    title: "Unpinned container image",
    detail: "The image has no version tag or uses latest.",
    remediation:
      "Pin an immutable digest or a release tag with an immutability policy.",
  },
  K8S008: {
    category: "reliability",
    severity: "medium",
    title: "Container resource bounds missing",
    detail: "CPU or memory requests, or the memory limit, are missing.",
    remediation:
      "Set measured CPU and memory requests and a memory limit. Review throttling before adding CPU limits.",
  },
  K8S009: {
    category: "reliability",
    severity: "medium",
    title: "Readiness probe missing",
    detail: "A serving container has no readiness probe.",
    remediation:
      "Add a readiness probe that confirms the process can accept traffic.",
  },
  K8S010: {
    category: "reliability",
    severity: "medium",
    title: "Liveness probe missing",
    detail: "A long-running container has no liveness probe.",
    remediation:
      "Add a liveness probe and, for slow startup, a startup probe. Avoid restarting on dependency outages.",
  },
  K8S011: {
    category: "reliability",
    severity: "medium",
    title: "Single workload replica",
    detail:
      "The workload requests fewer than two replicas and no matching autoscaler was submitted.",
    remediation:
      "Use at least two replicas for availability-sensitive services and spread them across nodes or zones.",
  },
  K8S012: {
    category: "security",
    severity: "high",
    title: "Secret stored in manifest",
    detail:
      "A Secret manifest contains inline data. Base64 encoding does not protect credentials.",
    remediation:
      "Load secret values from an external secret store and keep plaintext and base64-encoded credentials out of source control.",
  },
  K8S013: {
    category: "security",
    severity: "high",
    title: "Wildcard Kubernetes RBAC",
    detail: "A role grants wildcard verbs, resources, or API groups.",
    remediation:
      "Scope the role to the required API groups, resource names, and verbs.",
  },
  DF001: {
    category: "security",
    severity: "high",
    title: "Dockerfile runs as root",
    detail:
      "The last USER is root or 0, or the Dockerfile has no USER instruction.",
    remediation:
      "Add a final USER instruction for a non-root account that the image supports.",
  },
  DF002: {
    category: "security",
    severity: "medium",
    title: "Unpinned container image",
    detail: "A FROM image uses the latest tag, or it has no tag and no digest.",
    remediation:
      "Pin a release tag or an image digest. Scratch and named stages are not image pins.",
  },
  DF003: {
    category: "security",
    severity: "high",
    title: "Remote script piped to a shell",
    detail:
      "A RUN instruction downloads a script with curl or wget and pipes it to sh or bash.",
    remediation:
      "Download the script, review it, and pin a checksum before running it. Do not pipe a remote script to a shell.",
  },
  GH001: {
    category: "security",
    severity: "critical",
    title: "Pull request target checks out PR code",
    detail:
      "The workflow triggers on pull_request_target and checks out the pull request head ref or head sha.",
    remediation:
      "Avoid checking out pull request head code from pull_request_target. Use pull_request for untrusted code, or check out the base repository only.",
  },
  GH002: {
    category: "security",
    severity: "high",
    title: "Workflow permissions are broad",
    detail:
      "permissions is write-all, or a pull_request_target workflow sets contents to write.",
    remediation:
      "Set the narrowest permissions the workflow needs. Keep contents read-only on pull_request_target.",
  },
  GH003: {
    category: "security",
    severity: "medium",
    title: "Action ref is a floating branch",
    detail: "A uses value is pinned to @main or @master.",
    remediation: "Pin the action to a release tag or a full commit SHA.",
  },
  DF004: {
    category: "security",
    severity: "high",
    title: "Secret file copied into the image",
    detail:
      "A COPY or ADD instruction uses a secret file as a source.",
    remediation:
      "Keep secret files out of the image. Mount them at runtime from a secret store.",
  },
  GH004: {
    category: "security",
    severity: "high",
    title: "Workflow prints a secret",
    detail: "A run script echoes or prints a secrets expression.",
    remediation:
      "Remove the printed secret from the script. Pass secrets through an environment variable that the step does not print.",
  },
  DF005: {
    category: "security",
    severity: "high",
    title: "Secret assigned in an image variable",
    detail:
      "A Dockerfile ENV or ARG assigns a non-empty literal to a secret-like name.",
    remediation:
      "Pass the value at runtime or from a secret mount. Do not bake a literal secret into ENV or ARG.",
  },
  GH005: {
    category: "security",
    severity: "high",
    title: "Secret assigned in workflow env",
    detail:
      "A workflow env mapping assigns a non-empty literal to a secret-like name.",
    remediation:
      "Reference secrets or github.token in the env value. Do not commit a literal secret.",
  },
  AZ001: {
    category: "security",
    severity: "high",
    title: "Broad network exposure",
    detail:
      "A source address prefix allows every address, or a destination prefix is open outside an egress scope.",
    remediation:
      "Restrict source address prefixes to approved ranges. Keep open destination prefixes on egress rules only.",
  },
  AZ002: {
    category: "security",
    severity: "high",
    title: "Database or storage allows public network access",
    detail:
      "publicNetworkAccess is Enabled or true on a database, storage, or server resource.",
    remediation:
      "Set publicNetworkAccess to Disabled and reach the resource through a private endpoint.",
  },
  HELM001: {
    category: "security",
    severity: "critical",
    title: "Privileged container in a Helm template",
    detail: "The template sets privileged to true.",
    remediation:
      "Set privileged to false. Isolate workloads that genuinely require elevated privileges.",
  },
  HELM002: {
    category: "security",
    severity: "high",
    title: "Host network in a Helm template",
    detail: "The template sets hostNetwork to true.",
    remediation:
      "Disable hostNetwork unless a reviewed node-level component requires it.",
  },
  HELM003: {
    category: "reliability",
    severity: "medium",
    title: "Unpinned image in a Helm template",
    detail: "An image tag uses latest.",
    remediation: "Pin an immutable digest or a release tag.",
  },
  HELM004: {
    category: "security",
    severity: "high",
    title: "Docker socket mounted in a Helm template",
    detail: "A hostPath or volume contains docker.sock.",
    remediation:
      "Remove the Docker socket mount. Use a scoped volume or a reviewed runtime API instead.",
  },
  ANS001: {
    category: "security",
    severity: "high",
    title: "Ansible task runs as root",
    detail: "A play or task sets become to true or yes.",
    remediation:
      "Set become to false unless the task has a reviewed need to run as root.",
  },
  ANS002: {
    category: "security",
    severity: "high",
    title: "Broad network exposure",
    detail: "A cidr or source allows 0.0.0.0/0.",
    remediation:
      "Restrict the cidr or source to approved addresses.",
  },
  PIPE001: {
    category: "security",
    severity: "medium",
    title: "Unpinned container image",
    detail:
      "An image or step name uses the latest tag, or it has no tag and no digest.",
    remediation: "Pin a release tag or an image digest.",
  },
  PIPE002: {
    category: "security",
    severity: "high",
    title: "Pipeline prints a secret",
    detail: "A script line echoes or prints a secret-like variable.",
    remediation:
      "Remove the printed secret from the script. Pass secrets through a variable the script does not print.",
  },
  PIPE003: {
    category: "security",
    severity: "critical",
    title: "Elevated container privileges",
    detail: "The pipeline sets privileged to true.",
    remediation:
      "Set privileged to false. Isolate workloads that genuinely require elevated privileges.",
  },
  TF001: {
    category: "security",
    severity: "high",
    title: "Secret assigned in a Terraform variable",
    detail:
      "A Terraform variable default or tfvars assignment gives a non-empty literal to a secret-like name.",
    remediation:
      "Pass the value from a secret store or leave the default empty. Do not commit a literal secret.",
  },
  TF002: {
    category: "security",
    severity: "high",
    title: "Secret assigned in a Terraform local",
    detail:
      "A Terraform local assigns a non-empty literal to a secret-like name.",
    remediation:
      "Pass the value from a secret store or a variable reference. Do not commit a literal secret in locals.",
  },
  SLS001: {
    category: "security",
    severity: "high",
    title: "Secret assigned in serverless environment",
    detail:
      "A Serverless Framework environment entry assigns a non-empty literal to a secret-like name.",
    remediation:
      "Reference the value with a Serverless variable such as ${env:TOKEN}. Do not commit a literal secret.",
  },
  PKG001: {
    category: "security",
    severity: "high",
    title: "Package script pipes a download to a shell",
    detail:
      "A package install script downloads with curl or wget and pipes the result to a shell.",
    remediation:
      "Run a reviewed local script instead of piping a remote download to a shell.",
  },
  PKG002: {
    category: "security",
    severity: "medium",
    title: "Dependency range is floating",
    detail: "A dependency range is * or latest.",
    remediation: "Pin the dependency to a reviewed version.",
  },
};

export type TerraformLiterals = {
  vars: Map<string, string | boolean | number>;
  locals: Map<string, string | boolean | number>;
  declaredSecrets: Set<string>;
};

export function terraformLiterals(resources: Resource[]): TerraformLiterals {
  return collectSameFileLiterals(resources);
}

export function resourceFindings(
  resources: Resource[],
  format: string,
  shared?: TerraformLiterals,
): { findings: Finding[]; checked: Set<string> } {
  const findings: Finding[] = [];
  const checked = new Set<string>();
  const sameFile = shared ?? collectSameFileLiterals(resources);
  const suppressedSecrets = new WeakMap<Resource, Set<string>>();
  const moduleSecrets = new WeakMap<Resource, Set<string>>();
  const valueOrigins = new WeakMap<Resource, Map<string, string>>();
  if (format === "terraform") {
    for (const resource of resources) {
      if (
        resource.type === "terraform:variable" ||
        resource.type === "terraform:local" ||
        resource.type === "tfvars:assignment"
      )
        continue;
      const suppressed = new Set<string>();
      const referenced = new Set<string>();
      const origins = new Map<string, string>();
      resolveSameFileRefs(resource.value, sameFile, [], suppressed, referenced, origins);
      suppressedSecrets.set(resource, suppressed);
      moduleSecrets.set(resource, referenced);
      valueOrigins.set(resource, origins);
    }
  }
  for (const resource of resources) {
    const origins = valueOrigins.get(resource) ?? cloudFormationOrigins(resource);
    const check = (id: string, condition: unknown, path: Path = []) => {
      checked.add(id);
      if (condition)
        findings.push({
          ruleId: id,
          ...rules[id],
          detail: `${rules[id].detail}${originSentence(origins, path)}`,
          resource: resource.id,
          location: resource.locate(path),
        });
    };
    if (format === "dockerfile") {
      checkDockerfile(resource, check);
      continue;
    }
    if (format === "github") {
      checkGithub(resource, check);
      continue;
    }
    if (format === "helm") {
      checkHelm(resource, check);
      continue;
    }
    if (format === "ansible") {
      checkAnsible(resource, check);
      continue;
    }
    if (format === "bicep" || format === "arm") {
      checkAzure(resource, check);
      continue;
    }
    if (
      format === "gitlab" ||
      format === "azure-pipelines" ||
      format === "cloudbuild"
    ) {
      checkPipeline(resource, check);
      continue;
    }
    if (format === "serverless") {
      checkServerless(resource, check);
      continue;
    }
    if (format === "iam") {
      check("IAM001", resource.value.wildcard === true, ["Action"]);
      check("NET001", resource.value.openSourceIp === true, ["Condition"]);
      continue;
    }
    if (format === "package") {
      checkPackage(resource, check);
      continue;
    }
    if (resource.type === "terraform:local") {
      checkTerraformLiterals(resource.value, "local", check, []);
      continue;
    }
    if (resource.type === "terraform:module") {
      checkTerraformLiterals(
        resource.value,
        "module",
        check,
        [],
        "",
        moduleSecrets.get(resource),
      );
      continue;
    }
    if (resource.type === "terraform:variable") {
      checkTerraformLiterals(
        { [String(resource.value.name ?? "default")]: resource.value.default },
        "assignment",
        check,
        ["default"],
      );
      continue;
    }
    if (format === "tfvars" || resource.type === "tfvars:assignment") {
      checkTerraformLiterals(
        { [String(resource.value.name ?? "value")]: resource.value.value },
        "assignment",
        check,
        [],
      );
      continue;
    }
    walk(resource.value, (key, value, path, parent) => {
      if (typeof value !== "string") return;
      const credentialName =
        /(?:password|passwd|secret|api[_-]?key|auth[_-]?token)$/i;
      check(
        "SEC001",
        (credentialName.test(key) ||
          (key === "value" && credentialName.test(String(parent.name)))) &&
          literalCredential(value) &&
          !suppressedSecrets.get(resource)?.has(path.join(".")),
        path,
      );
      check("SEC002", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/.test(value), path);
      check(
        "SEC003",
        /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/.test(value),
        path,
      );
      check(
        "NET002",
        [...value.matchAll(/\bhttp:\/\/[^\s"'<>]+/gi)].some((m) =>
          externalHttp(m[0]),
        ),
        path,
      );
    });
    if (format === "kubernetes") checkKubernetes(resource, resources, check);
    else if (format === "compose") checkCompose(resource, check);
    else checkCloud(resource, resources, format, check);
    const referencedSecrets = Object.getOwnPropertyDescriptor(
      resource.value,
      "__referencedSecrets",
    )?.value;
    if (Array.isArray(referencedSecrets)) {
      for (const secretPath of referencedSecrets) {
        if (Array.isArray(secretPath)) check("SEC001", true, secretPath as Path);
      }
    }
  }
  return { findings: dedupeSecretFindings(findings), checked };
}

type Check = (id: string, condition: unknown, path?: Path) => void;

function checkDockerfile(resource: Resource, check: Check): void {
  if (resource.type === "dockerfile:user")
    check("DF001", resource.value.root === true, ["user"]);
  else if (resource.type === "dockerfile:from")
    check("DF002", resource.value.unpinned === true, ["image"]);
  else if (resource.type === "dockerfile:run")
    check("DF003", resource.value.piped === true, ["run"]);
  else if (resource.type === "dockerfile:copy")
    check("DF004", resource.value.secret === true, ["copy"]);
  else if (resource.type === "dockerfile:env")
    check("DF005", resource.value.literal === true, ["env"]);
}

function checkGithub(resource: Resource, check: Check): void {
  if (resource.type === "github:trigger")
    check(
      "GH001",
      resource.value.pullRequestTarget === true &&
        resource.value.checksOutHead === true,
      ["on"],
    );
  else if (resource.type === "github:permissions")
    check("GH002", resource.value.broad === true, ["permissions"]);
  else if (resource.type === "github:action")
    check("GH003", resource.value.floating === true, ["uses"]);
  else if (resource.type === "github:run")
    check("GH004", resource.value.printsSecret === true, ["run"]);
  else if (resource.type === "github:env")
    check("GH005", resource.value.literal === true, ["env"]);
}

function checkHelm(resource: Resource, check: Check): void {
  if (resource.type === "helm:privileged")
    check("HELM001", resource.value.present === true, ["privileged"]);
  else if (resource.type === "helm:hostNetwork")
    check("HELM002", resource.value.present === true, ["hostNetwork"]);
  else if (resource.type === "helm:image")
    check("HELM003", resource.value.present === true, ["image"]);
  else if (resource.type === "helm:socket")
    check("HELM004", resource.value.present === true, ["volume"]);
}

function checkAnsible(resource: Resource, check: Check): void {
  if (resource.type === "ansible:become")
    check("ANS001", resource.value.present === true, ["become"]);
  else if (resource.type === "ansible:cidr")
    check("ANS002", resource.value.present === true, ["cidr"]);
}

function checkPipeline(resource: Resource, check: Check): void {
  if (resource.type === "pipeline:image")
    check("PIPE001", resource.value.unpinned === true, ["image"]);
  else if (resource.type === "pipeline:script")
    check("PIPE002", resource.value.printsSecret === true, ["script"]);
  else if (resource.type === "pipeline:privileged")
    check("PIPE003", resource.value.present === true, ["privileged"]);
}

function checkServerless(resource: Resource, check: Check): void {
  if (resource.type === "serverless:iam") {
    check("IAM001", resource.value.wildcard === true, ["Action"]);
    check("NET001", resource.value.openSourceIp === true, ["Condition"]);
  } else if (resource.type === "serverless:env")
    check("SLS001", resource.value.literal === true, ["environment"]);
}

function terraformReference(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.includes("${") || /^var\./.test(trimmed);
}

function secretAssignmentName(name: string): boolean {
  const normalized = name.replace(/-/g, "_");
  return (
    /(?:^|_)(?:password|passwd|secret|token)$/i.test(normalized) ||
    /(?:^|_)(?:api_?key|auth_token|access_key|private_key)$/i.test(normalized)
  );
}

function moduleCidrExempt(name: string): boolean {
  const normalized = name.trim().toLowerCase().replace(/[\s-]+/g, "_");
  return (
    normalized === "egress" ||
    normalized === "destination" ||
    normalized === "ipv6_egress"
  );
}

function checkTerraformLiterals(
  value: unknown,
  mode: "module" | "assignment" | "local",
  check: Check,
  path: Path,
  name = "",
  referencedSecrets?: Set<string>,
): void {
  if (typeof value === "string" || typeof value === "boolean") {
    const open = value === "0.0.0.0/0" || value === "::/0";
    const exempt =
      mode === "assignment" ? name.toLowerCase() === "egress" : moduleCidrExempt(name);
    if (typeof value === "string")
      check("NET001", open && name !== "" && !exempt, path);
    if (name === "publicly_accessible") check("DB001", value === true, path);
    if (mode === "assignment" && typeof value === "string" && secretAssignmentName(name))
      check("TF001", value.trim() !== "" && !terraformReference(value), path);
    if (mode === "local" && typeof value === "string" && secretAssignmentName(name))
      check("TF002", value.trim() !== "" && !terraformReference(value), path);
    if (mode === "module" && referencedSecrets?.has(path.join(".")))
      check("SEC001", true, path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      checkTerraformLiterals(
        item,
        mode,
        check,
        [...path, index],
        name,
        referencedSecrets,
      ),
    );
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value))
      checkTerraformLiterals(child, mode, check, [...path, key], key, referencedSecrets);
  }
}

const exactSameFileRef = /^\$\{(var|local)\.([A-Za-z_][A-Za-z0-9_]*)\}$/;
const interpolationPiece = /\$\{(var|local)\.([A-Za-z_][A-Za-z0-9_]*)\}/g;
const interpolationOnly = /^(\$\{(?:var|local)\.[A-Za-z_][A-Za-z0-9_]*\})+$/;

function sameFileText(
  kind: string,
  name: string,
  sameFile: {
    vars: Map<string, string | boolean | number>;
    locals: Map<string, string | boolean | number>;
  },
): string | undefined {
  const literal = (kind === "var" ? sameFile.vars : sameFile.locals).get(name);
  if (typeof literal === "string" || typeof literal === "number" || typeof literal === "boolean")
    return String(literal);
  return undefined;
}

function resolveInterpolationString(
  value: string,
  sameFile: {
    vars: Map<string, string | boolean | number>;
    locals: Map<string, string | boolean | number>;
  },
): { text: string; sources: string[] } | undefined {
  const trimmed = value.trim();
  if (!interpolationOnly.test(trimmed)) return undefined;
  const sources: string[] = [];
  let count = 0;
  let failed = false;
  const text = trimmed.replace(interpolationPiece, (_full, kind: string, name: string) => {
    count += 1;
    const part = sameFileText(kind, name, sameFile);
    if (part === undefined) {
      failed = true;
      return "";
    }
    sources.push(`${kind}.${name}`);
    return part;
  });
  if (failed || count < 2) return undefined;
  return { text, sources };
}

function splitCallArguments(source: string): string[] | undefined {
  const args: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let depth = 0;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (quote) {
      current += char;
      if (char === "\\" && index + 1 < source.length) {
        current += source[index + 1];
        index += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      current += char;
      continue;
    }
    if (char === "(" || char === "[" || char === "{") {
      depth += 1;
      current += char;
      continue;
    }
    if (char === ")" || char === "]" || char === "}") {
      if (depth === 0) return undefined;
      depth -= 1;
      current += char;
      continue;
    }
    if (char === "," && depth === 0) {
      args.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  if (quote || depth !== 0) return undefined;
  if (current.trim() !== "") args.push(current.trim());
  return args;
}

function unquoteHcl(token: string): string | undefined {
  if (token.length < 2) return undefined;
  const quote = token[0];
  if ((quote !== '"' && quote !== "'") || token[token.length - 1] !== quote) return undefined;
  const body = token.slice(1, -1);
  return quote === '"'
    ? body.replace(/\\n/g, "\n").replace(/\\"/g, '"').replace(/\\\\/g, "\\")
    : body.replace(/\\'/g, "'").replace(/\\\\/g, "\\");
}

function resolveFormatArgument(
  token: string,
  sameFile: {
    vars: Map<string, string | boolean | number>;
    locals: Map<string, string | boolean | number>;
  },
): { text: string; source?: string } | undefined {
  const literal = unquoteHcl(token);
  if (literal !== undefined) {
    const ref = exactSameFileRef.exec(literal.trim());
    if (!ref) {
      if (literal.includes("${")) return undefined;
      return { text: literal };
    }
    const text = sameFileText(ref[1], ref[2], sameFile);
    if (text === undefined) return undefined;
    return { text, source: `${ref[1]}.${ref[2]}` };
  }
  if (/^-?\d+(?:\.\d+)?$/.test(token) || token === "true" || token === "false") return { text: token };
  const ref = /^(var|local)\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(token);
  if (!ref) return undefined;
  const text = sameFileText(ref[1], ref[2], sameFile);
  if (text === undefined) return undefined;
  return { text, source: `${ref[1]}.${ref[2]}` };
}

function applyPercentS(format: string, args: string[]): string | undefined {
  let index = 0;
  let text = "";
  for (let cursor = 0; cursor < format.length; cursor += 1) {
    if (format[cursor] !== "%") {
      text += format[cursor];
      continue;
    }
    const verb = format[cursor + 1];
    if (verb === "%") {
      text += "%";
      cursor += 1;
      continue;
    }
    if (verb !== "s" || index >= args.length) return undefined;
    text += args[index];
    index += 1;
    cursor += 1;
  }
  return text;
}

function resolveFormatCall(
  value: string,
  sameFile: {
    vars: Map<string, string | boolean | number>;
    locals: Map<string, string | boolean | number>;
  },
): { text: string; sources: string[] } | undefined {
  const wrapped = /^\$\{format\(([\s\S]*)\)\}$/.exec(value.trim());
  if (!wrapped) return undefined;
  const args = splitCallArguments(wrapped[1]);
  if (!args || args.length === 0) return undefined;
  const resolved: string[] = [];
  const sources: string[] = [];
  for (const arg of args) {
    const part = resolveFormatArgument(arg, sameFile);
    if (part === undefined) return undefined;
    resolved.push(part.text);
    if (part.source) sources.push(part.source);
  }
  const text = applyPercentS(resolved[0], resolved.slice(1));
  if (text === undefined) return undefined;
  return { text, sources };
}

function parseHclList(token: string): string[] | undefined {
  const trimmed = token.trim();
  if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) return undefined;
  return splitCallArguments(trimmed.slice(1, -1)) ?? [];
}

function resolveJoinCall(
  value: string,
  sameFile: {
    vars: Map<string, string | boolean | number>;
    locals: Map<string, string | boolean | number>;
  },
  depth = 0,
): { text: string; sources: string[] } | undefined {
  if (depth > 8) return undefined;
  const wrapped = /^\$\{join\(([\s\S]*)\)\}$/.exec(value.trim());
  const bare = /^join\(([\s\S]*)\)$/.exec(value.trim());
  const source = wrapped?.[1] ?? bare?.[1];
  if (source === undefined) return undefined;
  const args = splitCallArguments(source);
  if (!args || args.length !== 2) return undefined;
  const separator = resolveJoinPiece(args[0], sameFile, depth);
  const list = parseHclList(args[1]);
  if (!separator || !list) return undefined;
  const parts: string[] = [];
  const sources = [...separator.sources];
  for (const element of list) {
    const resolved = resolveJoinPiece(element, sameFile, depth);
    if (!resolved) return undefined;
    parts.push(resolved.text);
    sources.push(...resolved.sources);
  }
  return { text: parts.join(separator.text), sources };
}

function resolveJoinPiece(
  token: string,
  sameFile: {
    vars: Map<string, string | boolean | number>;
    locals: Map<string, string | boolean | number>;
  },
  depth: number,
): { text: string; sources: string[] } | undefined {
  if (/^join\(/.test(token.trim()))
    return resolveJoinCall(`\${${token.trim()}}`, sameFile, depth + 1);
  const resolved = resolveFormatArgument(token, sameFile);
  if (!resolved) return undefined;
  return { text: resolved.text, sources: resolved.source ? [resolved.source] : [] };
}

function noteResolvedLiteral(
  literal: string,
  path: Path,
  sameFile: { declaredSecrets: Set<string> },
  suppressed: Set<string>,
  referencedSecrets: Set<string>,
): void {
  if (literal.trim() === "") return;
  const key = [...path].reverse().find((part) => typeof part === "string");
  if (sameFile.declaredSecrets.has(literal)) suppressed.add(path.join("."));
  else if (typeof key === "string" && secretAssignmentName(key))
    referencedSecrets.add(path.join("."));
}

function sameFileLiteral(
  value: unknown,
): string | boolean | number | undefined {
  if (typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string" && !value.includes("${")) return value;
  return undefined;
}

function collectSameFileLiterals(resources: Resource[]): {
  vars: Map<string, string | boolean | number>;
  locals: Map<string, string | boolean | number>;
  declaredSecrets: Set<string>;
} {
  const vars = new Map<string, string | boolean | number>();
  const locals = new Map<string, string | boolean | number>();
  const declaredSecrets = new Set<string>();
  for (const resource of resources) {
    if (resource.type === "terraform:variable") {
      const name = String(resource.value.name ?? "");
      const literal = sameFileLiteral(resource.value.default);
      if (!name || literal === undefined) continue;
      vars.set(name, literal);
      if (typeof literal === "string" && literal.trim() !== "" && secretAssignmentName(name))
        declaredSecrets.add(literal);
    }
    if (resource.type === "terraform:local") {
      for (const [name, raw] of Object.entries(resource.value)) {
        const literal = sameFileLiteral(raw);
        if (literal === undefined) continue;
        locals.set(name, literal);
        if (typeof literal === "string" && literal.trim() !== "" && secretAssignmentName(name))
          declaredSecrets.add(literal);
      }
    }
  }
  return { vars, locals, declaredSecrets };
}

function recordResolvedSources(origins: Map<string, string>, path: Path, sources: string[]): void {
  const unique = [...new Set(sources)];
  if (unique.length === 1) origins.set(path.join("."), unique[0]);
}

function resolveSameFileRefs(
  value: unknown,
  sameFile: {
    vars: Map<string, string | boolean | number>;
    locals: Map<string, string | boolean | number>;
    declaredSecrets: Set<string>;
  },
  path: Path,
  suppressed: Set<string>,
  referencedSecrets: Set<string>,
  origins: Map<string, string>,
): unknown {
  if (typeof value === "string") {
    const match = exactSameFileRef.exec(value.trim());
    if (match) {
      const literal = (match[1] === "var" ? sameFile.vars : sameFile.locals).get(match[2]);
      if (literal === undefined) return value;
      if (typeof literal === "string")
        noteResolvedLiteral(literal, path, sameFile, suppressed, referencedSecrets);
      origins.set(path.join("."), `${match[1]}.${match[2]}`);
      return literal;
    }
    const concatenated = resolveInterpolationString(value, sameFile);
    if (concatenated !== undefined) {
      noteResolvedLiteral(concatenated.text, path, sameFile, suppressed, referencedSecrets);
      recordResolvedSources(origins, path, concatenated.sources);
      return concatenated.text;
    }
    const formatted = resolveFormatCall(value, sameFile);
    if (formatted !== undefined) {
      noteResolvedLiteral(formatted.text, path, sameFile, suppressed, referencedSecrets);
      recordResolvedSources(origins, path, formatted.sources);
      return formatted.text;
    }
    const joined = resolveJoinCall(value, sameFile);
    if (joined !== undefined) {
      noteResolvedLiteral(joined.text, path, sameFile, suppressed, referencedSecrets);
      recordResolvedSources(origins, path, joined.sources);
      return joined.text;
    }
    return value;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      value[index] = resolveSameFileRefs(
        item,
        sameFile,
        [...path, index],
        suppressed,
        referencedSecrets,
        origins,
      );
    });
    return value;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (key === "__referencedSecrets" || key === "__valueOrigins") continue;
      (value as Record<string, unknown>)[key] = resolveSameFileRefs(
        child,
        sameFile,
        [...path, key],
        suppressed,
        referencedSecrets,
        origins,
      );
    }
  }
  return value;
}

function cloudFormationOrigins(resource: Resource): Map<string, string> {
  const stored = Object.getOwnPropertyDescriptor(resource.value, "__valueOrigins")?.value;
  return stored instanceof Map ? stored : new Map();
}

function originSentence(origins: Map<string, string>, path: Path): string {
  if (origins.size === 0) return "";
  const prefix = path.join(".");
  const sources = new Set<string>();
  for (const [key, source] of origins) {
    if (key === prefix || key.startsWith(`${prefix}.`)) sources.add(source);
  }
  if (sources.size !== 1) return "";
  return ` Value comes from ${[...sources][0]}.`;
}

function checkPackage(resource: Resource, check: Check): void {
  if (resource.type === "package:script")
    check("PKG001", resource.value.pipes === true, ["command"]);
  else if (resource.type === "package:dependency")
    check("PKG002", resource.value.range === "*" || resource.value.range === "latest", ["range"]);
}

function dedupeSecretFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    if (finding.ruleId !== "SEC001") return true;
    const key = `${finding.ruleId}|${finding.resource}|${finding.location?.path ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function checkAzure(resource: Resource, check: Check): void {
  if (resource.type === "azure:exposure")
    check("AZ001", resource.value.present === true, ["sourceAddressPrefix"]);
  else if (resource.type === "azure:publicNetwork")
    check("AZ002", resource.value.present === true, ["publicNetworkAccess"]);
}

function walk(
  value: unknown,
  visit: (
    key: string,
    value: unknown,
    path: Path,
    parent: Record<string, unknown>,
  ) => void,
  path: Path = [],
): void {
  if (Array.isArray(value))
    value.forEach((child, index) => walk(child, visit, [...path, index]));
  else
    for (const [key, child] of Object.entries(object(value))) {
      visit(key, child, [...path, key], object(value));
      if (child && typeof child === "object")
        walk(child, visit, [...path, key]);
    }
}

function composePortIsPublic(port: unknown): boolean {
  if (typeof port === "string") {
    const value = port.trim();
    if (/^(?:127\.0\.0\.1|localhost):/.test(value)) return false;
    if (value.includes("0.0.0.0")) return true;
    return /^\d+:\d+(?:\/[A-Za-z0-9]+)?$/.test(value);
  }
  const mapping = object(port);
  const host = mapping.host_ip ?? mapping.hostIp;
  if (host === "127.0.0.1" || host === "localhost") return false;
  return host === "0.0.0.0" || mapping.published != null || mapping.target != null;
}

function checkCompose(resource: Resource, check: Check): void {
  const service = resource.value;
  const image = typeof service.image === "string" ? service.image : "";
  const limits = object(object(object(service.deploy).resources).limits);
  const user = service.user;
  check("K8S001", service.privileged === true, ["privileged"]);
  check("K8S002", service.network_mode === "host", ["network_mode"]);
  check(
    "K8S003",
    array(service.volumes).some((volume) => {
      const text =
        typeof volume === "string"
          ? volume
          : String(object(volume).source ?? object(volume).target ?? "");
      return (
        text.includes("docker.sock") ||
        /(?:^|:)\/:/.test(text) ||
        text.startsWith("/var/run/")
      );
    }),
    ["volumes"],
  );
  check(
    "K8S004",
    user === "root" || user === "0" || user === 0,
    ["user"],
  );
  check(
    "K8S006",
    array(service.cap_add).some((cap) =>
      ["ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"].includes(
        String(cap).toUpperCase(),
      ),
    ),
    ["cap_add"],
  );
  check(
    "K8S007",
    image !== "" && (image.endsWith(":latest") || !/[:@]/.test(image)),
    ["image"],
  );
  check(
    "K8S008",
    service.mem_limit == null &&
      limits.memory == null &&
      service.mem_reservation == null,
    ["mem_limit"],
  );
  check("NET001", array(service.ports).some(composePortIsPublic), ["ports"]);
}

function statementEffectAllows(body: Record<string, unknown>): boolean {
  const effect = body.Effect ?? body.effect;
  if (effect == null || String(effect).trim() === "") return true;
  return String(effect).trim().toLowerCase() === "allow";
}

function principalAllowsAnyone(value: unknown): boolean {
  if (typeof value === "string") return value.trim() === "*";
  if (Array.isArray(value)) return value.some((item) => principalAllowsAnyone(item));
  if (value && typeof value === "object")
    return Object.values(value).some((item) => principalAllowsAnyone(item));
  return false;
}

function actionIncludesWildcard(value: unknown): boolean {
  return array(value).some((item) => typeof item === "string" && item.includes("*"));
}

function checkInlinePolicy(document: unknown, check: Check, path: Path): void {
  const root = object(document);
  const statements = root.Statement ?? root.statement;
  if (!Array.isArray(statements) && (statements == null || typeof statements !== "object")) return;
  for (const statement of array(statements)) {
    const body = object(statement);
    if (!statementEffectAllows(body)) continue;
    check(
      "IAM001",
      actionIncludesWildcard(body.Action ?? body.action ?? body.Actions ?? body.actions),
      path,
    );
    const principal = body.Principal ?? body.principal ?? body.Principals ?? body.principals;
    if (principal !== undefined) check("IAM002", principalAllowsAnyone(principal), path);
  }
}

function checkCloud(
  resource: Resource,
  resources: Resource[],
  format: string,
  check: Check,
): void {
  const tf = format === "terraform";
  const pulumi = format === "pulumi";
  const value = tf
    ? resource.value
    : pulumi
      ? object(resource.value.properties)
      : object(resource.value.Properties);
  const prefix: Path = tf ? [] : pulumi ? ["properties"] : ["Properties"];
  const property = (hcl: string, cfn: string) => value[tf || pulumi ? hcl : cfn];
  const path = (hcl: string, cfn: string) => [
    ...prefix,
    tf || pulumi ? hcl : cfn,
  ];
  walk(value, (key, child, at, parent) => {
    const isIngress =
      !at.some((part) =>
        /^(?:egress|SecurityGroupEgress)$/i.test(String(part)),
      ) &&
      !/egress/i.test(resource.type) &&
      value.type !== "egress";
    if (
      /^(?:cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6|cidrBlocks|ipv6CidrBlocks|cidrBlock|CidrIp|CidrIpv6)$/.test(
        key,
      ) &&
      isIngress
    ) {
      check(
        "NET001",
        array(child).some((cidr) => cidr === "0.0.0.0/0" || cidr === "::/0"),
        [...prefix, ...at],
      );
    }
    if (/^(?:Action|actions)$/.test(key) && statementEffectAllows(parent)) {
      check("IAM001", actionIncludesWildcard(child), [...prefix, ...at]);
    }
    if (/^(?:Principal|principals)$/.test(key) && statementEffectAllows(parent)) {
      check("IAM002", principalAllowsAnyone(child), [...prefix, ...at]);
    }
    if (typeof child === "string") {
      const encoded = child.trim().startsWith("${jsonencode(")
        ? terraformJsonencodeValue(child)
        : undefined;
      let parsed: unknown;
      if (
        encoded === undefined &&
        /^(?:policy|assume_role_policy|PolicyDocument)$/.test(key) &&
        child.trimStart().startsWith("{")
      ) {
        try {
          parsed = JSON.parse(child);
        } catch {
          parsed = undefined;
        }
      }
      const document = encoded ?? parsed;
      if (document !== undefined)
        checkInlinePolicy(document, check, [...prefix, ...at]);
    }
    if (
      /^(?:instance_type|machine_type|vm_size|InstanceType|DBInstanceClass|instance_class)$/.test(
        key,
      )
    )
      check("COST001", typeof child === "string", [...prefix, ...at]);
  });
  if (
    ["aws_s3_bucket", "aws_s3_bucket_acl", "AWS::S3::Bucket"].includes(
      resource.type,
    )
  ) {
    check(
      "DATA001",
      [
        "public-read",
        "public-read-write",
        "PublicRead",
        "PublicReadWrite",
        "AuthenticatedRead",
        "authenticated-read",
      ].includes(String(property("acl", "AccessControl"))),
      path("acl", "AccessControl"),
    );
  }
  if (["aws_s3_bucket", "AWS::S3::Bucket"].includes(resource.type)) {
    const attached = resources.find(
      (r) =>
        r.type === "aws_s3_bucket_versioning" &&
        r.value.bucket === `\${${resource.id}.id}`,
    );
    const config = tf
      ? object(array(value.versioning)[0])
      : object(value.VersioningConfiguration);
    const separate = object(array(attached?.value.versioning_configuration)[0]);
    const enabled = tf
      ? config.enabled === true || separate.status === "Enabled"
      : config.Status === "Enabled";
    const dynamic = [config.enabled, config.Status, separate.status].some(
      (v) =>
        typeof v === "object" || (typeof v === "string" && v.includes("${")),
    );
    check(
      "DATA003",
      !enabled && !dynamic,
      path("versioning", "VersioningConfiguration"),
    );
  }
  if (
    ["aws_s3_bucket_public_access_block", "AWS::S3::Bucket"].includes(
      resource.type,
    )
  ) {
    const config = tf ? value : object(value.PublicAccessBlockConfiguration);
    for (const key of tf
      ? [
          "block_public_acls",
          "block_public_policy",
          "ignore_public_acls",
          "restrict_public_buckets",
        ]
      : [
          "BlockPublicAcls",
          "BlockPublicPolicy",
          "IgnorePublicAcls",
          "RestrictPublicBuckets",
        ]) {
      check(
        "DATA001",
        config[key] === false,
        tf ? [key] : ["Properties", "PublicAccessBlockConfiguration", key],
      );
    }
  }
  if (
    [
      "aws_db_instance",
      "aws_rds_cluster",
      "AWS::RDS::DBInstance",
      "AWS::RDS::DBCluster",
    ].includes(resource.type)
  ) {
    check(
      "DB001",
      property("publicly_accessible", "PubliclyAccessible") === true,
      path("publicly_accessible", "PubliclyAccessible"),
    );
    check(
      "DATA002",
      property("storage_encrypted", "StorageEncrypted") === false,
      path("storage_encrypted", "StorageEncrypted"),
    );
    check(
      "DB002",
      property("backup_retention_period", "BackupRetentionPeriod") === 0,
      path("backup_retention_period", "BackupRetentionPeriod"),
    );
    check(
      "DB003",
      property("deletion_protection", "DeletionProtection") === false,
      path("deletion_protection", "DeletionProtection"),
    );
    check(
      "DB004",
      property("multi_az", "MultiAZ") === false,
      path("multi_az", "MultiAZ"),
    );
  }
  if (["aws_ebs_volume", "AWS::EC2::Volume"].includes(resource.type))
    check(
      "DATA002",
      property("encrypted", "Encrypted") === false,
      path("encrypted", "Encrypted"),
    );
  if (["aws_instance", "AWS::EC2::Instance"].includes(resource.type)) {
    const metadata = tf
      ? object(array(value.metadata_options)[0])
      : object(value.MetadataOptions);
    const tokens = metadata[tf ? "http_tokens" : "HttpTokens"];
    const endpoint = metadata[tf ? "http_endpoint" : "HttpEndpoint"];
    check(
      "VM001",
      endpoint !== "disabled" &&
        (tokens === undefined || tokens === "optional"),
      path("metadata_options", "MetadataOptions"),
    );
  }
}

function checkKubernetes(
  resource: Resource,
  resources: Resource[],
  check: Check,
): void {
  const value = resource.value;
  const spec = object(value.spec);
  if (resource.type === "Secret")
    check(
      "K8S012",
      Object.keys(object(value.data)).length +
        Object.keys(object(value.stringData)).length >
        0,
    );
  if (["Role", "ClusterRole"].includes(resource.type)) {
    array(value.rules).forEach((rule, index) => {
      const r = object(rule);
      check(
        "K8S013",
        [
          ...array(r.verbs),
          ...array(r.resources),
          ...array(r.apiGroups),
        ].includes("*"),
        ["rules", index],
      );
    });
  }
  const workload = [
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
  ].includes(resource.type);
  if (!workload) return;
  const prefix: Path =
    resource.type === "Pod"
      ? ["spec"]
      : resource.type === "CronJob"
        ? ["spec", "jobTemplate", "spec", "template", "spec"]
        : ["spec", "template", "spec"];
  let pod: unknown = value;
  for (const key of prefix) pod = object(pod)[key];
  const podSpec = object(pod);
  const podSecurity = object(podSpec.securityContext);
  for (const key of ["hostNetwork", "hostPID", "hostIPC"])
    check("K8S002", podSpec[key] === true, [...prefix, key]);
  array(podSpec.volumes).forEach((volume, index) =>
    check("K8S003", object(volume).hostPath != null, [
      ...prefix,
      "volumes",
      index,
      "hostPath",
    ]),
  );
  if (
    [
      "Deployment",
      "StatefulSet",
      "ReplicaSet",
      "ReplicationController",
    ].includes(resource.type)
  ) {
    const metadata = object(value.metadata);
    const hasAutoscaler = resources.some((r) => {
      const target = object(object(r.value.spec).scaleTargetRef);
      return (
        r.type === "HorizontalPodAutoscaler" &&
        target.kind === resource.type &&
        target.name === metadata.name &&
        (object(r.value.metadata).namespace ?? "default") ===
          (metadata.namespace ?? "default")
      );
    });
    check(
      "K8S011",
      !hasAutoscaler &&
        (spec.replicas === undefined ||
          (typeof spec.replicas === "number" && spec.replicas < 2)),
      ["spec", "replicas"],
    );
  }
  for (const group of ["containers", "initContainers", "ephemeralContainers"]) {
    array(podSpec[group]).forEach((raw, index) => {
      const container = object(raw);
      const at: Path = [...prefix, group, index];
      const security = object(container.securityContext);
      check(
        "K8S001",
        security.privileged === true ||
          security.allowPrivilegeEscalation === true,
        [...at, "securityContext"],
      );
      check(
        "K8S004",
        (security.runAsNonRoot ?? podSecurity.runAsNonRoot) !== true ||
          (security.runAsUser ?? podSecurity.runAsUser) === 0,
        [...at, "securityContext"],
      );
      check("K8S005", security.readOnlyRootFilesystem !== true, [
        ...at,
        "securityContext",
      ]);
      check(
        "K8S006",
        array(object(security.capabilities).add).some((v) =>
          ["ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"].includes(String(v)),
        ),
        [...at, "securityContext", "capabilities"],
      );
      const image = typeof container.image === "string" ? container.image : "";
      check(
        "K8S007",
        image &&
          !image.includes("@sha256:") &&
          (!image.split("/").at(-1)?.includes(":") ||
            image.endsWith(":latest")),
        [...at, "image"],
      );
      if (group !== "ephemeralContainers") {
        const bounds = object(container.resources);
        const requests = object(bounds.requests);
        check(
          "K8S008",
          requests.cpu == null ||
            requests.memory == null ||
            object(bounds.limits).memory == null,
          [...at, "resources"],
        );
      }
      if (
        group === "containers" &&
        !["Job", "CronJob"].includes(resource.type)
      ) {
        check(
          "K8S009",
          array(container.ports).length > 0 && !container.readinessProbe,
          [...at, "readinessProbe"],
        );
        check("K8S010", !container.livenessProbe, [...at, "livenessProbe"]);
      }
    });
  }
}
