import { array, object, type Path, type Resource } from "./parse.js";
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
    detail: "An Allow statement grants wildcard actions or principals.",
    remediation:
      "List the required actions and trusted principals explicitly, with resource and condition restrictions.",
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
};

export function resourceFindings(
  resources: Resource[],
  format: string,
): { findings: Finding[]; checked: Set<string> } {
  const findings: Finding[] = [];
  const checked = new Set<string>();
  for (const resource of resources) {
    const check = (id: string, condition: unknown, path: Path = []) => {
      checked.add(id);
      if (condition)
        findings.push({
          ruleId: id,
          ...rules[id],
          resource: resource.id,
          location: resource.locate(path),
        });
    };
    walk(resource.value, (key, value, path, parent) => {
      if (typeof value !== "string") return;
      const credentialName =
        /(?:password|passwd|secret|api[_-]?key|auth[_-]?token)$/i;
      check(
        "SEC001",
        (credentialName.test(key) ||
          (key === "value" && credentialName.test(String(parent.name)))) &&
          literalCredential(value),
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
    else checkCloud(resource, resources, format, check);
  }
  return { findings, checked };
}

type Check = (id: string, condition: unknown, path?: Path) => void;

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

function checkCloud(
  resource: Resource,
  resources: Resource[],
  format: string,
  check: Check,
): void {
  const tf = format === "terraform";
  const value = tf ? resource.value : object(resource.value.Properties);
  const prefix: Path = tf ? [] : ["Properties"];
  const property = (hcl: string, cfn: string) => value[tf ? hcl : cfn];
  const path = (hcl: string, cfn: string) => [...prefix, tf ? hcl : cfn];
  walk(value, (key, child, at, parent) => {
    const isIngress =
      !at.some((part) =>
        /^(?:egress|SecurityGroupEgress)$/i.test(String(part)),
      ) &&
      !/egress/i.test(resource.type) &&
      value.type !== "egress";
    if (
      /^(?:cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6|CidrIp|CidrIpv6)$/.test(
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
    if (
      /^(?:Action|Principal|actions|principals)$/.test(key) &&
      (parent.Effect === "Allow" || parent.effect === "Allow")
    ) {
      const values =
        typeof child === "object" && !Array.isArray(child)
          ? Object.values(object(child)).flatMap(array)
          : array(child);
      check(
        "IAM001",
        values.some((item) => typeof item === "string" && item.includes("*")),
        [...prefix, ...at],
      );
    }
    if (
      /^(?:policy|assume_role_policy|PolicyDocument)$/.test(key) &&
      typeof child === "string" &&
      child.trimStart().startsWith("{")
    ) {
      try {
        const document = JSON.parse(child);
        for (const statement of array(object(document).Statement)) {
          const s = object(statement);
          check(
            "IAM001",
            s.Effect === "Allow" &&
              [
                ...array(s.Action),
                ...array(s.Principal),
                ...Object.values(object(s.Principal)).flatMap(array),
              ].some((v) => typeof v === "string" && v.includes("*")),
            [...prefix, ...at],
          );
        }
      } catch {
        /* Nonliteral policies are covered by the expression warning. */
      }
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
