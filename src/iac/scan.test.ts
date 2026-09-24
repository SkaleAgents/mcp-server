import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { scanIac } from "./scan.js";
import { looksLikeIac, ScanInputError } from "./parse.js";

describe("Terraform scanning", () => {
  it("parses resource blocks, ignores comments and strings, and distinguishes egress", () => {
    const scan = scanIac(
      `# resource "fake" "comment" {}
resource "aws_security_group" "web" {
  description = "resource is a word, not a resource"
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  egress { cidr_blocks = ["0.0.0.0/0"] }
}
resource "aws_vpc_security_group_egress_rule" "outbound" { cidr_ipv4 = "0.0.0.0/0" }
`,
      { format: "terraform" },
    );
    assert.equal(scan.parsedResourceCount, 2);
    assert.equal(scan.findings.filter((f) => f.ruleId === "NET001").length, 2);
    assert.equal(scan.findings[0].location?.line, 2);
    assert.match(scan.findings[0].location!.path, /ingress/);
  });
  it("handles Terraform JSON with the same resource rules", () => {
    const content = JSON.stringify({
      variable: {},
      resource: {
        aws_db_instance: {
          test: {
            publicly_accessible: true,
            storage_encrypted: false,
            backup_retention_period: 0,
            multi_az: false,
          },
        },
      },
    });
    assert.equal(looksLikeIac(content), true);
    const scan = scanIac(content);
    assert.equal(scan.format, "terraform");
    assert.deepEqual(
      new Set(scan.findings.map((f) => f.ruleId)),
      new Set(["DB001", "DATA002", "DB002", "DB004"]),
    );
  });
  it("resolves a submitted bucket versioning resource reference", () => {
    const scan = scanIac(`resource "aws_s3_bucket" "assets" {}
resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id
  versioning_configuration { status = "Enabled" }
}`);
    assert.ok(!scan.findings.some((f) => f.ruleId === "DATA003"));
    assert.ok(scan.warnings.some((w) => w.includes("expressions")));
  });
  it("checks IAM Allow statements without flagging a Deny wildcard", () => {
    const scan = scanIac(
      JSON.stringify({
        resource: {
          aws_iam_policy: {
            test: {
              policy: JSON.stringify({
                Statement: [
                  { Effect: "Deny", Action: "*", Resource: "*" },
                  { Effect: "Allow", Action: ["s3:*"], Resource: "*" },
                ],
              }),
            },
          },
        },
      }),
    );
    assert.equal(scan.findings.filter((f) => f.ruleId === "IAM001").length, 1);
  });
  it("does not claim variables or external modules were evaluated", () => {
    const scan = scanIac(
      'module "db" { source = "./database" }\nresource "aws_db_instance" "test" { publicly_accessible = var.public }',
    );
    assert.ok(scan.warnings.some((w) => w.includes("modules")));
    assert.ok(scan.warnings.some((w) => w.includes("expressions")));
    assert.ok(!scan.findings.some((f) => f.ruleId === "DB001"));
  });
});

describe("CloudFormation scanning", () => {
  it("counts Resources rather than property names and supports intrinsic functions", () => {
    const scan = scanIac(`AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      DBName: !Ref DatabaseName
      MasterUserPassword: !Sub '{{resolve:secretsmanager:db:SecretString:password}}'
      PubliclyAccessible: true
      StorageEncrypted: false
      BackupRetentionPeriod: 0
  Policy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: ['s3:*']
            Resource: !GetAtt [Bucket, Arn]
`);
    assert.equal(scan.format, "cloudformation");
    assert.equal(scan.parsedResourceCount, 2);
    assert.ok(
      scan.findings.some((f) => f.ruleId === "DB001" && f.location?.line === 8),
    );
    assert.ok(scan.findings.some((f) => f.ruleId === "IAM001"));
    assert.ok(!scan.findings.some((f) => f.ruleId === "SEC001"));
    assert.ok(scan.warnings.length);
  });
  it("checks public ACLs, backup protection and metadata tokens in JSON", () => {
    const scan = scanIac(
      JSON.stringify({
        Resources: {
          Bucket: {
            Type: "AWS::S3::Bucket",
            Properties: { AccessControl: "PublicRead" },
          },
          VM: {
            Type: "AWS::EC2::Instance",
            Properties: { MetadataOptions: { HttpTokens: "optional" } },
          },
          DB: {
            Type: "AWS::RDS::DBInstance",
            Properties: { DeletionProtection: false, MultiAZ: false },
          },
        },
      }),
    );
    for (const id of ["DATA001", "DATA003", "VM001", "DB003", "DB004"])
      assert.ok(
        scan.findings.some((f) => f.ruleId === id),
        id,
      );
  });
});

const hardenedPod = {
  apiVersion: "v1",
  kind: "Pod",
  metadata: { name: "test" },
  spec: {
    securityContext: { runAsNonRoot: true, runAsUser: 1000 },
    containers: [
      {
        name: "app",
        image: "nginx:1.28.0",
        securityContext: {
          readOnlyRootFilesystem: true,
          allowPrivilegeEscalation: false,
        },
        resources: {
          requests: { cpu: "100m", memory: "64Mi" },
          limits: { memory: "128Mi" },
        },
        livenessProbe: { exec: { command: ["true"] } },
      },
    ],
  },
};

describe("Kubernetes scanning", () => {
  it("checks pod settings and container settings at distinct paths", () => {
    const scan = scanIac(`apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  replicas: 1
  template:
    spec:
      hostNetwork: true
      volumes: [{ name: host, hostPath: { path: / } }]
      containers:
        - name: app
          image: nginx:latest
          ports: [{ containerPort: 80 }]
          securityContext: { privileged: true, capabilities: { add: [SYS_ADMIN] } }
`);
    for (const id of [
      "K8S001",
      "K8S002",
      "K8S003",
      "K8S004",
      "K8S005",
      "K8S006",
      "K8S007",
      "K8S008",
      "K8S009",
      "K8S010",
      "K8S011",
    ])
      assert.ok(
        scan.findings.some((f) => f.ruleId === id),
        id,
      );
    assert.equal(
      scan.findings.find((f) => f.ruleId === "K8S007")?.location?.line,
      12,
    );
    assert.ok(
      scan.findings.every((f) => f.location && f.remediation && f.resource),
    );
  });
  it("accepts a hardened pod without risk findings and inherits pod securityContext", () => {
    assert.equal(scanIac(JSON.stringify(hardenedPod)).findings.length, 0);
  });
  it("parses multi-document YAML and List items without counting nested kind properties", () => {
    const scan = scanIac(`apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Secret
    metadata: {name: credentials}
    data: {password: ZXhhbXBsZS10ZXN0LW9ubHk=}
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: {name: operator}
    rules: [{apiGroups: ['*'], resources: ['*'], verbs: ['*']}]
---
apiVersion: v1
kind: Service
metadata: {name: app}
spec: {type: ClusterIP}
`);
    assert.equal(scan.parsedResourceCount, 3);
    assert.ok(scan.findings.some((f) => f.ruleId === "K8S012"));
    assert.ok(scan.findings.some((f) => f.ruleId === "K8S013"));
    assert.ok(!JSON.stringify(scan).includes("ZXhhbXBsZS"));
  });
  it("does not require serving probes for batch jobs or ignore an autoscaler", () => {
    const job = {
      apiVersion: "batch/v1",
      kind: "Job",
      metadata: { name: "batch" },
      spec: {
        template: { spec: { containers: [{ name: "job", image: "job:1" }] } },
      },
    };
    assert.ok(
      !scanIac(JSON.stringify(job)).findings.some((f) =>
        ["K8S009", "K8S010", "K8S011"].includes(f.ruleId!),
      ),
    );
    const deployment = {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: { name: "app" },
      spec: { template: { spec: hardenedPod.spec } },
    };
    const hpa = {
      apiVersion: "autoscaling/v2",
      kind: "HorizontalPodAutoscaler",
      metadata: { name: "app" },
      spec: { scaleTargetRef: { kind: "Deployment", name: "app" } },
    };
    assert.ok(
      !scanIac(
        JSON.stringify({
          apiVersion: "v1",
          kind: "List",
          items: [deployment, hpa],
        }),
      ).findings.some((f) => f.ruleId === "K8S011"),
    );
  });
});

describe("scanner output and validation", () => {
  it("filters categories and severity, with deterministic ordering and honest truncation", () => {
    const content =
      'resource "aws_db_instance" "test" {\n publicly_accessible = true\n backup_retention_period = 0\n instance_class = "db.m5.large"\n}';
    const all = scanIac(content, { maxFindings: 1 });
    assert.equal(all.findings.length, 1);
    assert.equal(all.totalFindings, 3);
    assert.equal(all.truncated, true);
    assert.equal(all.totals.high, 2);
    assert.deepEqual(
      scanIac(content, { focus: "cost" }).findings.map((f) => f.ruleId),
      ["COST001"],
    );
    assert.equal(
      scanIac(content, { minSeverity: "critical" }).findings.length,
      0,
    );
  });
  it("checks literal secrets independently of environment references and omits source values", () => {
    const scan = scanIac(
      'resource "aws_db_instance" "test" {\n password = "example-test-only"\n username = var.username\n}',
    );
    assert.ok(scan.findings.some((f) => f.ruleId === "SEC001"));
    assert.ok(!JSON.stringify(scan).includes("example-test-only"));
  });
  it("excludes HTTPS, comments and loopback endpoints", () => {
    const scan = scanIac(
      'resource "custom" "test" {\n # password = "example-test-only"\n url = "https://example.com"\n local_url = "http://localhost:80"\n}',
    );
    assert.equal(scan.findings.length, 0);
  });
  for (const [label, content, format] of [
    ["invalid HCL", 'resource "x" "y" {', "terraform"],
    ["invalid YAML", "apiVersion: v1\nkind: Pod\nspec: [", "kubernetes"],
    ["duplicate keys", "apiVersion: v1\nkind: Pod\nkind: Secret", "kubernetes"],
    ["unknown tag", "Resources: { X: !Unknown bad }", "cloudformation"],
    ["missing resource type", "Resources: { X: {} }", "cloudformation"],
    ["missing workload containers", "apiVersion: v1\nkind: Pod", "kubernetes"],
    [
      "alias",
      "apiVersion: v1\nkind: Pod\nmetadata: &meta {name: a}\nspec: *meta",
      "kubernetes",
    ],
    ["unsupported format", "hello", "auto"],
    ["whitespace", "  \n", "auto"],
  ] as const)
    it(`rejects ${label} instead of claiming a successful scan`, () => {
      assert.throws(() => scanIac(content, { format }), ScanInputError);
    });
  it("caps nesting depth", () => {
    let value: unknown = {};
    for (let i = 0; i < 90; i++) value = { nested: value };
    assert.throws(
      () =>
        scanIac(
          JSON.stringify({ apiVersion: "v1", kind: "ConfigMap", data: value }),
        ),
      ScanInputError,
    );
  });
});
