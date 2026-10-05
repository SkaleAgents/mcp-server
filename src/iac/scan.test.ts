import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { scanIac } from "./scan.js";
import {
  looksLikeDockerfile,
  looksLikeGithubWorkflow,
  looksLikeIac,
  ScanInputError,
} from "./parse.js";

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
  it("scans public ingress in Pulumi YAML and ignores egress", () => {
    const content = `name: web
runtime: yaml
resources:
  webSg:
    type: aws:ec2/securityGroup:SecurityGroup
    properties:
      ingress:
        - protocol: tcp
          fromPort: 80
          toPort: 80
          cidrBlocks:
            - 0.0.0.0/0
      egress:
        - protocol: "-1"
          cidrBlocks:
            - 0.0.0.0/0
`;
    const scan = scanIac(content, { format: "auto" });
    assert.equal(looksLikeIac(content), true);
    assert.equal(scan.format, "pulumi");
    assert.equal(scan.parsedResourceCount, 1);
    assert.equal(scan.findings.filter((f) => f.ruleId === "NET001").length, 1);
    assert.match(scan.findings[0].location!.path, /ingress/);
  });
  it("scans public ingress in Pulumi programs and ignores egress and comments", () => {
    const scan = scanIac(
      `import * as pulumi from "@pulumi/pulumi";
const sg = new aws.ec2.SecurityGroup("web", {
  ingress: [{ cidrBlocks: ["0.0.0.0/0"] }],
  egress: [{ cidrBlocks: ["0.0.0.0/0"] }],
});
`,
      { format: "auto" },
    );
    assert.equal(scan.format, "pulumi");
    assert.equal(scan.findings.filter((f) => f.ruleId === "NET001").length, 1);
    assert.equal(
      scan.findings.find((f) => f.ruleId === "NET001")?.location?.line,
      3,
    );
    const deeper = scanIac(
      `import * as pulumi from "@pulumi/pulumi";
const db = new aws.rds.Instance("db", {
  publiclyAccessible: true,
  storageEncrypted: false,
  backupRetentionPeriod: 0,
});
const policy = { effect: "Allow", actions: ["*"] };
const denied = { effect: "Deny", actions: ["*"] };
const key = "AKIAIOSFODNN7EXAMPLE";
`,
    );
    for (const id of ["DB001", "DATA002", "DB002", "IAM001", "SEC002"])
      assert.equal(
        deeper.findings.filter((f) => f.ruleId === id).length,
        1,
        id,
      );
    assert.ok(!JSON.stringify(deeper).includes("AKIAIOSFODNN7EXAMPLE"));
    const python = scanIac(
      `import pulumi
sg = aws.ec2.SecurityGroup("web", ingress=[{"cidr_blocks": ["0.0.0.0/0"]}])
`,
    );
    assert.equal(python.findings.filter((f) => f.ruleId === "NET001").length, 1);
    const commented = scanIac(
      'import * as pulumi from "@pulumi/pulumi";\n// ingress cidrBlocks: ["0.0.0.0/0"]\n',
    );
    assert.equal(commented.findings.length, 0);
  });
  it("scans Docker Compose privileged services and public port bindings", () => {
    const scan = scanIac(
      `services:
  web:
    image: nginx:1.27
    privileged: true
    ports:
      - "0.0.0.0:80:80"
  db:
    image: postgres:16
    ports:
      - "127.0.0.1:5432:5432"
`,
      { format: "auto" },
    );
    assert.equal(scan.format, "compose");
    assert.equal(scan.parsedResourceCount, 2);
    assert.equal(scan.findings.filter((f) => f.ruleId === "K8S001").length, 1);
    assert.equal(scan.findings.filter((f) => f.ruleId === "NET001").length, 1);
    assert.equal(scan.findings.filter((f) => f.ruleId === "K8S008").length, 2);
  });
  it("scans Compose host access, capabilities, image pins, and short public ports", () => {
    const scan = scanIac(
      `services:
  web:
    image: nginx
    user: root
    network_mode: host
    cap_add:
      - SYS_ADMIN
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    mem_limit: 256m
`,
    );
    for (const id of ["K8S002", "K8S003", "K8S004", "K8S006", "K8S007", "NET001"])
      assert.equal(scan.findings.filter((f) => f.ruleId === id).length, 1, id);
    assert.equal(scan.findings.filter((f) => f.ruleId === "K8S008").length, 0);
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

const textWarning =
  "The scan reads the submitted text and does not execute the image or the workflow.";

describe("Dockerfile scanning", () => {
  it("flags a root user, an unpinned image, and a remote script piped to a shell", () => {
    const scan = scanIac(
      `FROM nginx:latest
USER root
RUN curl -fsSL https://example.com/install.sh | bash
`,
      { format: "auto" },
    );
    assert.equal(scan.format, "dockerfile");
    assert.equal(looksLikeDockerfile("FROM nginx:latest\n"), true);
    assert.equal(looksLikeIac("FROM nginx:latest\n"), true);
    assert.ok(scan.warnings.includes(textWarning));
    const root = scan.findings.find((finding) => finding.ruleId === "DF001");
    const image = scan.findings.find((finding) => finding.ruleId === "DF002");
    const piped = scan.findings.find((finding) => finding.ruleId === "DF003");
    assert.equal(root?.title, "Dockerfile runs as root");
    assert.equal(root?.category, "security");
    assert.equal(root?.severity, "high");
    assert.equal(image?.title, "Unpinned container image");
    assert.equal(image?.severity, "medium");
    assert.equal(piped?.title, "Remote script piped to a shell");
    assert.equal(piped?.severity, "high");
    assert.equal(scan.findings.some((finding) => finding.ruleId === "SEC001"), false);
    assert.equal(scan.rulesEvaluated.includes("NET001"), false);
  });

  it("treats a missing USER, uid 0, wget piped to sh, and an untagged image as findings", () => {
    const missingUser = scanIac("FROM nginx\nRUN wget -qO- https://example.com/install.sh | sh\n");
    assert.equal(missingUser.findings.filter((finding) => finding.ruleId === "DF001").length, 1);
    assert.equal(missingUser.findings.filter((finding) => finding.ruleId === "DF002").length, 1);
    assert.equal(missingUser.findings.filter((finding) => finding.ruleId === "DF003").length, 1);
    const uid = scanIac("FROM node:20-alpine\nUSER 0\n");
    assert.equal(uid.findings.filter((finding) => finding.ruleId === "DF001").length, 1);
    assert.equal(uid.findings.some((finding) => finding.ruleId === "DF002"), false);
  });

  it("clears a non-root user, a pinned tag, scratch, named stages, and a normal install", () => {
    const clear = scanIac(
      `FROM node:20-alpine AS build
FROM build
FROM scratch
FROM \${stage}
USER node
RUN npm ci
RUN curl -fsSL https://example.com/archive.tgz -o archive.tgz
`,
    );
    assert.equal(clear.format, "dockerfile");
    assert.equal(clear.findings.some((finding) => finding.ruleId === "DF001"), false);
    assert.equal(clear.findings.some((finding) => finding.ruleId === "DF002"), false);
    assert.equal(clear.findings.some((finding) => finding.ruleId === "DF003"), false);
    const finalNonRoot = scanIac("FROM nginx:latest\nUSER root\nUSER node\n");
    assert.equal(finalNonRoot.findings.some((finding) => finding.ruleId === "DF001"), false);
    assert.equal(finalNonRoot.findings.some((finding) => finding.ruleId === "DF002"), true);
  });

  it("does not classify a Dockerfile as Terraform, even when a line looks like HCL", () => {
    const content = `FROM nginx:latest
RUN echo 'resource "aws_s3_bucket" "logs" {'
`;
    assert.equal(scanIac(content, { format: "auto" }).format, "dockerfile");
    assert.equal(scanIac(content, { format: "terraform" }).format, "dockerfile");
    assert.doesNotThrow(() =>
      scanIac("FROM nginx:latest\nRUN [echo\n", { format: "auto" }),
    );
  });
});

describe("GitHub Actions scanning", () => {
  it("flags pull_request_target checkout of the PR head, broad permissions, and floating refs", () => {
    const checkout = scanIac(
      `on:
  pull_request_target:
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`,
      { format: "auto" },
    );
    assert.equal(checkout.format, "github");
    assert.equal(
      looksLikeGithubWorkflow("on:\n  pull_request_target:\njobs:\n  build:\n    steps: []\n"),
      true,
    );
    const quoted = `"on":\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          sha: \${{ github.event.pull_request.head.ref }}\n`;
    assert.equal(looksLikeGithubWorkflow(quoted), true);
    assert.equal(scanIac(quoted).format, "github");
    const head = checkout.findings.find((finding) => finding.ruleId === "GH001");
    assert.equal(head?.title, "Pull request target checks out PR code");
    assert.equal(head?.severity, "critical");
    assert.equal(head?.category, "security");
    assert.ok(checkout.warnings.includes(textWarning));
    const quotedScan = scanIac(quoted);
    assert.equal(quotedScan.findings.filter((finding) => finding.ruleId === "GH001").length, 1);

    const broad = scanIac(
      `on: push
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@main
      - uses: owner/action@master
`,
    );
    assert.equal(broad.findings.filter((finding) => finding.ruleId === "GH002").length, 1);
    assert.equal(broad.findings.find((finding) => finding.ruleId === "GH002")?.title, "Workflow permissions are broad");
    assert.equal(broad.findings.find((finding) => finding.ruleId === "GH002")?.severity, "high");
    assert.equal(broad.findings.filter((finding) => finding.ruleId === "GH003").length, 2);
    assert.equal(broad.findings.find((finding) => finding.ruleId === "GH003")?.title, "Action ref is a floating branch");
    assert.equal(broad.findings.find((finding) => finding.ruleId === "GH003")?.severity, "medium");
    assert.equal(broad.findings.some((finding) => finding.ruleId === "GH001"), false);

    const contents = scanIac(
      `on:
  pull_request_target:
permissions:
  contents: write
jobs:
  build:
    steps:
      - run: echo hi
`,
    );
    assert.equal(contents.findings.filter((finding) => finding.ruleId === "GH002").length, 1);
    assert.equal(contents.findings.some((finding) => finding.ruleId === "GH001"), false);
  });

  it("clears a push workflow with read permissions, a release tag, and a commit SHA", () => {
    const scan = scanIac(
      `on: push
permissions:
  contents: read
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
`,
    );
    assert.equal(scan.format, "github");
    assert.equal(scan.findings.length, 0);
    assert.ok(scan.warnings.includes(textWarning));
    const pushCheckout = scanIac(
      `on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`,
    );
    assert.equal(pushCheckout.findings.some((finding) => finding.ruleId === "GH001"), false);
  });
});

describe("format detection regressions", () => {
  it("keeps a Compose file with services and image as compose", () => {
    const scan = scanIac(
      `services:
  web:
    image: nginx:1.27
`,
      { format: "auto" },
    );
    assert.equal(scan.format, "compose");
    assert.equal(looksLikeGithubWorkflow("services:\n  web:\n    image: nginx\n"), false);
  });

  it("keeps a Kubernetes manifest as kubernetes", () => {
    const scan = scanIac(
      `apiVersion: v1
kind: ConfigMap
metadata:
  name: app
data:
  note: "on: push"
`,
      { format: "auto" },
    );
    assert.equal(scan.format, "kubernetes");
    assert.equal(
      looksLikeGithubWorkflow("apiVersion: v1\nkind: ConfigMap\non: push\njobs: {}\n"),
      false,
    );
  });

  it("scans a workflow that also declares job services as GitHub Actions", () => {
    const scan = scanIac(
      `on: push
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      db:
        image: postgres:16
    steps:
      - uses: actions/checkout@v4
`,
    );
    assert.equal(scan.format, "github");
    assert.equal(scan.findings.length, 0);
  });
});

describe("copied secret files", () => {
  it("flags COPY and ADD of secret files", () => {
    const scan = scanIac(
      `FROM nginx:1.27
USER nginx
COPY .env /app/.env
COPY id_rsa /root/.ssh/id_rsa
COPY id_ed25519 /root/.ssh/id_ed25519
ADD certs/app.pem /etc/ssl/app.pem
COPY config/credentials /run/credentials
COPY ["id_rsa", "/root/.ssh/id_rsa"]
`,
    );
    const secrets = scan.findings.filter((finding) => finding.ruleId === "DF004");
    assert.equal(secrets.length, 6);
    assert.equal(secrets[0]?.title, "Secret file copied into the image");
    assert.equal(secrets[0]?.severity, "high");
    assert.equal(secrets[0]?.category, "security");
    assert.equal(scan.findings.some((finding) => finding.ruleId === "DF001"), false);
  });

  it("clears COPY package.json and ignores comments", () => {
    const scan = scanIac(
      `FROM nginx:1.27
USER nginx
COPY package.json /app/package.json
# COPY .env /app/.env
# ADD id_rsa /root/.ssh/id_rsa
`,
    );
    assert.equal(scan.format, "dockerfile");
    assert.equal(scan.findings.some((finding) => finding.ruleId === "DF004"), false);
    assert.equal(scan.findings.some((finding) => finding.ruleId === "DF001"), false);
  });
});

describe("printed workflow secrets", () => {
  it("flags a run script that echoes a secrets expression", () => {
    const scan = scanIac(
      `on: push
jobs:
  build:
    steps:
      - run: echo \${{ secrets.API_KEY }}
`,
    );
    const printed = scan.findings.find((finding) => finding.ruleId === "GH004");
    assert.equal(printed?.title, "Workflow prints a secret");
    assert.equal(printed?.severity, "high");
    assert.equal(printed?.category, "security");
    assert.equal(scan.format, "github");
  });

  it("clears a normal echo and a secret that is only mapped into env", () => {
    const hello = scanIac(
      `on: push
jobs:
  build:
    steps:
      - run: echo "hello"
`,
    );
    assert.equal(hello.findings.some((finding) => finding.ruleId === "GH004"), false);
    const mapped = scanIac(
      `on: push
jobs:
  build:
    steps:
      - name: build
        env:
          TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: echo "hello"
`,
    );
    assert.equal(mapped.format, "github");
    assert.equal(mapped.findings.some((finding) => finding.ruleId === "GH004"), false);
    assert.equal(mapped.findings.some((finding) => finding.ruleId === "GH001"), false);
  });
});

const helmWarning =
  "Helm templates are not executed. Only literal text outside comments is checked.";
const ansibleWarning =
  "Ansible facts are not executed. Only literal text outside comments is checked.";

describe("Helm templates", () => {
  it("flags privileged, hostNetwork, latest, and docker.sock outside comments", () => {
    const scan = scanIac(
      `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.name }}
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
      volumes:
        - name: docker
          hostPath:
            path: /var/run/docker.sock
`,
      { format: "auto" },
    );
    assert.equal(scan.format, "helm");
    assert.ok(scan.warnings.includes(helmWarning));
    assert.equal(
      scan.findings.find((finding) => finding.ruleId === "HELM001")?.title,
      "Privileged container in a Helm template",
    );
    assert.equal(
      scan.findings.find((finding) => finding.ruleId === "HELM001")?.severity,
      "critical",
    );
    assert.equal(scan.findings.some((finding) => finding.ruleId === "HELM002"), true);
    assert.equal(scan.findings.some((finding) => finding.ruleId === "HELM003"), true);
    assert.equal(scan.findings.some((finding) => finding.ruleId === "HELM004"), true);
    assert.equal(scanIac(
      `apiVersion: v1
kind: Pod
metadata:
  name: {{ .Values.name }}
spec:
  containers:
    - name: app
      image: nginx:1.27
      # privileged: true
      # hostNetwork: true
      # image: nginx:latest
      # hostPath: /var/run/docker.sock
`,
    ).findings.filter((finding) => finding.ruleId.startsWith("HELM")).length, 0);
  });

  it("keeps a rendered manifest as kubernetes and clears a replicas-only template", () => {
    const rendered = scanIac(
      `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: nginx:1.27
`,
      { format: "auto" },
    );
    assert.equal(rendered.format, "kubernetes");
    const clear = scanIac(
      `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.name }}
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.27
`,
    );
    assert.equal(clear.format, "helm");
    assert.equal(
      clear.findings.filter((finding) => finding.ruleId.startsWith("HELM")).length,
      0,
    );
    const commentedMarker = scanIac(
      `apiVersion: apps/v1
kind: ConfigMap
metadata:
  name: app
# {{ .Values.unused }}
data:
  note: kept
`,
    );
    assert.equal(commentedMarker.format, "kubernetes");
  });
});

describe("Ansible playbooks", () => {
  it("flags become true or yes and a public cidr outside comments", () => {
    const scan = scanIac(
      `- hosts: all
  tasks:
    - name: open
      become: true
      ansible.builtin.firewalld:
        source: 0.0.0.0/0
`,
      { format: "auto" },
    );
    assert.equal(scan.format, "ansible");
    assert.ok(scan.warnings.includes(ansibleWarning));
    const root = scan.findings.find((finding) => finding.ruleId === "ANS001");
    assert.equal(root?.title, "Ansible task runs as root");
    assert.equal(root?.severity, "high");
    assert.equal(root?.category, "security");
    const exposure = scan.findings.find((finding) => finding.ruleId === "ANS002");
    assert.equal(exposure?.title, "Broad network exposure");
    assert.equal(exposure?.severity, "high");
    const play = scanIac(
      `hosts: all
become: yes
tasks:
  - name: show
    ansible.builtin.debug:
      msg: hi
`,
    );
    assert.equal(play.format, "ansible");
    assert.equal(play.findings.filter((finding) => finding.ruleId === "ANS001").length, 1);
    const commented = scanIac(
      `- hosts: all
  tasks:
    - name: note
      ansible.builtin.debug:
        msg: ok
  # source: 0.0.0.0/0
  # become: true
`,
    );
    assert.equal(commented.findings.length, 0);
  });

  it("clears a play with become false and no public cidr", () => {
    const scan = scanIac(
      `- hosts: web
  become: false
  tasks:
    - name: ping
      ansible.builtin.ping:
`,
      { format: "ansible" },
    );
    assert.equal(scan.format, "ansible");
    assert.equal(scan.findings.length, 0);
    assert.ok(scan.warnings.includes(ansibleWarning));
  });
});

describe("image and workflow secret assignment", () => {
  it("flags a literal secret in Dockerfile ENV or ARG", () => {
    const scan = scanIac(
      `FROM nginx:1.27
USER nginx
ENV NODE_ENV=production
ENV PATH=/usr/bin
ARG VERSION=1
ENV PASSWORD=hunter2
ENV API_KEY=abcd
ARG apikey=abcd
ENV AUTH_TOKEN=abcd
ENV ACCESS_KEY=abcd
ENV PRIVATE_KEY=abcd
ENV TOKEN=literal
ENV SECRET=literal
`,
    );
    const secrets = scan.findings.filter((finding) => finding.ruleId === "DF005");
    assert.equal(secrets.length, 8);
    assert.equal(secrets[0]?.title, "Secret assigned in an image variable");
    assert.equal(secrets[0]?.severity, "high");
    assert.equal(secrets[0]?.category, "security");
    assert.equal(scan.findings.some((finding) => finding.ruleId === "DF001"), false);
  });

  it("clears safe image variables, shell references, and comments", () => {
    const scan = scanIac(
      `FROM nginx:1.27
USER nginx
ENV NODE_ENV=production
ENV PATH=/usr/bin
ARG VERSION=1
ENV TOKEN=$TOKEN
ENV TOKEN=\${TOKEN}
ARG PASSWORD
# ENV PASSWORD=hunter2
# ARG TOKEN=literal
`,
    );
    assert.equal(scan.format, "dockerfile");
    assert.equal(scan.findings.some((finding) => finding.ruleId === "DF005"), false);
  });

  it("flags a literal workflow env value and keeps printed-secret checks", () => {
    const scan = scanIac(
      `on: push
jobs:
  build:
    steps:
      - env:
          TOKEN: literal-secret
          API_KEY: abcd
        run: echo "hello"
`,
    );
    const assigned = scan.findings.filter((finding) => finding.ruleId === "GH005");
    assert.equal(assigned.length, 2);
    assert.equal(assigned[0]?.title, "Secret assigned in workflow env");
    assert.equal(assigned[0]?.severity, "high");
    assert.equal(assigned[0]?.category, "security");
    assert.equal(scan.findings.some((finding) => finding.ruleId === "GH004"), false);
  });

  it("clears secrets expressions, github.token, empty env, and a hello echo", () => {
    const scan = scanIac(
      `on: push
env:
  TOKEN: \${{ secrets.TOKEN }}
jobs:
  build:
    env:
      API_KEY: \${{ github.token }}
      PASSWORD: ""
    steps:
      - run: echo "hello"
`,
    );
    assert.equal(scan.format, "github");
    assert.equal(scan.findings.some((finding) => finding.ruleId === "GH005"), false);
    assert.equal(scan.findings.some((finding) => finding.ruleId === "GH004"), false);
  });
});

const azureWarning = "Bicep modules and ARM expressions are not evaluated.";

describe("Bicep and ARM templates", () => {
  it("flags open source prefixes and public network access on Bicep resources", () => {
    const scan = scanIac(
      `resource store 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'store'
  properties: {
    publicNetworkAccess: 'Enabled'
  }
}
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  properties: {
    securityRules: [
      {
        name: 'open'
        properties: {
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '0.0.0.0/0'
        }
      }
    ]
  }
}
`,
      { format: "auto" },
    );
    assert.equal(scan.format, "bicep");
    assert.ok(scan.warnings.includes(azureWarning));
    const exposure = scan.findings.find((finding) => finding.ruleId === "AZ001");
    const access = scan.findings.find((finding) => finding.ruleId === "AZ002");
    assert.equal(exposure?.title, "Broad network exposure");
    assert.equal(exposure?.severity, "high");
    assert.equal(exposure?.category, "security");
    assert.equal(access?.title, "Database or storage allows public network access");
    assert.equal(access?.severity, "high");
    assert.equal(access?.category, "security");
  });

  it("keeps a Terraform resource block as terraform", () => {
    const scan = scanIac(
      `resource "azurerm_storage_account" "example" {
  name = "example"
  public_network_access_enabled = true
}
`,
    );
    assert.equal(scan.format, "terraform");
    assert.equal(scan.findings.some((finding) => finding.ruleId === "AZ002"), false);
  });

  it("clears egress destinations, disabled access, and comments", () => {
    const scan = scanIac(
      `resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  properties: {
    securityRules: [
      {
        properties: {
          direction: 'Outbound'
          destinationAddressPrefix: '*'
          sourceAddressPrefix: '10.0.0.0/24'
        }
      }
    ]
  }
}
resource db 'Microsoft.Sql/servers@2021-11-01' = {
  properties: {
    publicNetworkAccess: 'Disabled'
  }
}
// sourceAddressPrefix: '*'
/* publicNetworkAccess: 'Enabled' */
`,
      { format: "bicep" },
    );
    assert.equal(scan.format, "bicep");
    assert.equal(scan.findings.length, 0);
    assert.ok(scan.warnings.includes(azureWarning));
  });

  it("detects an ARM template and does not steal Terraform JSON or CloudFormation", () => {
    const arm = scanIac(
      `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Sql/servers",
      "apiVersion": "2021-11-01",
      "name": "db",
      "properties": {
        "publicNetworkAccess": "Enabled"
      }
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "apiVersion": "2023-05-01",
      "name": "nsg",
      "properties": {
        "securityRules": [
          {
            "properties": {
              "direction": "Inbound",
              "sourceAddressPrefixes": ["0.0.0.0/0"]
            }
          }
        ]
      }
    }
  ]
}
`,
    );
    assert.equal(arm.format, "arm");
    assert.ok(arm.warnings.includes(azureWarning));
    assert.equal(
      arm.findings.find((finding) => finding.ruleId === "AZ002")?.title,
      "Database or storage allows public network access",
    );
    assert.equal(
      arm.findings.find((finding) => finding.ruleId === "AZ001")?.title,
      "Broad network exposure",
    );
    const byVersion = scanIac(
      `{
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "store",
      "properties": { "publicNetworkAccess": true }
    }
  ]
}
`,
      { format: "arm" },
    );
    assert.equal(byVersion.format, "arm");
    assert.equal(byVersion.findings.some((finding) => finding.ruleId === "AZ002"), true);
    const terraform = scanIac(
      `{
  "resource": {
    "aws_s3_bucket": {
      "example": { "bucket": "example" }
    }
  }
}
`,
    );
    assert.equal(terraform.format, "terraform");
    const cloudformation = scanIac(
      `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Bucket": { "Type": "AWS::S3::Bucket", "Properties": {} }
  }
}
`,
    );
    assert.equal(cloudformation.format, "cloudformation");
  });
});

describe("pipeline, module, and tfvars scanning", () => {
  const pipelineWarning =
    "The pipeline is not executed. Only literal text outside comments is checked.";

  it("scans GitLab CI, Azure Pipelines, and Cloud Build without stealing other formats", () => {
    const gitlab = scanIac(`stages:
  - test
image: nginx:latest
# privileged: true
test_job:
  stage: test
  image: node:20
  script:
    - echo hello
    - echo $CI_JOB_TOKEN
    - echo "\${secrets.TOKEN}"
  services:
    - name: nginx
privileged: true
`);
    assert.equal(gitlab.format, "gitlab");
    assert.ok(gitlab.warnings.includes(pipelineWarning));
    assert.equal(
      gitlab.findings.filter((finding) => finding.ruleId === "PIPE001").length,
      1,
    );
    assert.equal(
      gitlab.findings.find((finding) => finding.ruleId === "PIPE001")?.title,
      "Unpinned container image",
    );
    assert.equal(
      gitlab.findings.find((finding) => finding.ruleId === "PIPE001")?.severity,
      "medium",
    );
    assert.equal(
      gitlab.findings.filter((finding) => finding.ruleId === "PIPE002").length,
      1,
    );
    assert.equal(
      gitlab.findings.find((finding) => finding.ruleId === "PIPE002")?.title,
      "Pipeline prints a secret",
    );
    assert.equal(
      gitlab.findings.find((finding) => finding.ruleId === "PIPE002")?.severity,
      "high",
    );
    assert.equal(
      gitlab.findings.find((finding) => finding.ruleId === "PIPE003")?.title,
      "Elevated container privileges",
    );
    assert.equal(
      gitlab.findings.find((finding) => finding.ruleId === "PIPE003")?.severity,
      "critical",
    );

    const clearGitlab = scanIac(
      "stages:\n  - test\nimage: node:20\njob:\n  script:\n    - echo hello\n",
      { format: "gitlab" },
    );
    assert.equal(clearGitlab.format, "gitlab");
    assert.equal(
      clearGitlab.findings.filter((finding) => finding.ruleId.startsWith("PIPE")).length,
      0,
    );

    const azure = scanIac(`trigger:
  - main
pool:
  vmImage: ubuntu-latest
steps:
  - script: echo hello
  - bash: echo $(secretValue)
    privileged: true
container:
  image: nginx:latest
`);
    assert.equal(azure.format, "azure-pipelines");
    assert.ok(azure.warnings.includes(pipelineWarning));
    assert.equal(azure.findings.some((finding) => finding.ruleId === "PIPE001"), true);
    assert.equal(azure.findings.some((finding) => finding.ruleId === "PIPE002"), true);
    assert.equal(azure.findings.some((finding) => finding.ruleId === "PIPE003"), true);
    const clearAzure = scanIac(
      "pool:\n  vmImage: ubuntu-latest\nsteps:\n  - script: echo hello\n",
      { format: "azure-pipelines" },
    );
    assert.equal(clearAzure.findings.some((finding) => finding.title === "Pipeline prints a secret"), false);
    assert.equal(clearAzure.findings.some((finding) => finding.title === "Unpinned container image"), false);

    const cloudBuild = scanIac(`steps:
  - name: nginx:latest
    args: ['-c', 'echo $TOKEN']
  - name: node:20
    args: ['echo', 'hello']
# privileged: true
`);
    assert.equal(cloudBuild.format, "cloudbuild");
    assert.ok(cloudBuild.warnings.includes(pipelineWarning));
    assert.equal(
      cloudBuild.findings.filter((finding) => finding.ruleId === "PIPE001").length,
      1,
    );
    assert.equal(
      cloudBuild.findings.filter((finding) => finding.ruleId === "PIPE002").length,
      1,
    );
    assert.equal(cloudBuild.findings.some((finding) => finding.ruleId === "PIPE003"), false);

    const github = scanIac(`on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`);
    assert.equal(github.format, "github");

    const compose = scanIac("services:\n  web:\n    image: nginx:latest\n");
    assert.equal(compose.format, "compose");
    const kubernetes = scanIac(
      "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: web\n      image: nginx:latest\n",
    );
    assert.equal(kubernetes.format, "kubernetes");
    const helm = scanIac("apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Release.Name }}\n");
    assert.equal(helm.format, "helm");
    const ansible = scanIac("hosts: all\ntasks:\n  - name: ping\n    ping:\n");
    assert.equal(ansible.format, "ansible");
  });

  it("scans Terraform module arguments without loading the module", () => {
    const scan = scanIac(`module "edge" {
  source = "./modules/edge"
  cidr = "0.0.0.0/0"
  publicly_accessible = true
  egress = "0.0.0.0/0"
  destination = "::/0"
  ipv6_egress = "::/0"
}
module "clear" {
  source = "./modules/clear"
  # cidr = "0.0.0.0/0"
  cidr = "10.0.0.0/24"
}
`);
    assert.equal(scan.format, "terraform");
    assert.ok(scan.warnings.some((warning) => warning.includes("module body was not loaded")));
    assert.equal(scan.findings.filter((finding) => finding.ruleId === "NET001").length, 1);
    assert.equal(
      scan.findings.find((finding) => finding.ruleId === "NET001")?.title,
      "Broad network exposure",
    );
    assert.equal(scan.findings.filter((finding) => finding.ruleId === "DB001").length, 1);
    assert.equal(
      scan.findings.find((finding) => finding.ruleId === "DB001")?.title,
      "Database publicly accessible",
    );
  });

  it("scans tfvars assignments and Terraform variable defaults", () => {
    const tfvars = scanIac(`cidr = "0.0.0.0/0"
egress = "::/0"
publicly_accessible = true
password = "hunter2"
token = var.token
empty = ""
environment = "prod"
# api_key = "hidden"
ok = "10.0.0.0/24"
`);
    assert.equal(tfvars.format, "tfvars");
    assert.equal(tfvars.findings.filter((finding) => finding.ruleId === "NET001").length, 1);
    assert.equal(tfvars.findings.filter((finding) => finding.ruleId === "DB001").length, 1);
    assert.equal(tfvars.findings.filter((finding) => finding.ruleId === "TF001").length, 1);
    assert.equal(
      tfvars.findings.find((finding) => finding.ruleId === "TF001")?.title,
      "Secret assigned in a Terraform variable",
    );
    const requested = scanIac('environment = "prod"\n', { format: "tfvars" });
    assert.equal(requested.format, "tfvars");
    assert.equal(requested.findings.length, 0);

    const variables = scanIac(`variable "password" {
  default = "hunter2"
}
variable "cidr" {
  default = "0.0.0.0/0"
}
variable "ok" {
  default = "10.0.0.0/24"
}
variable "ref" {
  default = var.password
}
variable "empty" {
  default = ""
}
variable "environment" {
  default = "prod"
}
variable "egress" {
  default = "::/0"
}
`);
    assert.equal(variables.format, "terraform");
    assert.equal(variables.findings.filter((finding) => finding.ruleId === "TF001").length, 1);
    assert.equal(variables.findings.filter((finding) => finding.ruleId === "NET001").length, 1);
    assert.equal(variables.findings.some((finding) => finding.ruleId === "DB001"), false);
  });
});
