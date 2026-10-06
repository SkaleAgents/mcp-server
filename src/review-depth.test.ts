import assert from "node:assert/strict";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { scanIac } from "./iac/scan.js";
import { exactLineEdit, rankFindings } from "./review-edits.js";
import { createServer } from "./server.js";

const publicDatabase = `resource "aws_db_instance" "app" {
  publicly_accessible = true
}
`;

type ReviewFinding = {
  title: string;
  severity: string;
  proposedChange?: { from: string; to: string | null; diff: string };
};

async function callTool(name: string, args: Record<string, unknown>) {
  const previous = process.env.PLATFORM_API_URL;
  process.env.PLATFORM_API_URL = "http://127.0.0.1:9";
  const server = createServer(true);
  const client = new Client({ name: "review-depth-test", version: "1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    return await client.callTool({ name, arguments: args });
  } finally {
    await client.close();
    await server.close();
    if (previous === undefined) delete process.env.PLATFORM_API_URL;
    else process.env.PLATFORM_API_URL = previous;
  }
}

function outputOf(result: Awaited<ReturnType<typeof callTool>>) {
  const text = result.content?.[0]?.text;
  assert.equal(typeof text, "string");
  const output = JSON.parse(text) as {
    summary?: string;
    findings?: ReviewFinding[];
    priority?: ReviewFinding[];
    content?: string;
  };
  assert.deepEqual(result.structuredContent, output);
  return { text, output };
}

test("ranks findings by severity and keeps the original order within a severity", () => {
  const findings = [
    { title: "low first", severity: "low" },
    { title: "high later", severity: "high" },
    { title: "high earlier", severity: "high" },
    { title: "critical", severity: "critical" },
    { title: "medium", severity: "medium" },
    { title: "info", severity: "info" },
  ];
  const ranked = rankFindings(findings);
  assert.deepEqual(ranked.map((finding) => finding.title), [
    "critical",
    "high later",
    "high earlier",
    "medium",
    "low first",
    "info",
  ]);
  assert.deepEqual(rankFindings(findings), ranked);
});

test("public database line proposes the exact change and a nearby line does not", async () => {
  const edit = exactLineEdit(publicDatabase, "Database publicly accessible");
  assert.equal(edit?.from, "  publicly_accessible = true");
  assert.equal(edit?.to, "  publicly_accessible = false");
  assert.equal(exactLineEdit('publicly_accessible = "true"', "Database publicly accessible"), null);
  assert.equal(exactLineEdit("publicly_accessible = true # temporary", "Database publicly accessible"), null);

  for (const name of ["review_architecture", "scan_iac"]) {
    const { text, output } = outputOf(await callTool(name, { content: publicDatabase, format: "terraform" }));
    const finding = output.findings?.find((item) => item.title === "Database publicly accessible");
    assert.ok(finding?.proposedChange);
    assert.equal(finding.proposedChange.from, "  publicly_accessible = true");
    assert.equal(finding.proposedChange.to, "  publicly_accessible = false");
    assert.match(finding.proposedChange.diff, /^- {2}publicly_accessible = true$/m);
    assert.match(finding.proposedChange.diff, /^\+ {2}publicly_accessible = false$/m);
    assert.equal(output.priority?.[0]?.title, "Database publicly accessible");
    assert.equal(output.priority?.[0]?.proposedChange?.to, "  publicly_accessible = false");
    assert.equal(
      output.summary,
      "Fix these first: Database publicly accessible: publicly_accessible = true becomes publicly_accessible = false.",
    );
    assert.equal(output.content, undefined);
    assert.equal(text.includes(publicDatabase), false);
  }

  for (const content of ['publicly_accessible = "true"\n', "publicly_accessible = true # temporary\n"]) {
    const { text, output } = outputOf(await callTool("scan_iac", { content, format: "terraform" }));
    assert.equal(text.includes("proposedChange"), false);
    assert.deepEqual(output.findings, []);
    assert.deepEqual(output.priority, []);
    assert.equal(output.summary, "No findings. That does not prove the system is secure.");
  }
});

test("keeps scan ranking stable and omits a proposed change when the title has no rule", async () => {
  const content = `resource "aws_db_instance" "app" {
  publicly_accessible = true
  backup_retention_period = 0
  deletion_protection = false
  storage_encrypted = false
}
`;
  const first = outputOf(await callTool("scan_iac", { content, format: "terraform" }));
  const second = outputOf(await callTool("scan_iac", { content, format: "terraform" }));
  assert.deepEqual(
    first.output.findings?.map((finding) => finding.title),
    second.output.findings?.map((finding) => finding.title),
  );
  assert.deepEqual(
    first.output.priority?.map((finding) => finding.title),
    second.output.priority?.map((finding) => finding.title),
  );
  assert.deepEqual(first.output.priority?.map((finding) => finding.title), [
    "Storage encryption disabled",
    "Database publicly accessible",
    "Database backups disabled",
  ]);
  const backups = first.output.findings?.find((finding) => finding.title === "Database backups disabled");
  assert.ok(backups);
  assert.equal("proposedChange" in backups, false);
  assert.equal(first.output.priority?.[2] && "proposedChange" in first.output.priority[2], false);
  assert.match(first.output.summary ?? "", /^Fix these first: /);
  assert.match(first.output.summary ?? "", /publicly_accessible = true becomes publicly_accessible = false/);
  assert.equal(first.text.includes(content), false);

  const application = outputOf(await callTool("review_architecture", {
    content: 'export const endpoint = "http://example.com";',
    format: "application",
  }));
  const httpFinding = application.output.findings?.find((finding) => finding.title === "Unencrypted HTTP endpoint");
  assert.ok(httpFinding);
  assert.equal("proposedChange" in httpFinding, false);
});

test("empty input still fails validation", async () => {
  const result = await callTool("scan_iac", { content: "", format: "terraform" });
  assert.equal(result.isError, true);
  assert.match(String(result.content?.[0]?.text), /Too small: expected string to have >=1 characters at content/);
  assert.equal(result.structuredContent, undefined);
});

test("scanIac keeps its persisted summary and finding shape", () => {
  const scan = scanIac(publicDatabase);
  assert.match(scan.summary, /^Scanned /);
  assert.equal("priority" in scan, false);
  assert.equal(scan.findings.some((finding) => "proposedChange" in finding), false);
});
