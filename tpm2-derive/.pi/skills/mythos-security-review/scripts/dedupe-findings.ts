#!/usr/bin/env -S deno run --allow-read --allow-write

/**
 * dedupe-findings.ts
 *
 * Scans candidate and validated finding markdown files and groups likely
 * duplicates by root-cause key or normalized title/component/path.
 *
 * Usage:
 *   deno run --allow-read scripts/dedupe-findings.ts ./.mythos-review/YYYY-MM-DD-slug
 *   deno run --allow-read scripts/dedupe-findings.ts ./.mythos-review/YYYY-MM-DD-slug --json
 *   deno run --allow-read --allow-write scripts/dedupe-findings.ts ./.mythos-review/YYYY-MM-DD-slug --output ./.mythos-review/YYYY-MM-DD-slug/reports/deduped-findings.md
 */

type Finding = {
  file: string;
  stage: "candidate" | "validated";
  id: string;
  title: string;
  component: string;
  paths: string;
  severity: string;
  confidence: string;
  rootCauseKey: string;
};

function usage() {
  console.log(`dedupe-findings.ts

Usage:
  deno run --allow-read [--allow-write] scripts/dedupe-findings.ts <workspace> [--json] [--output FILE]
`);
}

function parseArgs(args: string[]) {
  if (args.includes("--help") || args.includes("-h")) {
    usage();
    Deno.exit(0);
  }

  const outputIndex = args.indexOf("--output");
  const json = args.includes("--json");
  const output = outputIndex !== -1 ? args[outputIndex + 1] : "";

  const consumed = new Set<number>();
  if (outputIndex !== -1) {
    consumed.add(outputIndex);
    consumed.add(outputIndex + 1);
  }

  let workspace = "";
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith("--") && !consumed.has(i)) {
      workspace = args[i];
      break;
    }
  }

  if (!workspace) {
    usage();
    Deno.exit(1);
  }

  return { workspace, json, output };
}

async function* walk(dir: string): AsyncGenerator<string> {
  try {
    for await (const entry of Deno.readDir(dir)) {
      const path = `${dir}/${entry.name}`;
      if (entry.isDirectory) {
        yield* walk(path);
      } else if (entry.isFile && path.endsWith(".md")) {
        yield path;
      }
    }
  } catch {
    // ignore missing dirs
  }
}

function field(text: string, label: string): string {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = text.match(new RegExp(`^- ${escaped}:\\s*(.*)$`, "mi"));
  return match?.[1]?.trim() ?? "";
}

function normalize(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 120);
}

async function parseFinding(path: string, stage: "candidate" | "validated"): Promise<Finding | null> {
  const text = await Deno.readTextFile(path);
  const id = field(text, "ID");
  const title = field(text, "Title");
  const component = field(text, "Component");
  const paths = field(text, "Path(s)");
  const severity = field(text, "Severity");
  const confidence = field(text, "Confidence");
  const rootCauseKey = field(text, "Root Cause Key");

  if (!id && !title && !component && !paths) return null;
  return { file: path, stage, id, title, component, paths, severity, confidence, rootCauseKey };
}

function groupingKey(finding: Finding) {
  if (finding.rootCauseKey) return normalize(finding.rootCauseKey);
  return normalize(`${finding.title}|${finding.component}|${finding.paths}`);
}

function formatMarkdown(groups: Record<string, Finding[]>) {
  const lines = [
    "# Deduped Findings",
    "",
    "| Group | Count | Stages | Representative Title | Files |",
    "|-------|-------|--------|----------------------|-------|",
  ];

  for (const [key, findings] of Object.entries(groups).sort((a, b) => b[1].length - a[1].length)) {
    const representative = findings[0]?.title || findings[0]?.component || key;
    const stages = [...new Set(findings.map((f) => f.stage))].join(", ");
    const files = findings.map((f) => f.file).join("<br>");
    lines.push(`| ${key} | ${findings.length} | ${stages} | ${representative} | ${files} |`);
  }
  return lines.join("\n");
}

async function main() {
  const { workspace, json, output } = parseArgs(Deno.args);
  const findings: Finding[] = [];

  for (const [dir, stage] of [[`${workspace}/candidates`, "candidate"], [`${workspace}/validated`, "validated"]] as const) {
    for await (const path of walk(dir)) {
      const finding = await parseFinding(path, stage);
      if (finding) findings.push(finding);
    }
  }

  const groups: Record<string, Finding[]> = {};
  for (const finding of findings) {
    const key = groupingKey(finding);
    groups[key] ??= [];
    groups[key].push(finding);
  }

  const rendered = json ? JSON.stringify(groups, null, 2) : formatMarkdown(groups);
  if (output) {
    await Deno.writeTextFile(output, rendered);
  }
  console.log(rendered);
}

main();
