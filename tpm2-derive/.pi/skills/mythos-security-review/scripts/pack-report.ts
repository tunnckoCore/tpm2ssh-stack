#!/usr/bin/env -S deno run --allow-read --allow-write

/**
 * pack-report.ts
 *
 * Builds a markdown summary report from canonical validated findings and links
 * optional remediation handoffs by finding ID.
 *
 * Usage:
 *   deno run --allow-read scripts/pack-report.ts ./.mythos-review/YYYY-MM-DD-slug
 *   deno run --allow-read --allow-write scripts/pack-report.ts ./.mythos-review/YYYY-MM-DD-slug --title "Auth Service Hunt" --output ./.mythos-review/YYYY-MM-DD-slug/reports/final-report.md
 */

type Finding = {
  id: string;
  file: string;
  title: string;
  severity: string;
  confidence: string;
  rootCauseKey: string;
  component: string;
  paths: string;
  whyFixNow: string;
  handoffPath?: string;
};

function usage() {
  console.log(`pack-report.ts

Usage:
  deno run --allow-read [--allow-write] scripts/pack-report.ts <hunt-root> [--title TITLE] [--output FILE]
`);
}

function parseArgs(args: string[]) {
  if (args.includes("--help") || args.includes("-h")) {
    usage();
    Deno.exit(0);
  }

  const titleIndex = args.indexOf("--title");
  const outputIndex = args.indexOf("--output");
  const title = titleIndex !== -1 ? args[titleIndex + 1] : "Mythos Security Review Report";
  const output = outputIndex !== -1 ? args[outputIndex + 1] : "";

  const consumed = new Set<number>();
  for (const index of [titleIndex, outputIndex]) {
    if (index !== -1) {
      consumed.add(index);
      consumed.add(index + 1);
    }
  }

  let root = "";
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith("--") && !consumed.has(i)) {
      root = args[i];
      break;
    }
  }

  if (!root) {
    usage();
    Deno.exit(1);
  }

  return { root, title, output };
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

async function parseValidatedFinding(path: string): Promise<Finding | null> {
  const text = await Deno.readTextFile(path);
  if (!text.startsWith("# Validated Finding")) return null;

  const finding: Finding = {
    id: field(text, "ID"),
    file: path,
    title: field(text, "Title"),
    severity: field(text, "Severity"),
    confidence: field(text, "Confidence"),
    rootCauseKey: field(text, "Root Cause Key"),
    component: field(text, "Component"),
    paths: field(text, "Path(s)"),
    whyFixNow: field(text, "Why fix now"),
  };

  if (!finding.id || !finding.title) return null;
  return finding;
}

async function collectHandoffs(dir: string) {
  const handoffs = new Map<string, string>();
  for await (const path of walk(dir)) {
    const text = await Deno.readTextFile(path);
    if (!text.startsWith("# Remediation Handoff")) continue;
    const id = field(text, "ID");
    if (id) handoffs.set(id, path);
  }
  return handoffs;
}

function countBy(findings: Finding[], key: keyof Finding) {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    const value = (finding[key] || "unknown").toString();
    counts[value] = (counts[value] || 0) + 1;
  }
  return counts;
}

function renderCounts(title: string, counts: Record<string, number>) {
  const lines = [`## ${title}`, ""];
  for (const [key, value] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
    lines.push(`- ${key}: ${value}`);
  }
  lines.push("");
  return lines.join("\n");
}

function renderReport(title: string, findings: Finding[]) {
  const lines = [`# ${title}`, "", `Generated: ${new Date().toISOString()}`, ""];

  lines.push("## Summary", "", `- Total validated findings: ${findings.length}`, "");
  lines.push(renderCounts("By Severity", countBy(findings, "severity")));
  lines.push(renderCounts("By Confidence", countBy(findings, "confidence")));

  lines.push("## Findings", "", "| ID | Severity | Confidence | Title | Component | Path(s) | Handoff |", "|----|----------|------------|-------|-----------|---------|---------|");
  for (const finding of findings) {
    lines.push(`| ${finding.id} | ${finding.severity || "unknown"} | ${finding.confidence || "unknown"} | ${finding.title || "(untitled)"} | ${finding.component || ""} | ${finding.paths || ""} | ${finding.handoffPath || ""} |`);
  }

  lines.push("", "## Why fix now", "");
  for (const finding of findings) {
    lines.push(`### ${finding.id}: ${finding.title || finding.file}`);
    lines.push(finding.whyFixNow || "No rationale supplied.");
    lines.push("");
  }

  return lines.join("\n");
}

async function main() {
  const { root, title, output } = parseArgs(Deno.args);
  const findings: Finding[] = [];
  const handoffs = await collectHandoffs(`${root}/handoffs`);

  for await (const path of walk(`${root}/validated`)) {
    const finding = await parseValidatedFinding(path);
    if (!finding) continue;
    finding.handoffPath = handoffs.get(finding.id) || "";
    findings.push(finding);
  }

  const report = renderReport(title, findings);
  if (output) {
    await Deno.writeTextFile(output, report);
  }
  console.log(report);
}

main();
