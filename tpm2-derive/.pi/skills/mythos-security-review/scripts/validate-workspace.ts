#!/usr/bin/env -S deno run --allow-read

/**
 * validate-workspace.ts
 *
 * Checks that a hunt workspace has the expected structure and that validated
 * findings contain the minimum fields needed for final packaging.
 *
 * Usage:
 *   deno run --allow-read scripts/validate-workspace.ts ./.mythos-review/YYYY-MM-DD-slug
 *   deno run --allow-read scripts/validate-workspace.ts ./.mythos-review/YYYY-MM-DD-slug --json
 */

type Result = {
  ok: boolean;
  errors: string[];
  warnings: string[];
};

function usage() {
  console.log(`validate-workspace.ts

Usage:
  deno run --allow-read scripts/validate-workspace.ts <workspace> [--json]
`);
}

function parseArgs(args: string[]) {
  if (args.includes("--help") || args.includes("-h")) {
    usage();
    Deno.exit(0);
  }
  const json = args.includes("--json");
  const workspace = args.find((arg) => !arg.startsWith("--")) || "";
  if (!workspace) {
    usage();
    Deno.exit(1);
  }
  return { workspace, json };
}

function field(text: string, label: string): string {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = text.match(new RegExp(`^- ${escaped}:\\s*(.*)$`, "mi"));
  return match?.[1]?.trim() ?? "";
}

async function exists(path: string) {
  try {
    await Deno.stat(path);
    return true;
  } catch {
    return false;
  }
}

async function validateWorkspace(workspace: string): Promise<Result> {
  const errors: string[] = [];
  const warnings: string[] = [];

  const requiredPaths = [
    `${workspace}/hunt-charter.md`,
    `${workspace}/run-manifest.json`,
    `${workspace}/briefs`,
    `${workspace}/candidates`,
    `${workspace}/validated`,
    `${workspace}/handoffs`,
    `${workspace}/reports`,
    `${workspace}/ledgers/finding-ledger.md`,
  ];

  for (const path of requiredPaths) {
    if (!(await exists(path))) {
      errors.push(`missing required path: ${path}`);
    }
  }

  const validatedDir = `${workspace}/validated`;
  if (await exists(validatedDir)) {
    for await (const entry of Deno.readDir(validatedDir)) {
      if (!entry.isFile || !entry.name.endsWith(".md")) continue;
      const path = `${validatedDir}/${entry.name}`;
      const text = await Deno.readTextFile(path);
      const requiredFields = [
        "ID",
        "Title",
        "Severity",
        "Confidence",
        "Root Cause Key",
        "Component",
        "Path(s)",
        "Proof method",
        "Observed result",
        "Oracle used",
        "Why fix now",
      ];
      for (const label of requiredFields) {
        if (!field(text, label)) {
          errors.push(`${path}: missing field '${label}'`);
        }
      }
    }
  }

  const candidateDir = `${workspace}/candidates`;
  if (await exists(candidateDir)) {
    let count = 0;
    for await (const entry of Deno.readDir(candidateDir)) {
      if (entry.isFile && entry.name.endsWith(".md")) count += 1;
    }
    if (count === 0) {
      warnings.push("no candidate findings present");
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

async function main() {
  const { workspace, json } = parseArgs(Deno.args);
  const result = await validateWorkspace(workspace);

  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`# Workspace Validation\n`);
    console.log(`Status: ${result.ok ? "OK" : "FAILED"}`);
    if (result.errors.length) {
      console.log("\n## Errors");
      for (const error of result.errors) console.log(`- ${error}`);
    }
    if (result.warnings.length) {
      console.log("\n## Warnings");
      for (const warning of result.warnings) console.log(`- ${warning}`);
    }
  }

  if (!result.ok) Deno.exit(1);
}

main();
