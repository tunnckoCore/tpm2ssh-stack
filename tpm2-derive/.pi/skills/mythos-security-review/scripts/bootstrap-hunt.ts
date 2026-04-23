#!/usr/bin/env -S deno run --allow-read --allow-write

/**
 * bootstrap-hunt.ts
 *
 * Creates a self-contained hunt workspace from the skill templates so an
 * orchestrator agent can immediately start ranking hotspots, spawning subagents,
 * and collecting findings.
 *
 * Usage:
 *   deno run --allow-read --allow-write scripts/bootstrap-hunt.ts <target-name>
 *   deno run --allow-read --allow-write scripts/bootstrap-hunt.ts <target-name> --output-dir ./.mythos-review/<YYYY-MM-DD-slug>
 *   deno run --allow-read --allow-write scripts/bootstrap-hunt.ts <target-name> --target-path /abs/path/to/repo
 *   deno run --allow-read --allow-write scripts/bootstrap-hunt.ts <target-name> --refresh
 */

function usage() {
  console.log(`bootstrap-hunt.ts

Usage:
  deno run --allow-read --allow-write scripts/bootstrap-hunt.ts <target-name> [--output-dir DIR] [--target-path PATH] [--refresh]

Options:
  --output-dir DIR   Where to create the hunt workspace (default: ./.mythos-review/YYYY-MM-DD-slug)
  --target-path PATH Path to the codebase or binary under review
  --refresh          Allow overwriting run metadata when the target changes
`);
}

function sanitizeName(value: string) {
  return value.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "target";
}

function defaultRunDir(slug: string) {
  const date = new Date().toISOString().slice(0, 10);
  return `${Deno.cwd()}/.mythos-review/${date}-${slug}`;
}

function parseArgs(args: string[]) {
  if (args.includes("--help") || args.includes("-h")) {
    usage();
    Deno.exit(0);
  }

  const outputDirIndex = args.indexOf("--output-dir");
  const targetPathIndex = args.indexOf("--target-path");
  const outputDir = outputDirIndex !== -1 ? args[outputDirIndex + 1] : null;
  const targetPath = targetPathIndex !== -1 ? args[targetPathIndex + 1] : "";
  const refresh = args.includes("--refresh");

  const consumed = new Set<number>();
  for (const index of [outputDirIndex, targetPathIndex]) {
    if (index !== -1) {
      consumed.add(index);
      consumed.add(index + 1);
    }
  }

  let targetName = "";
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith("--") && !consumed.has(i)) {
      targetName = args[i];
      break;
    }
  }

  if (!targetName) {
    usage();
    Deno.exit(1);
  }

  const safeTargetName = sanitizeName(targetName);
  return {
    targetName: safeTargetName,
    outputDir: outputDir ?? defaultRunDir(safeTargetName),
    targetPath,
    refresh,
  };
}

async function readText(path: string) {
  return await Deno.readTextFile(path);
}

function fill(text: string, replacements: Record<string, string>) {
  let next = text;
  for (const [key, value] of Object.entries(replacements)) {
    next = next.replaceAll(key, value);
  }
  return next;
}

async function ensureDir(path: string) {
  await Deno.mkdir(path, { recursive: true });
}

async function exists(path: string) {
  try {
    await Deno.stat(path);
    return true;
  } catch {
    return false;
  }
}

async function writeTemplate(path: string, content: string, refresh = false) {
  if (!refresh && await exists(path)) return;
  await Deno.writeTextFile(path, content);
}

async function assertWorkspaceCompatibility(outputDir: string, targetName: string, targetPath: string, refresh: boolean) {
  const manifestPath = `${outputDir}/run-manifest.json`;
  if (!(await exists(manifestPath))) return;
  const manifest = JSON.parse(await readText(manifestPath));
  const sameName = manifest.target_name === targetName;
  const samePath = !targetPath || !manifest.target_path || manifest.target_path === targetPath;
  if ((!sameName || !samePath) && !refresh) {
    console.error(`Refusing to reuse ${outputDir} for a different target. Re-run with --refresh if intentional.`);
    Deno.exit(1);
  }
}

async function main() {
  const { targetName, outputDir, targetPath, refresh } = parseArgs(Deno.args);
  const rootDir = new URL("../", import.meta.url).pathname;
  const templatesDir = `${rootDir}templates`;

  await assertWorkspaceCompatibility(outputDir, targetName, targetPath, refresh);

  for (const dir of [
    outputDir,
    `${outputDir}/briefs`,
    `${outputDir}/candidates`,
    `${outputDir}/validated`,
    `${outputDir}/handoffs`,
    `${outputDir}/reports`,
    `${outputDir}/ledgers`,
    `${outputDir}/rankings`,
    `${outputDir}/evidence`,
    `${outputDir}/rejected`,
    `${outputDir}/checkpoints`,
    `${outputDir}/templates`,
  ]) {
    await ensureDir(dir);
  }

  const replacements = {
    "TARGET_NAME": targetName,
    "TARGET_PATH": targetPath,
    "WORKSPACE_PATH": outputDir,
    "- Name:": `- Name: ${targetName}`,
    "- Path / binary:": `- Path / binary: ${targetPath}`,
    "- Full internal path:": `- Full internal path: ${outputDir}/reports`,
    "- Finding ledger path:": `- Finding ledger path: ${outputDir}/ledgers/finding-ledger.md`,
    "- Output workspace:": `- Output workspace: ${outputDir}`,
  };

  const filesToMaterialize = [
    ["hunt-charter.md", "hunt-charter.md"],
    ["rankings/hotspot-ranking.md", "hotspot-ranking.md"],
    ["ledgers/finding-ledger.md", "finding-ledger.md"],
    ["briefs/parallel-agent-brief.template.md", "parallel-agent-brief.md"],
    ["templates/candidate-finding.md", "candidate-finding.md"],
    ["templates/validated-finding.md", "validated-finding.md"],
    ["templates/remediation-handoff.md", "remediation-handoff.md"],
    ["templates/orchestrator-runbook.md", "orchestrator-runbook.md"],
    ["templates/parallel-agent-brief.md", "parallel-agent-brief.md"],
    ["run-manifest.json", "run-manifest.json"],
  ] as const;

  for (const [relativeOutput, templateName] of filesToMaterialize) {
    const raw = await readText(`${templatesDir}/${templateName}`);
    const content = fill(raw, replacements);
    await writeTemplate(`${outputDir}/${relativeOutput}`, content, refresh);
  }

  const readme = `# Hunt Workspace: ${targetName}

Generated by mythos-security-review/bootstrap-hunt.ts.

Run all commands from the skill root:

\`cd /home/arcka/code/mythos-security-review\`

## Suggested flow
1. Fill out \`hunt-charter.md\` and confirm authorization in \`run-manifest.json\`
2. Run \`scripts/rank-hotspots.ts\` against the target and save JSON to \`rankings/top.json\`
3. Run \`scripts/plan-subagents.ts\` to create agent briefs in \`briefs/\`
4. Collect candidate findings in \`candidates/\` using \`templates/candidate-finding.md\`
5. Promote validated findings into \`validated/\` using \`templates/validated-finding.md\`
6. Generate remediation handoffs in \`handoffs/\` using \`templates/remediation-handoff.md\`
7. Run \`scripts/dedupe-findings.ts\`, \`scripts/validate-workspace.ts\`, and \`scripts/pack-report.ts\` to summarize results

## Target path
${targetPath || "(not set)"}
`;
  await writeTemplate(`${outputDir}/README.md`, readme, refresh);

  console.log(`Created hunt workspace at ${outputDir}`);
}

main();
