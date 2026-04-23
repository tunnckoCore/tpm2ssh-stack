#!/usr/bin/env -S deno run --allow-read --allow-write

/**
 * plan-subagents.ts
 *
 * Reads hotspot ranking JSON and produces balanced agent briefs for parallel hunt
 * passes. This is intended for orchestrator agents that want to turn one ranked
 * attack surface into many focused subagent tasks.
 *
 * Usage:
 *   deno run --allow-read --allow-write scripts/plan-subagents.ts rankings.json --agents 4 --output-dir ./.mythos-review/YYYY-MM-DD-slug/briefs
 *   deno run --allow-read --allow-write scripts/plan-subagents.ts rankings.json --agents 6 --prefix hunter
 */

type RankedFile = {
  path: string;
  score: number;
  reasons?: string[];
};

type Bucket = {
  name: string;
  totalScore: number;
  items: RankedFile[];
};

function usage() {
  console.log(`plan-subagents.ts

Usage:
  deno run --allow-read --allow-write scripts/plan-subagents.ts <rankings.json> [--agents N] [--output-dir DIR] [--prefix NAME]

Options:
  --agents N       Number of briefs to create (default: 4)
  --output-dir DIR Output directory for briefs (default: ./briefs)
  --prefix NAME    Agent name prefix (default: hunter)
`);
}

function parseArgs(args: string[]) {
  if (args.includes("--help") || args.includes("-h")) {
    usage();
    Deno.exit(0);
  }

  const agentsIndex = args.indexOf("--agents");
  const outputDirIndex = args.indexOf("--output-dir");
  const prefixIndex = args.indexOf("--prefix");
  const agents = agentsIndex !== -1 ? Number(args[agentsIndex + 1]) : 4;
  const outputDir = outputDirIndex !== -1 ? args[outputDirIndex + 1] : "briefs";
  const prefix = prefixIndex !== -1 ? args[prefixIndex + 1] : "hunter";

  if (!Number.isInteger(agents) || agents < 1) {
    console.error("--agents must be an integer >= 1");
    Deno.exit(1);
  }

  const consumed = new Set<number>();
  for (const index of [agentsIndex, outputDirIndex, prefixIndex]) {
    if (index !== -1) {
      consumed.add(index);
      consumed.add(index + 1);
    }
  }

  let rankingsPath = "";
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith("--") && !consumed.has(i)) {
      rankingsPath = args[i];
      break;
    }
  }

  if (!rankingsPath) {
    usage();
    Deno.exit(1);
  }

  return { rankingsPath, agents, outputDir, prefix };
}

function bucketize(items: RankedFile[], count: number, prefix: string): Bucket[] {
  const buckets: Bucket[] = Array.from({ length: count }, (_, i) => ({
    name: `${prefix}-${String(i + 1).padStart(2, "0")}`,
    totalScore: 0,
    items: [],
  }));

  const sorted = [...items].sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
  for (const item of sorted) {
    buckets.sort((a, b) => a.totalScore - b.totalScore || a.name.localeCompare(b.name));
    buckets[0].items.push(item);
    buckets[0].totalScore += item.score;
  }

  return buckets.filter((bucket) => bucket.items.length > 0).sort((a, b) => a.name.localeCompare(b.name));
}

function renderBrief(bucket: Bucket, outputDir: string) {
  const candidatePath = outputDir.replace(/\/briefs$/, "/candidates");
  const lines = [
    `# Parallel Agent Brief: ${bucket.name}`,
    "",
    "## Mission",
    "Investigate the assigned hotspots aggressively and return only evidence-backed findings.",
    "",
    "## Assigned scope",
    `- Files / directories: ${bucket.items.length}`,
    `- Component: mixed cluster totaling score ${bucket.totalScore}`,
    "- Bug class focus: auth, parser, logic, unsafe/native, and trust-boundary failures in assigned paths",
    "",
    "## Assigned paths",
  ];

  for (const item of bucket.items) {
    lines.push(`- ${item.path} (score ${item.score}${item.reasons?.length ? `; ${item.reasons.join(", ")}` : ""})`);
  }

  lines.push(
    "",
    "## Hunt priorities",
    "- untrusted input handling",
    "- trust and privilege boundaries",
    "- unsafe/native behavior",
    "- state or logic inconsistencies",
    "",
    "## Expected outputs",
    "1. Ranked sub-hotspots within assigned paths",
    "2. Candidate findings with evidence",
    "3. Rejected hypotheses worth not revisiting",
    "4. Suggested next oracle when proof is incomplete",
    "",
    "## Report format",
    `Write candidate findings under ${candidatePath} using candidate-finding.md fields: ID, Title, Component, Path(s), Bug class, Root Cause Key, evidence, oracle strength, and next step.`,
    "",
    "## Rules",
    "- Stay inside assigned scope unless the root cause clearly crosses a boundary.",
    "- Prefer minimal repro and hard oracles.",
    "- Do not inflate severity from suspicion alone.",
    "- Note likely duplicates via Root Cause Key when possible.",
  );

  return lines.join("\n");
}

async function main() {
  const { rankingsPath, agents, outputDir, prefix } = parseArgs(Deno.args);
  const content = await Deno.readTextFile(rankingsPath);
  const rankings = JSON.parse(content) as RankedFile[];

  if (!Array.isArray(rankings)) {
    console.error("rankings.json must be an array");
    Deno.exit(1);
  }
  if (rankings.length === 0) {
    console.error("rankings.json is empty");
    Deno.exit(1);
  }
  for (const item of rankings) {
    if (typeof item.path !== "string" || typeof item.score !== "number") {
      console.error("each ranking entry must contain { path, score }");
      Deno.exit(1);
    }
  }

  const agentCount = Math.min(agents, rankings.length);
  const buckets = bucketize(rankings, agentCount, prefix);

  await Deno.mkdir(outputDir, { recursive: true });
  for (const bucket of buckets) {
    await Deno.writeTextFile(`${outputDir}/${bucket.name}.md`, renderBrief(bucket, outputDir));
  }

  const summary = ["agent\ttotal_score\tfiles"];
  for (const bucket of buckets) {
    summary.push(`${bucket.name}\t${bucket.totalScore}\t${bucket.items.length}`);
  }
  console.log(summary.join("\n"));
}

main();
