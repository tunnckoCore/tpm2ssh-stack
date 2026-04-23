#!/usr/bin/env -S deno run --allow-read

/**
 * rank-hotspots.ts
 *
 * Heuristically ranks files in a codebase by likely security-review value.
 * Useful for splitting a hunt across subagents before deep review.
 *
 * Usage:
 *   deno run --allow-read scripts/rank-hotspots.ts <repo-root>
 *   deno run --allow-read scripts/rank-hotspots.ts <repo-root> --limit 50
 *   deno run --allow-read scripts/rank-hotspots.ts <repo-root> --json
 */

type RankedFile = {
  path: string;
  score: number;
  reasons: string[];
};

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  "vendor",
  "target",
  "tmp",
  ".next",
  ".turbo",
  ".cache",
]);

const PATH_RULES: Array<{ pattern: RegExp; score: number; reason: string }> = [
  { pattern: /(auth|login|session|token|permission|acl|role|policy)/i, score: 5, reason: "auth or authorization surface" },
  { pattern: /(parser|decode|deserialize|marshal|unmarshal|codec|protocol)/i, score: 5, reason: "parsing or protocol handling" },
  { pattern: /(unsafe|ffi|native|kernel|sandbox|hypervisor|vm|driver)/i, score: 5, reason: "unsafe or high-privilege boundary" },
  { pattern: /(crypto|tls|ssh|x509|cert|signature|cipher|key)/i, score: 5, reason: "cryptographic material or protocol" },
  { pattern: /(rpc|api|http|server|socket|network|request|handler)/i, score: 4, reason: "network-facing or request handling" },
  { pattern: /(upload|import|export|archive|image|media)/i, score: 4, reason: "complex attacker-controlled input" },
  { pattern: /(config|migration|bootstrap|init|startup)/i, score: 3, reason: "initialization or configuration path" },
];

const CONTENT_RULES: Array<{ pattern: RegExp; score: number; reason: string }> = [
  { pattern: /unsafe\s*\{/i, score: 5, reason: "contains unsafe block" },
  { pattern: /(memcpy|strcpy|strncpy|malloc|free|realloc|new\s+\w+\[)/i, score: 4, reason: "manual memory handling" },
  { pattern: /(eval\(|exec\(|system\(|child_process|subprocess)/i, score: 4, reason: "process or code execution" },
  { pattern: /(password|token|secret|apikey|private[_-]?key)/i, score: 3, reason: "handles security-sensitive material" },
  { pattern: /(TODO|FIXME|HACK|XXX|should never happen)/i, score: 2, reason: "contains warning marker" },
  { pattern: /(deserialize|unmarshal|parse|decode)/i, score: 3, reason: "parsing keywords" },
];

function parseArgs(args: string[]) {
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`rank-hotspots.ts

Usage:
  deno run --allow-read scripts/rank-hotspots.ts <repo-root> [--limit N] [--json]

Options:
  --limit N   Maximum rows to print (default: 30)
  --json      Output JSON
`);
    Deno.exit(0);
  }

  const limitIndex = args.indexOf("--limit");
  const limit = limitIndex !== -1 ? Number(args[limitIndex + 1]) : 30;
  const json = args.includes("--json");

  const consumed = new Set<number>();
  if (limitIndex !== -1) {
    consumed.add(limitIndex);
    consumed.add(limitIndex + 1);
  }

  let root = ".";
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith("--") && !consumed.has(i)) {
      root = args[i];
      break;
    }
  }

  return { root, limit, json };
}

async function* walk(dir: string): AsyncGenerator<string> {
  for await (const entry of Deno.readDir(dir)) {
    const fullPath = `${dir}/${entry.name}`;
    if (entry.isDirectory) {
      if (!SKIP_DIRS.has(entry.name)) {
        yield* walk(fullPath);
      }
      continue;
    }
    if (entry.isFile) {
      yield fullPath;
    }
  }
}

function fileLooksRelevant(path: string): boolean {
  return /\.(c|cc|cpp|cxx|h|hpp|rs|go|java|kt|py|rb|php|js|jsx|ts|tsx|swift|m|mm|sh)$/i.test(path);
}

async function scoreFile(path: string): Promise<RankedFile | null> {
  if (!fileLooksRelevant(path)) return null;

  let score = 1;
  const reasons: string[] = [];
  const normalized = path.replace(/^\.\//, "");

  for (const rule of PATH_RULES) {
    if (rule.pattern.test(normalized)) {
      score += rule.score;
      reasons.push(rule.reason);
    }
  }

  try {
    const text = await Deno.readTextFile(path);
    const sample = text.slice(0, 8000);
    for (const rule of CONTENT_RULES) {
      if (rule.pattern.test(sample)) {
        score += rule.score;
        reasons.push(rule.reason);
      }
    }

    const lineCount = sample.split("\n").length;
    if (lineCount > 200) {
      score += 1;
      reasons.push("non-trivial file size");
    }
  } catch {
    return null;
  }

  const uniqueReasons = [...new Set(reasons)].slice(0, 6);
  return { path: normalized, score: Math.min(score, 25), reasons: uniqueReasons };
}

function formatTable(rows: RankedFile[]): string {
  const lines = ["score\tpath\treasons"];
  for (const row of rows) {
    lines.push(`${row.score}\t${row.path}\t${row.reasons.join(", ")}`);
  }
  return lines.join("\n");
}

async function main() {
  const { root, limit, json } = parseArgs(Deno.args);
  const ranked: RankedFile[] = [];

  for await (const path of walk(root)) {
    const row = await scoreFile(path);
    if (row) ranked.push(row);
  }

  ranked.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
  const trimmed = ranked.slice(0, limit);

  if (json) {
    console.log(JSON.stringify(trimmed, null, 2));
  } else {
    console.log(formatTable(trimmed));
  }
}

main();
