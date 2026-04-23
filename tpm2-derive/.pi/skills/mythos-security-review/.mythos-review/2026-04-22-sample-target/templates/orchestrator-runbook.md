# Orchestrator Runbook

## Hunt setup
- Target:
- Authorization confirmed by:
- Output workspace: /home/arcka/code/mythos-security-review/.mythos-review/2026-04-22-sample-target
- Environment boundary:

## Commands
- Bootstrap: `deno run --allow-read --allow-write scripts/bootstrap-hunt.ts <target> --target-path /abs/path` -> default run dir: `./.mythos-review/YYYY-MM-DD-<slug>/`
- Rank hotspots: `deno run --allow-read scripts/rank-hotspots.ts /abs/path --json > ./.mythos-review/YYYY-MM-DD-<slug>/rankings/top.json`
- Plan subagents: `deno run --allow-read --allow-write scripts/plan-subagents.ts ./.mythos-review/YYYY-MM-DD-<slug>/rankings/top.json --agents 4 --output-dir ./.mythos-review/YYYY-MM-DD-<slug>/briefs`
- Dedupe findings: `deno run --allow-read --allow-write scripts/dedupe-findings.ts ./.mythos-review/YYYY-MM-DD-<slug> --output ./.mythos-review/YYYY-MM-DD-<slug>/reports/deduped-findings.md`
- Validate workspace: `deno run --allow-read scripts/validate-workspace.ts ./.mythos-review/YYYY-MM-DD-<slug>`
- Pack report: `deno run --allow-read --allow-write scripts/pack-report.ts ./.mythos-review/YYYY-MM-DD-<slug> --output ./.mythos-review/YYYY-MM-DD-<slug>/reports/final-report.md`

## Agent roster
| Agent | Scope | Input Brief | Output Path | Status |
|-------|-------|-------------|-------------|--------|
| | | | | |

## Merge checkpoints
- checkpoint 1:
- checkpoint 2:
- checkpoint 3:

## Final outputs
- validated findings:
- remediation handoffs:
- report:
