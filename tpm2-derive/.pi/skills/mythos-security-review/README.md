# mythos-security-review

An orchestrator-oriented skill for authorized vulnerability hunting with subagents.

## Prerequisites
- `deno`
- a target you are authorized to analyze
- a harness that can spawn subagents and share files on disk

## Quickstart
Run from this directory:

```bash
cd /home/arcka/code/mythos-security-review

# 1. Create a workspace
RUN_DIR="$(deno run --allow-read --allow-write scripts/bootstrap-hunt.ts <target-name> \
  --target-path /abs/path/to/target | awk '/Created hunt workspace at/{print $NF}')"

# Default location if you do not pass --output-dir:
#   ./.mythos-review/YYYY-MM-DD-<target-name>/

# 2. Rank hotspots
 deno run --allow-read scripts/rank-hotspots.ts /abs/path/to/target --limit 50 --json \
  > "$RUN_DIR/rankings/top.json"

# 3. Plan subagent briefs
deno run --allow-read --allow-write scripts/plan-subagents.ts \
  "$RUN_DIR/rankings/top.json" \
  --agents 4 \
  --output-dir "$RUN_DIR/briefs"

# 4. Have subagents write candidate findings under:
#    $RUN_DIR/candidates/
#    using $RUN_DIR/templates/candidate-finding.md

# 5. Promote validated findings under:
#    $RUN_DIR/validated/
#    and optional handoffs under:
#    $RUN_DIR/handoffs/

# 6. Dedupe candidates/validated findings
deno run --allow-read --allow-write scripts/dedupe-findings.ts "$RUN_DIR" \
  --output "$RUN_DIR/reports/deduped-findings.md"

# 7. Validate the workspace before final packaging
deno run --allow-read scripts/validate-workspace.ts "$RUN_DIR"

# 8. Build the final report from canonical validated findings
deno run --allow-read --allow-write scripts/pack-report.ts "$RUN_DIR" \
  --output "$RUN_DIR/reports/final-report.md"
```

## Canonical artifact flow
- `./.mythos-review/YYYY-MM-DD-<slug>/hunt-charter.md`
- `./.mythos-review/YYYY-MM-DD-<slug>/run-manifest.json`
- `./.mythos-review/YYYY-MM-DD-<slug>/rankings/top.json`
- `./.mythos-review/YYYY-MM-DD-<slug>/briefs/*.md`
- `./.mythos-review/YYYY-MM-DD-<slug>/candidates/F-*.md`
- `./.mythos-review/YYYY-MM-DD-<slug>/validated/F-*.md`
- `./.mythos-review/YYYY-MM-DD-<slug>/handoffs/F-*.md`
- `./.mythos-review/YYYY-MM-DD-<slug>/reports/*.md`

Only `validated/` is treated as the canonical source of findings for final packaging.
Handoffs are linked support artifacts, not separate findings.
