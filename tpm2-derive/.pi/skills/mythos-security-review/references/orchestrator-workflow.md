# Orchestrator Workflow

This skill is designed for a lead agent that can spawn subagents.

## Default loop
1. Bootstrap a hunt workspace.
2. Rank hotspots.
3. Split the ranking into balanced agent briefs.
4. Spawn one subagent per brief.
5. Merge candidate findings into a shared ledger.
6. Strengthen or reject weak candidates.
7. Deduplicate candidates and validated findings.
8. Validate the workspace before packaging.
9. Package remediation handoffs and a final report.

## Suggested role split
- **Lead/orchestrator:** scope, ranking, assignments, merging, final triage
- **Recon subagents:** file/component reconnaissance and hypothesis generation
- **Validation subagents:** harnesses, repro loops, sanitizer-backed proof
- **Challenge subagents:** duplicate checks, severity challenges, exploitability skepticism
- **Packaging subagents:** final handoff docs and report assembly

## Shared artifacts
- hunt charter
- hotspot ranking JSON/Markdown
- subagent briefs
- candidate findings
- validated findings
- remediation handoffs
- final report

## Escalation rule
Promote only when another agent could immediately start fixing or hardening from the report.
