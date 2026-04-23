# Parallel Agent Brief: segment-hunter-03

## Mission
Investigate the assigned hotspots aggressively and return only evidence-backed findings.

## Assigned scope
- Files / directories: 1
- Component: mixed cluster totaling score 5
- Bug class focus: auth, parser, logic, unsafe/native, and trust-boundary failures in assigned paths

## Assigned paths
- tests/support/mod.rs (score 5; parsing keywords, non-trivial file size)

## Hunt priorities
- untrusted input handling
- trust and privilege boundaries
- unsafe/native behavior
- state or logic inconsistencies

## Expected outputs
1. Ranked sub-hotspots within assigned paths
2. Candidate findings with evidence
3. Rejected hypotheses worth not revisiting
4. Suggested next oracle when proof is incomplete

## Report format
Write candidate findings under ./.mythos-review/2026-04-23-tests-subprocess/candidates using candidate-finding.md fields: ID, Title, Component, Path(s), Bug class, Root Cause Key, evidence, oracle strength, and next step.

## Rules
- Stay inside assigned scope unless the root cause clearly crosses a boundary.
- Prefer minimal repro and hard oracles.
- Do not inflate severity from suspicion alone.
- Note likely duplicates via Root Cause Key when possible.