# Parallel Agent Brief: hunter-01

## Mission
Investigate the assigned hotspots aggressively and return only evidence-backed findings.

## Assigned scope
- Files / directories: 10
- Component: mixed cluster totaling score 83
- Bug class focus: auth, parser, logic, unsafe/native, and trust-boundary failures in assigned paths

## Assigned paths
- src/ops/native.rs (score 17; unsafe or high-privilege boundary, process or code execution, handles security-sensitive material, parsing keywords, non-trivial file size)
- src/backend/parser.rs (score 10; parsing or protocol handling, parsing keywords, non-trivial file size)
- src/backend/subprocess.rs (score 9; process or code execution, parsing keywords, non-trivial file size)
- src/ops.rs (score 9; process or code execution, handles security-sensitive material, non-trivial file size)
- .agents/skills/adr-skill/scripts/bootstrap_adr.js (score 8; initialization or configuration path, parsing keywords, non-trivial file size)
- src/ops/seed.rs (score 8; handles security-sensitive material, parsing keywords, non-trivial file size)
- src/cli/args.rs (score 7; handles security-sensitive material, parsing keywords)
- src/backend/recommend.rs (score 6; process or code execution, non-trivial file size)
- src/ops/shared.rs (score 5; handles security-sensitive material, non-trivial file size)
- src/bin/tpm2-derive.rs (score 4; parsing keywords)

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
Write candidate findings under ./.mythos-review/2026-04-23-crypto-backends/candidates using candidate-finding.md fields: ID, Title, Component, Path(s), Bug class, Root Cause Key, evidence, oracle strength, and next step.

## Rules
- Stay inside assigned scope unless the root cause clearly crosses a boundary.
- Prefer minimal repro and hard oracles.
- Do not inflate severity from suspicion alone.
- Note likely duplicates via Root Cause Key when possible.