# Parallel Agent Brief: hunter-03

## Mission
Investigate the assigned hotspots aggressively and return only evidence-backed findings.

## Assigned scope
- Files / directories: 10
- Component: mixed cluster totaling score 82
- Bug class focus: auth, parser, logic, unsafe/native, and trust-boundary failures in assigned paths

## Assigned paths
- src/ops/ssh.rs (score 14; cryptographic material or protocol, process or code execution, handles security-sensitive material, non-trivial file size)
- src/ops/prf.rs (score 12; process or code execution, handles security-sensitive material, parsing keywords, non-trivial file size)
- src/ops/native/subprocess.rs (score 10; unsafe or high-privilege boundary, parsing keywords, non-trivial file size)
- src/ops/sign.rs (score 9; process or code execution, handles security-sensitive material, non-trivial file size)
- src/model/command.rs (score 8; handles security-sensitive material, parsing keywords, non-trivial file size)
- tests/real_tpm_cli.rs (score 8; handles security-sensitive material, parsing keywords, non-trivial file size)
- src/model/core.rs (score 7; handles security-sensitive material, parsing keywords)
- src/cli/mod.rs (score 5; handles security-sensitive material, non-trivial file size)
- src/ops/enforcement.rs (score 5; handles security-sensitive material, non-trivial file size)
- .agents/skills/adr-skill/scripts/set_adr_status.js (score 4; parsing keywords)

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