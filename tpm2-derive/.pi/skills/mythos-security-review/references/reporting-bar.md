# Reporting Bar

## Candidate finding
Use when suspicion exists but proof is incomplete.
Must include:
- suspected area
- hypothesis
- current evidence
- missing oracle
- next validation step

## Validated finding
Use when the issue is real.
Must include:
- affected files/functions
- reproduction method
- observed result
- root-cause hypothesis
- confidence
- severity rationale
- duplicates checked

## Fix-ready handoff
Use when another agent or engineer should start fixing.
Must include:
- exact component ownership if known
- why the issue matters
- what breaks or gets crossed
- how to reproduce safely
- what test should be added
- likely fix direction
- disclosure tier

## Reject conditions
Do not escalate when:
- the issue is not reproducible
- the root cause is speculative
- the same root cause already exists in the ledger
- the evidence is too weak for a fixer to act on
