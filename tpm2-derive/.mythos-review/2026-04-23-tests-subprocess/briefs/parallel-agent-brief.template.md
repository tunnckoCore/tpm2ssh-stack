# Parallel Agent Brief

## Mission
Investigate one hotspot cluster aggressively and return only evidence-backed findings.

## Assigned scope
- Files / directories:
- Component:
- Bug class focus:

## Assigned paths
- 

## Hunt priorities
- Untrusted input handling
- Trust/privilege boundary mistakes
- Unsafe/native memory behavior
- Logic inconsistencies between policy and implementation

## Expected outputs
1. Ranked sub-hotspots
2. Candidate findings with evidence
3. Rejected hypotheses worth not revisiting
4. Suggested next oracle when proof is incomplete

## Report format
Write candidate findings using these fields:
- ID
- Title
- Component
- Path(s)
- Bug class
- Root Cause Key
- current evidence
- oracle strength: weak / moderate / strong
- next step

## Rules
- Stay inside assigned scope unless the root cause clearly crosses a boundary.
- Prefer minimal repro and hard oracles.
- Do not inflate severity from suspicion alone.
- Note likely duplicates.
