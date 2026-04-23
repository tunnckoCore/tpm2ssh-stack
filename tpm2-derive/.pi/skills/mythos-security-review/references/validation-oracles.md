# Validation Oracles

Use the strongest oracle available before promoting a candidate.

## Strong oracles
- sanitizer hit (ASan, UBSan, TSan, KASAN, etc.)
- deterministic failing test
- reproducible invariant violation
- verified authz bypass against a controlled harness
- differential behavior against a known-good implementation or spec

## Moderate oracles
- debugger trace supporting the suspected root cause
- repeatable crash without a perfect oracle
- constrained taint/dataflow reaching a sensitive sink
- binary/source mismatch confirmed across multiple observations

## Weak oracles
- suspicious code pattern only
- model intuition without execution evidence
- one-off flaky behavior
- severity label with no proof of impact

## Promotion rule
- Weak -> keep as candidate only
- Moderate -> triage carefully, try to strengthen
- Strong -> eligible for validated finding and fix handoff

## Minimum evidence for handoff
A fix-ready report should contain:
- affected component/path
- trigger conditions
- repro or proof method
- observed result
- suspected root cause
- confidence level
- test or regression idea

## When to stop digging
Stop when the issue is real enough that a fixing agent can begin safely. Go deeper only if:
- severity is still unclear,
- duplicates need separation,
- or the user explicitly requests deeper exploitability triage.
