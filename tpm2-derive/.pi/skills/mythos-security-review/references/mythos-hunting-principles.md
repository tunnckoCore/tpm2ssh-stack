# Mythos Hunting Principles

Use this reference when running `mythos-security-review` against an authorized target.

## Core loop
1. Establish authorization and environment boundaries.
2. Rank attack surface before deep review.
3. Split the hunt into focused parallel passes.
4. Convert suspicions into evidence quickly.
5. Deduplicate before escalating counts.
6. Hand off only fix-ready findings.

## What to optimize for
- Coverage across high-yield components
- Strong validation oracles
- Minimal time spent on weak candidates
- Reports that a fixing agent can act on immediately

## Preferred hunt order
1. Untrusted input parsers
2. Authn/authz flows
3. Deserialization and IPC boundaries
4. Unsafe/native/FFI code
5. Cryptographic state transitions and key handling
6. Privilege boundaries, sandbox crossings, kernel/device edges
7. Complex state machines and “should never happen” logic

## Real vs interesting
A finding is worth routing when it is:
- reproducible,
- localized enough to fix,
- tied to a concrete trust-boundary failure,
- and supported by evidence stronger than intuition.

Interesting-but-not-yet-actionable findings stay in the candidate ledger until upgraded or rejected.

## Default reporting posture
- Internal report: full evidence needed for fixers
- Restricted summary: enough detail for triage and planning
- Public-safe summary: abstract only, no unnecessary trigger detail
