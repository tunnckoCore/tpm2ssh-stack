# Review Summary

## Scope
Focused review of the requested CLI-surface segment plus minimal validation cross-references.

## User steer applied
Received supplementary directive verbatim:
"assume host/server is properly protected, do not suggest things general advices and obvious things"

This report therefore excludes generic host-hardening advice and only discusses repo-specific code behavior.

## Concise outcome
- Validated: 1 low-severity fix-ready issue
- Rejected after oracle review: 1 duplicate-context semantics candidate
- No production files modified

## Validated finding
- **F-001** — identity setup/load accepts invalid derivation defaults that only fail later when crypto operations execute.
  - Setup accepts malformed non-native defaults (`purpose="   "`, `tenant=`).
  - Persisted malformed defaults also survive `load_named()`.
  - Later seed-mode crypto operations fail with shared derivation validation errors.

## Primary evidence
- `evidence/invalid-defaults-oracle/output.txt`
- `evidence/context-dup-oracle/output.txt`
