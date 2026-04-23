# Remediation Handoff

## Finding
- ID: F-001
- Title: Identity setup/load accepts invalid derivation defaults that later hard-fail crypto operations
- Severity: low
- Confidence: high
- Root Cause Key: cli-identity+model-identity:missing-derivation-default-validation:deferred-crypto-failure
- Path(s): src/cli/args.rs, src/cli/mod.rs, src/ops.rs, src/ops/shared.rs, src/model/identity.rs

## Why the fixing agent should care
- User-visible or security impact: operators can successfully set up or load an identity that is guaranteed to fail when it reaches a real crypto path, creating fragile state in a secret-bearing workflow.
- Affected component: non-native identity creation / load path for PRF and seed modes
- Trust boundary: CLI/API input and persisted identity JSON crossing into key-derivation routines

## What is already known
- Repro status: strong local repro
- Root cause status: confirmed by codepath + oracle
- Evidence quality: high; see `evidence/invalid-defaults-oracle/output.txt`

## Likely fix direction
- Checks to add or restore: validate `org`, `purpose`, and every context value before persisting and before accepting loaded identity JSON
- State transitions to harden: `IdentityCreateRequest -> Identity::with_defaults`, and `Identity::load_named -> usable Identity`
- Bounds / lifetime / ownership rules to enforce: derivation defaults must satisfy the same invariants at setup/load time that runtime derivation already expects
- Tests to add:
  - creation rejects whitespace-only `purpose`
  - creation rejects `--context tenant=`
  - loading malformed persisted defaults fails closed
  - validator parity test between create path and runtime derivation path

## Suggested first implementation steps
1. Extract a shared `validate_derivation_defaults(...)` helper near `resolve_effective_derivation_inputs()` or the identity lifecycle.
2. Call it from `build_identity_record()` before `Identity::with_defaults(...)` and from `Identity::load_named()` after decode but before accepting the record.
3. Add regression tests for both CLI-facing setup and persisted JSON load.

## Handoff attachments
- logs: `evidence/invalid-defaults-oracle/output.txt`
- repro artifacts: `evidence/invalid-defaults-oracle/`
- stack traces / screenshots: none needed
- related findings: candidate F-002 discusses duplicate `--context` semantics but is not promoted
