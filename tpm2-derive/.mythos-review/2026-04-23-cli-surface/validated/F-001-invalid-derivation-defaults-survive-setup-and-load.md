# Validated Finding

## Summary
- ID: F-001
- Title: Identity setup/load accepts invalid derivation defaults that later hard-fail crypto operations
- Severity: low
- Confidence: high
- Root Cause Key: cli-identity+model-identity:missing-derivation-default-validation:deferred-crypto-failure
- Disclosure tier: full internal

## Affected area
- Component: CLI identity setup and persisted identity lifecycle
- Path(s): src/cli/args.rs:88-95, src/cli/mod.rs:120-125, src/ops.rs:171-243, src/ops/shared.rs:68-105, src/model/identity.rs:147-206
- Function(s): `parse_key_value`, `derivation_overrides`, `build_identity_record`, `resolve_effective_derivation_inputs`, `Identity::persist`, `Identity::load_named`
- Ownership if known: CLI / identity persistence surface

## What was proven
- Trigger conditions: create or load a non-native identity with whitespace-only `purpose`, empty `org`, or empty context values such as `tenant=`
- Proof method: local Rust oracle using public library APIs plus a fixed fake seed backend
- Observed result: `resolve_identity(..., dry_run=true)` accepted invalid defaults; `Identity::load_named()` also accepted persisted invalid defaults; later `encrypt::encrypt(...)` failed with `validation error: purpose must not be empty` or `validation error: context value for key 'tenant' must not be empty`
- Oracle used: `./.mythos-review/2026-04-23-cli-surface/evidence/invalid-defaults-oracle/output.txt` produced by the reproducible harness under `evidence/invalid-defaults-oracle/`

## Root cause
- Explanation: setup and load paths validate name/mode/use compatibility, but they never validate non-native derivation defaults before persisting or accepting them. The same fields are validated only later inside `resolve_effective_derivation_inputs()` when a real sign/encrypt/export/ssh-add flow tries to derive key material.
- Why this is the likely cause: `build_identity_record()` copies `request.defaults` directly into `Identity::with_defaults()` (`src/ops.rs:228-242`), `parse_key_value()` only rejects missing keys (`src/cli/args.rs:371-380`), and `Identity::load_named()` validates mode/use combinations but not derivation-default correctness (`src/model/identity.rs:195-206`). The later shared derivation path explicitly rejects empty `org`, `purpose`, and context values (`src/ops/shared.rs:82-101`).
- Duplicate check result: distinct from duplicate-context overwrite candidate F-002; F-001 is about missing validity checks across create/load lifecycle.

## Impact triage
- Boundary crossed: operator input / persisted identity state -> cryptographic derivation preconditions
- Reachability: direct from CLI/API for setup; also reachable by loading already-persisted identity JSON
- Preconditions: non-native identity mode plus malformed defaults
- Breadth: affects sign/verify/encrypt/decrypt/export/ssh-add flows that rely on effective derivation inputs
- Why fix now: the CLI can report successful setup (especially `--dry-run`) for identities that are guaranteed to fail later, and malformed identity JSON remains loadable until a runtime operation trips over it. This creates time-bomb state and breaks automation in a security-sensitive path.

## Fix handoff
- Likely fix direction: add one shared validator for derivation defaults and call it from identity creation and identity load before persistence/acceptance; reject empty `org`, empty/whitespace `purpose`, and empty context values up front.
- Suggested regression test: reject `identity ... --purpose "   "`; reject `identity ... --context tenant=`; reject loading persisted identity JSON with empty derivation-default values; ensure the same validator is used by create and load.
- Open questions: whether duplicate context keys should also be rejected explicitly instead of silently last-winning.
