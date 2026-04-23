# Validated Finding

## Summary
- ID: MSR-2026-04-23-crypto-backends-001
- Title: Singleton-dot identity names collapse backend state roots and turn seed overwrite into shared-state deletion
- Severity: High
- Confidence: High
- Root Cause Key: identity-name-single-dot-collapses-state-root
- Disclosure tier: full internal

## Affected area
- Component: seed/prf/native state layout and subprocess backends
- Path(s): src/ops/seed.rs; src/ops/prf.rs; src/ops/native/subprocess.rs; src/ops.rs
- Function(s): validate_profile_name; validate_identity_name; SeedSealedObjectLayout::for_profile; PrfRootLayout::for_profile; SubprocessSeedBackend::commit_staging_object
- Ownership if known: crypto/backend hardening path

## What was proven
- Trigger conditions: an accepted identity/profile name of `.` reaches backend layout construction; for the seed backend, `overwrite_existing=true` reaches the staging commit path.
- Proof method: two standalone local rust repro harnesses linked against the current crate. Repro A showed `ops::resolve_identity` accepts `.` and both seed/PRF layouts resolve to `objects/.`. Repro B invoked `SubprocessSeedBackend::seal_seed` with `overwrite_existing=true`, a fake TPM runner, and an unrelated sentinel under `objects/victim/sentinel`.
- Observed result: Repro B deleted the unrelated sentinel under the shared objects root before returning `Err(State("failed to remove existing seed object directory .../objects/.: Invalid argument"))`.
- Oracle used: deterministic local harness on the reviewed branch plus direct filesystem state observation.

## Root cause
- Explanation: name validation only blocks `..`, `/`, and `\`, but allows the special path component `.`. The backend layout code then treats `objects_dir.join(".")` as an identity-local directory even though it aliases the shared objects root. The seed overwrite path recursively deletes that computed directory.
- Why this is the likely cause: the destructive repro required no races, no TPM, and no external interference; changing only the accepted name to `.` was sufficient to collapse the layout and delete sibling data.
- Duplicate check result: no duplicate finding in this workspace; adjacent PRF/native evidence shares the same root cause and is folded into this finding.

## Impact triage
- Boundary crossed: per-identity backend state isolation -> shared `objects/` namespace.
- Reachability: reachable anywhere the library or a service built on it accepts caller-chosen identity/profile names and exposes a seed overwrite path.
- Preconditions: caller can supply `.` as the target identity/profile and set or induce `overwrite_existing=true` on a seed import/recovery flow.
- Breadth: destructive seed overwrite is the strongest observed impact; PRF and native layouts also collapse into shared roots for the same accepted name.
- Why fix now: this is a one-input integrity/availability break on the shared object store. The demonstrated failure deleted unrelated state even though the operation ultimately errored, so retry/rollback does not contain the damage.

## Fix handoff
- Likely fix direction: reject `.` (and any other single-component aliases that do not create a real child name) in all identity/profile validators, then add a fail-closed guard that refuses to operate when a computed object dir canonicalizes to the shared objects root.
- Suggested regression test: add unit tests proving `.` is rejected in identity/profile validators and a backend test ensuring `overwrite_existing=true` never targets `objects_dir` itself.
- Open questions: whether any persisted state already uses `.` or similarly dangerous aliases and needs migration handling.
