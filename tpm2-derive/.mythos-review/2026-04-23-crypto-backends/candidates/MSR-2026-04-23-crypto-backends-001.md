# Candidate Finding

## Summary
- ID: MSR-2026-04-23-crypto-backends-001
- Title: Singleton-dot identity names collapse backend state roots and turn seed overwrite into shared-state deletion
- Component: seed/prf/native state layout and subprocess backends
- Path(s): src/ops/seed.rs; src/ops/prf.rs; src/ops/native/subprocess.rs; src/ops.rs
- Bug class: missing validation / destructive path confusion
- Root Cause Key: identity-name-single-dot-collapses-state-root

## Hypothesis
- Suspected issue: validators accept `.` as an identity/profile name even though the backends later derive per-identity object directories via `objects_dir.join(name)`. For `.` this collapses to the shared `objects/` root.
- Why it may matter: the seed overwrite path may recurse over the shared object store instead of an identity-local directory, allowing cross-identity deletion or bricking state.
- Trust boundary involved: user-controlled identity/profile name -> filesystem layout for TPM-backed state.

## Evidence so far
- Static evidence: `validate_profile_name` / `validate_identity_name` reject `..` and separators, but accept `.`. `SeedSealedObjectLayout::for_profile` and `PrfRootLayout::for_profile` both join `objects_dir` with that name. `SubprocessSeedBackend::commit_staging_object` recursively removes `layout.object_dir` when `overwrite_existing=true`.
- Dynamic evidence: standalone local repro linked against the current crate shows `ops::resolve_identity` accepts `.`, both seed and PRF layouts collapse to `objects/.`, and a second deterministic repro deletes an unrelated `objects/victim/sentinel` file before the seed operation fails.
- Oracle strength: strong

## Reproduction status
- Repro available? yes
- Minimal trigger idea: pass identity/profile `.` into seed overwrite flow with `overwrite_existing=true` and any valid seed material.
- Preconditions: caller can choose the target identity/profile name and reach a seed overwrite path (for example recovery import or direct backend use).

## Root cause
- Suspected root cause: lexical validation forbids traversal tokens like `..` but still permits the special filesystem component `.`; later layout builders assume any accepted name maps to an identity-owned subdirectory.
- Confidence: high
- Competing explanations: none after the destructive repro removed unrelated data under the shared objects root.

## Next step to validate or reject
- Best next oracle: none needed beyond preserving the deterministic repro artifacts already collected.
- Owner: lead reviewer
