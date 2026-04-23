# Remediation Handoff

## Finding
- ID: MSR-2026-04-23-crypto-backends-001
- Title: Singleton-dot identity names collapse backend state roots and turn seed overwrite into shared-state deletion
- Severity: High
- Confidence: High
- Root Cause Key: identity-name-single-dot-collapses-state-root
- Path(s): src/ops/seed.rs; src/ops/prf.rs; src/ops/native/subprocess.rs; src/ops.rs

## Why the fixing agent should care
- User-visible or security impact: a caller-controlled profile name of `.` can redirect backend state to the shared objects root; the seed overwrite path can then delete unrelated identity material before failing.
- Affected component: identity/profile validation and seed backend staging commit logic.
- Trust boundary: user-supplied identity/profile name into filesystem paths for TPM-backed state.

## What is already known
- Repro status: deterministic local repro complete.
- Root cause status: confirmed.
- Evidence quality: strong oracle with direct filesystem side-effect observation.

## Likely fix direction
- Checks to add or restore: reject `.` in every identity/profile validator used by seed, PRF, native, and high-level ops paths.
- State transitions to harden: before any overwrite/delete, assert that the computed target directory is a strict child of `objects_dir`, not the root itself.
- Bounds / lifetime / ownership rules to enforce: per-identity object directories must always be distinct child directories, never aliases like `.`.
- Tests to add: validator rejection tests for `.`, layout tests for strict-child semantics, and a seed overwrite regression test that proves sibling data survives malformed names.

## Suggested first implementation steps
1. Tighten all relevant validators (`validate_profile_name`, `validate_identity_name`, and any equivalents) to reject `.` explicitly.
2. Add a shared helper that verifies computed object directories are strict descendants of the shared objects root before delete/rename operations.
3. Cover the seed overwrite path with a regression test mirroring the destructive repro.

## Handoff attachments
- logs: ./.mythos-review/2026-04-23-crypto-backends/evidence/seed-dot-overwrite-delete-repro.txt
- repro artifacts: ./.mythos-review/2026-04-23-crypto-backends/evidence/identity-dot-layout-repro.txt
- stack traces / screenshots: none
- related findings: none
