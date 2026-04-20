# TPM2 Derive Progress

_As of 2026-04-20._

## Current state

### Working slices
- `inspect`: real TPM/tooling capability probe.
- `setup --mode native`: materializes native TPM setup and persists locator metadata.
- `setup --mode prf`: provisions PRF root material and persists paths/metadata.
- `setup --mode seed`: seals a seed and persists seed metadata/blob paths.
- `derive`: works for persisted `prf` and `seed` profiles.
- `sign`: native sign executes when native setup state exists; otherwise returns a concrete planned result.
- `verify`: native verify now works for native `p256` profiles.
- `export --kind public-key`: works for native profiles.
- `export --kind recovery-bundle`: works for seed profiles with explicit confirmations and explicit output path.
- `ssh agent add`: seed-mode `ed25519` slice is wired.
- `tpm2ssh`: now has a managed flow using `tpm2-derive` for safer setup/login paths.

### Library-only but usable internals
- seed recovery-bundle import / restore path exists in library code and reseals imported seed material.

### Notes
- `tpm2-derive/src/ops.rs` is **not** orphaned; it is the real `crate::ops` module root referenced by `tpm2-derive/src/lib.rs`.

### Still missing / partial
- CLI surface for recovery import / restore
- broader verify coverage beyond native `p256`
- broader `ssh agent add` coverage beyond seed `ed25519`
- richer TPM auth flows
- PRF/seed sign support
- encrypt/decrypt
- more direct `tpm2ssh` migration away from legacy fallback paths

## Cycle 1 — 2026-04-20

### Merged this cycle
- `47de64f` — native setup materialization
- `3809f5f` — PRF setup provisioning
- `b66e25b` — native sign execution
- `9542acd` — seed recovery-bundle export
- `3f11ad8` — seed setup sealing

### Result after merge
- persisted profiles now carry real backend metadata instead of scaffold-only state
- `setup` is no longer metadata-only for `native`, `prf`, and `seed`
- `derive` can use persisted PRF roots and sealed-seed state
- native sign can execute against persisted native setup state
- seed recovery export exists as an explicit high-friction path

### Validation
- `cargo test -p tpm2-derive` passed
- latest pass count seen in this cycle: `54 tests`

## Cycle 2 — 2026-04-20

### Merged this cycle
- `ae59a18` — ops root cleanup / non-orphan note / seed setup coverage
- `1aaf208` — seed recovery bundle import path
- `e7b9a73` — native verify vertical slice
- `e9971b0` — seed-mode ssh-agent ed25519 slice
- `d402c49` — `tpm2ssh` managed flow via `tpm2-derive`

### Result after merge
- native verify is now usable for the first real end-to-end verify path
- seed-mode ssh-agent add exists for `ed25519`
- recovery restore is now possible at library level
- `tpm2ssh` started consuming `tpm2-derive` instead of relying only on legacy direct TPM handling
- `src/ops.rs` concern was checked and clarified: it is intentional module structure, not dead/orphan code

### Validation
- `cargo test -p tpm2-derive` passed
- latest pass count seen in this cycle: `65 tests`
- `cargo test -p tpm2ssh` passed (`3 tests`)
- `cargo check` passed

## Next cycle targets
1. add CLI command path for recovery import / restore
2. expand `ssh agent add` beyond seed `ed25519`
3. expand verify coverage and tighten native UX
4. continue migrating `tpm2ssh` off the legacy flow
5. decide whether to hide or implement remaining placeholders (`encrypt`, `decrypt`, other unsupported mode combinations)
