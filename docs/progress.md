# TPM2 Derive Progress

_As of 2026-04-20._

## Current state

### Working slices
- `inspect`: real TPM/tooling capability probe.
- `setup --mode native`: now materializes native TPM setup and persists locator metadata.
- `setup --mode prf`: now provisions PRF root material and persists paths/metadata.
- `setup --mode seed`: now seals a seed and persists seed metadata/blob paths.
- `derive`: works for persisted `prf` and `seed` profiles.
- `sign`: native sign now executes when native setup state exists; otherwise returns a concrete planned result.
- `export --kind public-key`: works for native profiles.
- `export --kind recovery-bundle`: works for seed profiles with explicit confirmations and explicit output path.

### Still missing / partial
- `verify`
- `ssh agent add`
- recovery import / restore consume path
- richer TPM auth flows
- PRF/seed sign support
- encrypt/decrypt
- tighter native verify/export/sign end-to-end UX

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

### Left for next cycle
1. implement `verify`
2. implement `ssh agent add`
3. tighten seed setup tests / warnings cleanup
4. add recovery import path
5. continue making the CLI usable end-to-end without planned placeholders
