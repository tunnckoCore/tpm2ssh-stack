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
- `verify`:
  - native `p256` works
  - seed `ed25519` works
- `export --kind public-key`:
  - native `p256` works
  - seed `ed25519` works
  - seed `p256` works
  - seed `secp256k1` works
  - formats now include `spki-der`, `spki-pem`, `spki-hex`, and `openssh` where wired
- `export --kind recovery-bundle`: works for seed profiles with explicit confirmations and explicit output path.
- `recovery import`: CLI path now exists via `tpm2-derive recovery import`.
- `ssh agent add`:
  - seed `ed25519` works
  - seed `p256` works
- `tpm2ssh`: now has managed flows using `tpm2-derive` and now covers managed seed P-256 SSH support too.

### Notes
- `tpm2-derive/src/ops.rs` is **not** orphaned; it is the real `crate::ops` module root referenced by `tpm2-derive/src/lib.rs`.
- SSH in this project is **not** Ed25519-only. P-256 is a valid SSH/Git flow too.

### Still missing / partial
- broader verify coverage beyond native `p256` and seed `ed25519`
- broader `ssh agent add` coverage beyond seed `ed25519` / seed `p256`
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

### Validation
- `cargo test -p tpm2-derive` passed
- latest pass count seen in this cycle: `65 tests`
- `cargo test -p tpm2ssh` passed (`3 tests`)
- `cargo check` passed

## Cycle 3 — 2026-04-20

### Landed this cycle
- clap help text for top-level commands, subcommands, flags, and enum values
- user-facing combinations guide: `docs/TPM2_DERIVE_COMBINATIONS.md`
- troubleshooting note for the common PRF-under-sudo TCTI/Tabrmd failure mode

### Validation
- `cargo test -p tpm2-derive` passed
- verified help output by building with a temporary cargo target dir and checking `--help`

## Cycle 4/5 — 2026-04-20

### Merged this cycle
- `6970853` — seed-mode public key export
- `1aafdd7` — public key export formats
- `1bf76e6` — managed seed P-256 SSH support
- `d39e517` — p256 SSH/signing docs clarification
- `805d59f` — seed ed25519 verify support
- `ec4ae63` — recovery import CLI path

### Result after merge
- seed-mode public export is real for `ed25519`, `p256`, and `secp256k1`
- export formats now support binary DER plus armor/hex variants
- direct ssh-agent flow now covers seed `p256` in addition to seed `ed25519`
- recovery import is no longer library-only; it has a CLI command path
- docs/help now stop implying SSH means Ed25519 only

### Validation
- `cargo test -p tpm2-derive` passed
- latest pass count seen in this cycle: `78 tests`
- `cargo test -p tpm2ssh` passed (`4 tests`)
- `cargo check` passed

## Next cycle targets
1. add seed-mode `sign` / `verify` for `ed25519`, `p256`, and `secp256k1`
2. simplify recovery import/export UX:
   - prefer `import` over `recovery import`
   - reduce confirmation flags to `--confirm` AND `--confirm-phrase` - both required
   - the `--reason` remains required
3. enforce use-case boundaries:
   - `derive` should fail for profiles without `use=derive`
   - `ssh-agent add` should require ssh/ssh-agent use, not derive use
   - add tests for both directions
4. clean `docs/TPM2_DERIVE_COMBINATIONS.md`:
   - add `Recovery Import` column
   - remove user-specific PRF troubleshooting AND the meta-talk
   - make `seed` the default practical framing
5. review state layout and on-disk permissions:
   - document exactly what is stored under `profiles/`, `objects/`, `exports/`
   - tighten permissions where appropriate
6. decide and implement SSH UX direction:
   - rename toward `ssh-agent add`, or
   - fold agent-loading UX into another command if that stays coherent
7. implement `encrypt` / `decrypt`
8. design and add `keygen`:
   - accept derived material from our `derive` command, or direct input
   - emit secret/public keypair with format selection, and optional output location
   - optionally support a structured envelope from `derive`, but do not pretend stdin provenance can be strongly enforced without extra cryptographic design
