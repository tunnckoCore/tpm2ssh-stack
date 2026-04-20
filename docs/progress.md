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
1. drop `tpm2ssh` from workspace members in root `Cargo.toml` (do NOT touch `tpm2ssh/` directory)
2. add seed-mode `sign` / `verify` for `ed25519`, `p256`, and `secp256k1`
3. rename `recovery import` to top-level `import` (no alias, no compatibility shim)
4. simplify recovery export confirmations:
   - require `--confirm`, `--confirm-phrase`, and `--reason`
   - drop `--confirm-recovery-export`, `--confirm-sealed-at-rest-boundary`, `--confirm-imported-seed-material`
   - import requires `--confirm` only
5. enforce use-case boundaries:
   - valid uses: `sign`, `verify`, `ssh-agent`, `derive`, `encrypt`, `decrypt` (drop `ssh` / `ethereum`)
   - `derive` must fail for profiles without `use=derive`
   - `ssh-agent add` must fail for profiles without `use=ssh-agent`
   - mode/use enforcement:
     - `prf` mode allows: `ssh-agent`, `derive`; throw on `sign`, `verify`, `encrypt`, `decrypt`
     - `seed` mode allows: everything
     - `native` mode allows: `sign`, `verify` (and public-key export), throw on else
   - add tests for all enforcement directions
6. SSH UX: keep dedicated `ssh-agent add` command AND add `derive --ssh-agent-add` flag (both work)
7. clean `docs/TPM2_DERIVE_COMBINATIONS.md`:
   - add `Recovery Import` column
   - remove PRF troubleshooting section
   - remove all meta-talk ("important distinction", "SSH doesn't mean ed25519", "higher-level wrapper" etc)
   - make `seed` the default practical framing
8. tighten state layout on-disk permissions:
   - dirs `0700`, files `0600`
   - document what lives under `profiles/`, `objects/`, `exports/`
9. implement `encrypt` / `decrypt` for the modes: `native` and `seed` only (prf cannot, you must derive keypair from the returned prf, or just use `keygen --from-profile`)
10. add `keygen` command:
    - no stdin; accepts `--from-profile` (`--profile` as alias) and `--kind auto|prf|seed`
    - `--kind` defaults to `auto` which tries `prf` first, then `seed`, otherwise throws
    - emits secret/public keypair with `--format` output flag, and optional output location
    - this is our architecture-specific keygen, not a general-purpose keygen
