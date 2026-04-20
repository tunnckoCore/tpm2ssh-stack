# tpm2-derive

TPM-backed key operations with native, PRF, and seed modes.

## Design intent

`tpm2-derive` is the shared core for TPM-backed and TPM-gated key workflows in this workspace.

It is being built around three execution modes:

- **native** — use TPM-native key operations when the local TPM supports the requested algorithm/operation combination.
- **prf** — keep a TPM-resident secret and use TPM-backed PRF/HMAC-style derivation when the TPM can act as a deterministic oracle over labeled context.
- **seed** — keep a high-entropy seed sealed in the TPM, then derive child material in software with strong domain separation when native or PRF support is unavailable or unsuitable.

## Goals

- library-first architecture reusable by `tpm2ssh` and future tools
- non-interactive, automation-friendly CLI
- capability detection and mode recommendation
- explicit and high-friction secret export path for recovery only
- security-first handling of secret material

## Status

Scaffold / planning stage.

See `../docs/TPM2_DERIVE_PLAN.md` for the current architecture and CLI plan.
