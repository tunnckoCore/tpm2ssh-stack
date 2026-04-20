# tpm2ssh-stack

Consolidated stack repo for TPM-backed key tooling.

## Layout

- `tpm2-derive` — shared TPM-backed core with `native`, `prf`, and `seed` modes
- `tpm2ssh` — SSH/Git-focused integration crate
- `docs` — architecture and planning docs
- `flow.sh` — helper script for the stack

Build artifacts and local test keys are intentionally ignored.
