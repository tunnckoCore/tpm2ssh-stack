# tpm2ssh

Consolidated stack repo for the TPM-backed SSH tooling and related services.

## Layout

- `tpm2ssh` — main TPM-backed SSH / Git signing tool
- `tpm2ssh-prfd` — PRF backend service
- `docs` — workspace docs
- `flow.sh` — helper script for the stack

This repo preserves the original `tpm2ssh` history and also imports the local `tpm2ssh-prfd` history.

Build artifacts and local test keys are intentionally ignored.
