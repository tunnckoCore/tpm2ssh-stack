# tpm2ssh

Consolidated stack repo for the TPM-backed SSH tooling and related services.

## Layout

- `tpm2ssh` — main TPM-backed SSH / Git signing tool
- `tpm2ssh-prfd` — PRF backend service
- `docs` — workspace docs
- `flow.sh` — helper script for the stack

This repo preserves the original `tpm2ssh` history and also imports the local `tpm2ssh-prfd` history.

Build artifacts and local test keys are intentionally ignored.

---

 A few better options:                   
 - TPM-native where possible, TPM-sealed seed derivation where necessary                       
 - Adaptive TPM-backed key operations with sealed-seed fallback                                
 - TPM-backed key operations with native and sealed-seed modes                                 
 - Use native TPM crypto when available; fall back to TPM-sealed seed derivation when not

 ---
 
 session `019da94a-3c33-768b-bc9c-53562d131fb0` at `/home/arcka/code/tpm2ssh-stack`
