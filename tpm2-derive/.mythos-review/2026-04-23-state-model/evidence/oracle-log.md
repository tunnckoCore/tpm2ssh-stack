# Oracle Log

## Commands run

### Capability layer claims PRF supports one-sided use sets
```bash
cargo test prf_support_matches_the_current_identity_surface -- --nocapture
```
Result: PASS
Key observation: `backend::recommend::tests::prf_support_matches_the_current_identity_surface` asserts PRF support for `Verify`, `Encrypt+Decrypt`, `Ssh`, and `ExportSecret`-only vectors as individually supported report surfaces.

### Setup rejects ssh-without-sign
```bash
cargo test setup_rejects_ssh_without_sign_use_contract -- --nocapture
```
Result: PASS
Key observation: setup rejects ssh-only identities via `UseCase::validate_for_mode` contract.

### Setup rejects decrypt-without-encrypt
```bash
cargo test setup_rejects_decrypt_without_encrypt_use_contract -- --nocapture
```
Result: PASS
Key observation: setup rejects decrypt-only identities via coupled-use contract.

### Setup rejects verify-without-sign
```bash
cargo test setup_rejects_verify_only_use_contract -- --nocapture
```
Result: PASS
Key observation: setup rejects verify-only identities via coupled-use contract.

## Validation conclusion
The repository's own tests prove a real contract drift:
- recommendation/support layer says these use sets are supported in PRF/Seed paths;
- setup/enforcement layer refuses them.

This is a validated failure mode in the state/model truthfulness layer, not a speculative concern.
