# tpmctl

`tpmctl` is being split into a library-first Rust workspace for TPM-backed key workflows.

## Workspace layout

- `crates/tpmctl-core` — reusable library code. It owns TPM helper APIs and derived-key crypto helpers. It does not contain CLI parsing or PKCS#11 entrypoints.
- `crates/tpmctl-cli` — the future `tpmctl` command-line binary. In this worktree it is only a minimal scaffold so the workspace can build.
- `crates/tpmctl-pkcs11` — a separate `cdylib` PKCS#11 provider crate for OpenSSH-compatible sign-only workflows.

PKCS#11 support is intentionally isolated from the CLI crate. Building the CLI should not compile PKCS#11 entrypoint code or require `pkcs11-sys`.

## Build

```bash
cargo build
cargo build -p tpmctl-core
cargo build -p tpmctl-cli
cargo build -p tpmctl-pkcs11 --release
```

On Linux, the PKCS#11 release artifact is typically:

```text
target/release/libtpmctl_pkcs11.so
```

## Runtime and build packages

The TPM-backed pieces use TPM2-TSS through `tss-esapi`. Systems need TPM2-TSS libraries available at build and runtime.

Typical build-time requirements:

- Rust toolchain
- `pkg-config`
- TPM2-TSS development files visible to `pkg-config`, including:
  - `tss2-sys`
  - `tss2-esys`
  - `tss2-tctildr`
  - `tss2-mu`

Typical runtime requirements:

- a reachable TPM or simulator
- TPM2-TSS runtime libraries
- a TCTI configuration, usually through one of:
  - `TPM2TOOLS_TCTI`
  - `TCTI`
  - `TEST_TCTI`

If no TCTI variable is set, the provider/core helper defaults to the device TCTI.

## Derived-key software model

Derived-key operations are not TPM-native signing operations. The intended model is:

1. TPM-protected PRF seed material is unsealed or loaded by higher-level command code.
2. `tpmctl-core::crypto` derives software keys from that seed with HKDF-SHA256 domain separation.
3. p256 and secp256k1 derivation retry until the curve library accepts a valid non-zero scalar.
4. Ed25519 derives a 32-byte signing seed and uses pure Ed25519 signing. Ed25519 signing rejects hash/prehash selection for v1.
5. Temporary seed, scalar, and intermediate buffers are zeroized where practical.
6. Software key material exists in process memory briefly; callers should avoid logging, debug dumps, and long-lived storage of derived secrets.

Supported derived helpers in this worktree:

- p256 secret/public/sign helpers
- Ed25519 secret/public/sign helpers
- secp256k1 secret/public/sign helpers
- EIP-55 checksummed Ethereum address formatting for secp256k1 public keys

## PKCS#11 provider

`crates/tpmctl-pkcs11` exposes a minimal sign-only PKCS#11 module for one TPM-backed P-256 ECDSA key configured through environment variables.

Required key configuration:

```bash
export TPM2_PKCS11_KEY_HANDLE=0x81000001   # or a saved TPMS_CONTEXT file path
export TPM2_PKCS11_KEY_PUBLIC_DER=/path/to/public.der
# alternatively:
# export TPM2_PKCS11_KEY_PUBLIC_PEM=/path/to/public.pem
```

Optional configuration:

```bash
export TPM2_PKCS11_KEY_LABEL=tpm2-key
export TPM2_PKCS11_KEY_ID=tpm2-key
export TPM2TOOLS_TCTI=device
```

Build and load with OpenSSH tools:

```bash
cargo build -p tpmctl-pkcs11 --release
eval "$(ssh-agent -s)"
ssh-add -s ./target/release/libtpmctl_pkcs11.so
ssh-add -L
```

Scope and limitations:

- one configured key
- P-256 EC only
- `CKM_ECDSA` signing only
- empty PKCS#11 user PIN and empty TPM auth in the current scaffold
- no key generation, certificate storage, random, wrap/unwrap, derive, or multipart sign APIs

## Development checks

```bash
cargo fmt --all
cargo check --workspace --all-targets
cargo test --workspace
cargo build
```
