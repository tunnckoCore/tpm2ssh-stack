# tpmctl

`tpmctl` is a library-first Rust workspace for TPM-backed key workflows. The intended shape is:

- reusable TPM and registry APIs in `tpmctl-core`
- a thin `tpmctl` CLI in `tpmctl-cli`
- a separately built PKCS#11 provider in `tpmctl-pkcs11`

PKCS#11 support is intentionally isolated from the CLI crate. Building the CLI does not compile PKCS#11 entrypoint code and does not need `pkcs11-sys`.

## Current implementation status

The workspace, parser/validation layer, output encoders, registry path safety, derived-key software helpers, and PKCS#11 crate boundary are implemented and tested. Several TPM runtime command bodies are still incomplete; where a command has not yet been wired to TPM object creation/loading/signing/sealing, it returns an unsupported/TPM-unavailable error rather than pretending to succeed.

Remaining TPM-runtime work includes reloadable `keygen`, TPM `Sign`, direct-handle `ReadPublic` command wiring, `ECDH_ZGen`, TPM HMAC sequence/one-shot command wiring, seal/unseal persistence, and the hmac-to-seal convenience path. Use the plan checklist as the source of truth before depending on a command in production.

## Workspace layout

- `crates/tpmctl-core` — reusable library code. Owns TPM helper APIs, registry storage, command-domain contracts, output encoders, and derived-key crypto helpers. It contains no CLI parsing and no PKCS#11 entrypoints.
- `crates/tpmctl-cli` — `tpmctl` binary. Owns clap parsing, validation, stdout/stderr policy, TTY guards, and thin dispatch into `tpmctl-core`.
- `crates/tpmctl-pkcs11` — separate `cdylib` PKCS#11 provider crate for OpenSSH-compatible sign-only workflows.

## Build

From the workspace root:

```bash
cargo build
cargo build -p tpmctl-core
cargo build -p tpmctl-cli
cargo build -p tpmctl-pkcs11 --release
```

Typical Linux PKCS#11 release artifact:

```text
target/release/libtpmctl_pkcs11.so
```

Development checks:

```bash
cargo fmt --all
cargo check --workspace --all-targets
cargo test --workspace
cargo build
```

## Runtime and build packages

The TPM-backed pieces use TPM2-TSS through `tss-esapi`; no normal command path should shell out to `tpm2_*` binaries.

Build-time requirements:

- Rust toolchain
- C toolchain/linker appropriate for Rust native dependencies
- `pkg-config`
- TPM2-TSS development files visible to `pkg-config`, including:
  - `tss2-sys`
  - `tss2-esys`
  - `tss2-tctildr`
  - `tss2-mu`

Common Debian/Ubuntu package names are typically similar to:

```bash
sudo apt-get install pkg-config libtss2-dev
```

Common Fedora package names are typically similar to:

```bash
sudo dnf install pkgconf-pkg-config tpm2-tss-devel
```

Runtime requirements:

- a reachable TPM 2.0 device or simulator
- TPM2-TSS runtime libraries
- permissions for the selected TPM device/TCTI
- a TCTI configuration, usually through one of:
  - `TPM2TOOLS_TCTI`
  - `TCTI`
  - `TEST_TCTI`

If no TCTI variable is set, core helpers default to the device TCTI (`device:/dev/tpmrm0` in the current helper path).

## TPM simulator instructions

Integration tests that need a live TPM are gated. They run when a TCTI environment variable is already set or when `swtpm` is installed and the test harness can start it. Without either, the simulator test prints a skip message and returns successfully.

Using an already-running simulator:

```bash
export TEST_TCTI='swtpm:host=127.0.0.1,port=2321'
cargo test --workspace
```

Starting `swtpm` manually for local testing:

```bash
mkdir -p /tmp/tpmctl-swtpm
swtpm socket \
  --tpm2 \
  --tpmstate dir=/tmp/tpmctl-swtpm \
  --server type=tcp,host=127.0.0.1,port=2321 \
  --ctrl type=tcp,host=127.0.0.1,port=2322 \
  --flags not-need-init

# in another shell
export TEST_TCTI='swtpm:host=127.0.0.1,port=2321'
cargo test --workspace
```

A fresh `swtpm` may need TPM2_Startup before normal commands. The simulator integration harness attempts startup if the first RNG command reports that startup is needed.

## CLI examples

The CLI parser and validation layer support the planned command surface. TPM runtime command bodies may still return unsupported until the remaining TPM checklist items are completed.

```bash
# key creation
tpmctl keygen --use sign --id org/acme/alice/main
tpmctl keygen --use ecdh --id org/acme/alice/comms
tpmctl keygen --use hmac --id org/acme/alice/kdf
tpmctl keygen --use sign --id org/acme/alice/main --handle 0x81010010

# public key export
tpmctl pubkey --id org/acme/alice/main --format pem > alice-main.pem
tpmctl pubkey --id org/acme/alice/main --format ssh
tpmctl pubkey --handle 0x81010010 --format der --output alice-main.der

# signing
tpmctl sign --id org/acme/alice/main --input message.txt --format der --output sig.der
tpmctl sign --id org/acme/alice/main --digest message.sha256 --format hex

# ECDH/HMAC
tpmctl ecdh --id org/acme/alice/comms --peer-pub bob-comms.pem --format hex
tpmctl hmac --id org/acme/alice/kdf --input ctx.bin --hash sha512 --format hex

# seal/unseal
tpmctl seal --input secret.bin --id org/acme/alice/sealed/foo
tpmctl unseal --id org/acme/alice/sealed/foo --output secret.bin

# derived software keys from TPM-protected PRF seed material
tpmctl derive --id org/acme/alice/derived/foo --label user1 --algorithm ed25519 --format hex
tpmctl derive --id org/acme/bob/derived/eth-prf --use pubkey --algorithm secp256k1 --format address
tpmctl derive --handle 0x81010020 --algorithm p256 --use sign --input message.txt --format hex
```

Global behavior:

- `--store <path>` overrides `TPMCTL_STORE`, which overrides the XDG default store root.
- Use `-` for stdin/stdout where file input/output is expected.
- Raw binary stdout is rejected on an interactive TTY unless `--force` is supplied.
- Operations over existing material require exactly one of `--id <id>` or `--handle <handle>`.

## Derived-key software model

Derived-key operations are intentionally not TPM-native p256/Ed25519/secp256k1 operations. The model is:

1. TPM-protected PRF seed material is unsealed or loaded by higher-level command code.
2. `tpmctl-core::crypto` derives software keys from that seed with HKDF-SHA256 domain separation over algorithm/use/label or ephemeral randomness.
3. p256 and secp256k1 scalar derivation retry with a counter until the curve library accepts a valid non-zero scalar.
4. Ed25519 derives a 32-byte signing seed and uses pure Ed25519 signing. Ed25519 signing rejects hash/prehash selection for v1; `--digest` bytes are treated as the message bytes to sign, not as Ed25519ph.
5. Temporary seed, scalar, and intermediate buffers are zeroized where practical.
6. Software key material exists in process memory briefly. Avoid logging, debug dumps, core dumps, swap exposure, and long-lived storage of derived secrets.

Supported derived helpers in this workspace:

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
- empty PKCS#11 user PIN and empty TPM auth in the current implementation
- no key generation, certificate storage, random, wrap/unwrap, derive, or multipart sign APIs

## Remaining hardware requirements

For production TPM-backed flows, use a TPM 2.0 implementation with:

- ECC P-256 signing and ECDH support where those commands are required
- keyed-hash/HMAC support for HMAC/PRF workflows
- persistent handle space available under the owner hierarchy when `--handle` persistence is used
- stable owner hierarchy policy and authorization compatible with the current empty-auth v1 model
- platform permissions that allow the process to access the TPM resource manager or configured TCTI

TPM private blobs and sealed objects are not expected to be portable across TPMs.
