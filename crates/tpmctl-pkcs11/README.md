# tpmctl-pkcs11

Minimal `cdylib` PKCS#11 provider for exposing one TPM-backed P-256 ECDSA signing key to OpenSSH-style clients.

This crate is intentionally separate from `tpmctl-cli` so CLI builds do not compile PKCS#11 entrypoints or depend on PKCS#11-specific crates.

## Build and runtime packages

Build-time requirements:

- Rust toolchain
- C toolchain/linker
- `pkg-config`
- TPM2-TSS development files visible to `pkg-config` (`tss2-sys`, `tss2-esys`, `tss2-tctildr`, `tss2-mu`)

Typical package examples:

```bash
# Debian/Ubuntu
sudo apt-get install pkg-config libtss2-dev

# Fedora
sudo dnf install pkgconf-pkg-config tpm2-tss-devel
```

Runtime requirements:

- TPM2-TSS runtime libraries
- a reachable TPM 2.0 device or simulator through `TPM2TOOLS_TCTI`, `TCTI`, `TEST_TCTI`, or the default device TCTI
- a TPM-backed P-256 signing key referenced by persistent handle or saved context
- a matching P-256 public key in DER or PEM SubjectPublicKeyInfo form

## Configuration

Required:

```bash
export TPM2_PKCS11_KEY_HANDLE=0x81000001
export TPM2_PKCS11_KEY_PUBLIC_DER=/path/to/public.der
# or:
# export TPM2_PKCS11_KEY_PUBLIC_PEM=/path/to/public.pem
```

Optional:

```bash
export TPM2_PKCS11_KEY_LABEL=tpm2-key
export TPM2_PKCS11_KEY_ID=tpm2-key
export TPM2TOOLS_TCTI=device
```

`TPM2_PKCS11_KEY_HANDLE` can be a persistent TPM handle such as `0x81000001` or a path to a saved `TPMS_CONTEXT` file. The public key file must be P-256 SubjectPublicKeyInfo DER or PEM; OpenSSH `.pub` lines are not accepted directly.

## Build

```bash
cargo build -p tpmctl-pkcs11 --release
```

Linux artifact:

```text
target/release/libtpmctl_pkcs11.so
```

## OpenSSH quick start

```bash
eval "$(ssh-agent -s)"
ssh-add -s ./target/release/libtpmctl_pkcs11.so
ssh-add -L
```

## Simulator quick check

If you are testing against `swtpm`, start a simulator and point TPM2-TSS at it:

```bash
mkdir -p /tmp/tpmctl-swtpm
swtpm socket \
  --tpm2 \
  --tpmstate dir=/tmp/tpmctl-swtpm \
  --server type=tcp,host=127.0.0.1,port=2321 \
  --ctrl type=tcp,host=127.0.0.1,port=2322 \
  --flags not-need-init

export TEST_TCTI='swtpm:host=127.0.0.1,port=2321'
```

You still need a TPM-resident P-256 signing key and matching public key file for the PKCS#11 provider to expose an object.

## Scope

Implemented PKCS#11 surface is deliberately narrow:

- fixed slot id `1`
- one token if the environment resolves to a key
- one public object and one private object
- empty user PIN
- `CKM_ECDSA` signing
- raw 64-byte P1363 `r || s` ECDSA signatures

Unsupported by design:

- PKCS#11 key generation or object storage
- certificates
- verify, encrypt, decrypt, wrap, unwrap, derive, random APIs
- multipart signing
- non-P-256 keys

## Security notes

The private key remains TPM-backed, but the provider is intentionally small and process-local. The loading application can request signatures after the module is loaded. Configure environment variables in the same environment that starts `ssh-agent` or the consuming process, avoid exposing key context files unnecessarily, and prefer hardware-backed persistent handles for long-lived keys.
