# tpmctl-pkcs11

Minimal `cdylib` PKCS#11 provider for exposing one TPM-backed P-256 ECDSA signing key to OpenSSH-style clients.

This crate is intentionally separate from `tpmctl-cli` so CLI builds do not compile PKCS#11 entrypoints or depend on PKCS#11-specific crates.

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

`TPM2_PKCS11_KEY_HANDLE` can be a persistent TPM handle such as `0x81000001` or a path to a saved `TPMS_CONTEXT` file. The public key file must be P-256 SubjectPublicKeyInfo DER or PEM.

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

## Scope

Implemented PKCS#11 surface is deliberately narrow:

- fixed slot id `1`
- one token if the environment resolves to a key
- one public object and one private object
- empty user PIN
- `CKM_ECDSA` signing
- raw 64-byte P1363 `r || s` ECDSA signatures

Unsupported by design in this scaffold:

- PKCS#11 key generation or object storage
- certificates
- verify, encrypt, decrypt, wrap, unwrap, derive, random APIs
- multipart signing
- non-P-256 keys
