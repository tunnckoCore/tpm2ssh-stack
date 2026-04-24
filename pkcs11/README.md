# tpm2-derive-pkcs11

A tiny Rust `cdylib` that exposes **one TPM-backed P-256 ECDSA key** through the PKCS#11 API.

It is designed for the narrow case of making a TPM-resident key usable by tools that already understand PKCS#11, especially:

- `ssh-agent` / `ssh-add -s`
- `ssh -I ...`
- GitHub SSH authentication
- Git SSH commit signing

This is **not** a general-purpose PKCS#11 token implementation. It intentionally skips token storage, key generation, object management, and most of the PKCS#11 surface.

## What it does

At initialization, the library reads a small set of environment variables, loads exactly one public key, and exposes it as:

- one PKCS#11 public key object
- one PKCS#11 private key object

When a caller asks the private key to sign, the library opens a TPM ESAPI context in-process, loads the configured key handle or saved context, calls `Esys_Sign`, and returns the raw ECDSA signature.

The private key material never leaves the TPM-backed signing path.

## What it expects

### Required

Set these before loading the provider:

```bash
export TPM2_PKCS11_KEY_HANDLE=/path/to/key.ctx # or handle
export TPM2_PKCS11_KEY_PUBLIC_DER=/path/to/public.der
# or instead of *_DER:
# export TPM2_PKCS11_KEY_PUBLIC_PEM=/path/to/public.pem
```

### Optional

```bash
export TPM2_PKCS11_KEY_LABEL=tpm2-key
export TPM2_PKCS11_KEY_ID=tpm2-key
export TPM2TOOLS_TCTI=device
# or, for example:
# export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
```

### Environment variable reference

| Variable | Required | Meaning |
| --- | --- | --- |
| `TPM2_PKCS11_KEY_HANDLE` | yes | TPM key reference. Supported forms are a persistent handle like `0x81000001` or a path to a saved `TPMS_CONTEXT` file. |
| `TPM2_PKCS11_KEY_PUBLIC_DER` | yes* | Public key in **DER SubjectPublicKeyInfo** format. |
| `TPM2_PKCS11_KEY_PUBLIC_PEM` | yes* | Public key in **PEM SubjectPublicKeyInfo** format. Used only if `*_DER` is not set. |
| `TPM2_PKCS11_KEY_LABEL` | no | PKCS#11 `CKA_LABEL`. Defaults to `tpm2-key`. |
| `TPM2_PKCS11_KEY_ID` | no | PKCS#11 `CKA_ID`. Defaults to the label bytes. |
| `TPM2TOOLS_TCTI` / `TCTI` / `TEST_TCTI` | no | TPM TCTI configuration used to open the TPM connection. If unset, the library defaults to the device TCTI. |

\* You must provide either `TPM2_PKCS11_KEY_PUBLIC_DER` or `TPM2_PKCS11_KEY_PUBLIC_PEM`.

## Important format note

The public key file must be a **DER or PEM-encoded SubjectPublicKeyInfo** key that `p256` can parse.

An OpenSSH public key like this is **not** accepted directly:

```text
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY...
```

If you only have an OpenSSH `.pub`, convert or export the key in PEM/DER SPKI form first.

## Requirements

Build-time:

- Rust toolchain
- `pkg-config`
- TPM2-TSS development files visible to `pkg-config`:
  - `tss2-sys`
  - `tss2-esys`
  - `tss2-tctildr`
  - `tss2-mu`

Runtime:

- A reachable TPM via a supported TCTI (`TPM2TOOLS_TCTI`, `TCTI`, or default device TCTI)
- A TPM-backed **P-256** signing key referenced by persistent handle or saved context file
- A matching public key in DER or PEM SPKI form

## Build

From this crate directory:

```bash
cargo build
```

Or from the workspace root:

```bash
cargo build -p tpm2-derive-pkcs11
```

On Linux, the library will typically be:

```bash
target/debug/libtpm2_derive_pkcs11.so
```

For a release build:

```bash
cargo build --release
```

Artifact:

```bash
target/release/libtpm2_derive_pkcs11.so
```

## Quick start with ssh-agent

```bash
eval "$(ssh-agent -s)"
ssh-add -s ./target/debug/libtpm2_derive_pkcs11.so
ssh-add -L
```

If everything is wired correctly, `ssh-add -L` should print the SSH public key exposed by the provider.

## Use directly with ssh

You can bypass agent loading and point OpenSSH at the PKCS#11 library directly:

```bash
ssh -I ./target/debug/libtpm2_derive_pkcs11.so -T git@github.com
```

## GitHub SSH authentication

After loading the provider into the agent:

```bash
ssh-add -L > ~/.ssh/tpm2-github.pub
```

Upload that public key to GitHub as an SSH authentication key, then test:

```bash
ssh -T git@github.com
```

## Git commit signing with SSH

Load the provider first:

```bash
ssh-add -s ./target/debug/libtpm2_derive_pkcs11.so
```

Export the public key that Git should use for SSH signing:

```bash
ssh-add -L > ~/.ssh/tpm2-git-signing.pub
```

Configure Git:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/tpm2-git-signing.pub
```

For local verification, create an allowed signers file:

```bash
printf "%s %s\n" "$USER" "$(cat ~/.ssh/tpm2-git-signing.pub)" > ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

Now sign commits:

```bash
git commit -S -m "test"
```

Verify locally:

```bash
git log --show-signature -1
```

To have GitHub show SSH-signed commits as verified, upload the same public key to GitHub as an SSH signing key.

## PKCS#11 behavior and scope

This library intentionally implements only the small subset needed for the target workflow.

### Exposed token model

- one fixed slot (`slot id 1`)
- one token when the environment variables resolve to a key
- one public object + one private object for that key
- login supported with an **empty user PIN**
- TPM authorization is currently also treated as empty

### Supported mechanism

- `CKM_ECDSA`

### Signing behavior

The `C_Sign` path expects a **digest**, not an arbitrary message blob. Internally the library accepts digest sizes of:

- 32 bytes → `sha256`
- 48 bytes → `sha384`
- 64 bytes → `sha512`

It passes the digest to the TPM through `Esys_Sign` and returns a raw 64-byte P1363-style `r || s` ECDSA signature.

## Limitations

This crate is intentionally minimal. Some important non-goals:

- only **one** configured key
- only **P-256 EC** keys
- only **ECDSA signing**
- only keys with **empty TPM auth** are currently supported
- no PKCS#11 verify operation implementation
- no key generation
- no persistent PKCS#11 object store
- no certificate objects
- no wrap/unwrap/derive/random APIs
- no multipart signing (`C_SignUpdate` / `C_SignFinal` are not supported)
- not a drop-in replacement for a full HSM or `tpm2-pkcs11`

## Troubleshooting

### `ssh-add -s ...` does not show a key

Make sure the environment variables are set in the same environment where `ssh-add` loads the library.

At minimum:

```bash
env | grep -E '^(TPM2_PKCS11_|TPM2TOOLS_TCTI|TCTI|TEST_TCTI)'
```

### Public key load fails

Check that the public key is:

- for the same TPM key
- P-256
- PEM or DER SubjectPublicKeyInfo
- not an OpenSSH `.pub` file

### Signing fails

Check:

- the TPM is reachable through the selected TCTI
- `TPM2_PKCS11_KEY_HANDLE` points to a valid persistent handle or saved context
- the referenced object is usable for P-256 ECDSA signing
- the public key file actually matches the TPM key

If you use a non-default transport, set it explicitly, for example:

```bash
export TPM2TOOLS_TCTI=device
```

### Build fails because `pkg-config` cannot find `tss2-*`

Make sure the TPM2-TSS development output is visible to `pkg-config`.

On NixOS this often means building inside a shell that includes `tpm2-tss.dev`, or exporting a `PKG_CONFIG_PATH` that contains the `tpm2-tss.dev` `lib/pkgconfig` directory.

## Security notes

- The private key is not loaded into Rust memory as a software key.
- The library performs signing in-process through TPM2-TSS instead of spawning `tpm2_sign`.
- This removes the extra attack surface of `PATH` lookup or external signer binary substitution.
- The implementation keeps only in-memory metadata for the exposed PKCS#11 objects and sessions.

## Summary

If you have a TPM-backed P-256 key and just want a very small PKCS#11 bridge for SSH-style workflows, this crate does that. If you need a complete PKCS#11 token implementation, this crate is intentionally too small for that job.
