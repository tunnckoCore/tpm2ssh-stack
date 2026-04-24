---
title: "tpmctl TPM Key CLI"
date: 2026-04-24
author: "arcka"
status: Draft
---

# Plan: `tpmctl` TPM Key CLI

## Source

- **Source**: Conversation-defined CLI/API design for TPM-backed key management, signing, ECDH, HMAC, sealing, unsealing, and derived software keys.
- **Repository**: `tpm2ssh-stack`
- **Date**: 2026-04-24
- **Author**: arcka

## Goals

- Build a library-first TPM toolkit using TPM2-TSS APIs through Rust, not `tpm2_*` binaries.
- Put the reusable core library, CLI, and PKCS#11 provider in three separate crates under `crates/`.
- Keep `tpmctl` as a thin CLI over the core library, not the place where core behavior lives.
- Keep PKCS#11/OpenSSH support as a separate module crate that depends on the core library.
- Support named local identities via `--id` and direct persistent TPM handles via `--handle`.
- Support TPM-backed signing, public key export, ECDH, HMAC, sealing, and unsealing.
- Support PRF-derived ephemeral/deterministic software keys for p256, Ed25519, and secp256k1 helper workflows.

## Non-Goals

- Do not implement a full TPM management suite.
- Do not depend on `tpm2-tools` binaries for normal operation.
- Do not make derived (`derive` command) p256/Ed25519/secp256k1 operations TPM-native; they are software operations over TPM-protected PRF material.
- Do not support key auth in v1; created keys and loaded TPM objects use empty auth.
- Do not put PKCS#11 support in the default CLI crate; build it through the separate `tpmctl-pkcs11` crate.
- Do not attempt cross-TPM portability for key private blobs or sealed objects.

## Architecture Overview

The project should be reorganized as a library-first workspace. `crates/tpmctl-core` owns TPM/TSS integration, local registry storage, command-domain operations, output encoders, and derived-key crypto. `crates/tpmctl-cli` is a thin command-line wrapper over the core library. `crates/tpmctl-pkcs11` is a separate `cdylib` provider crate for OpenSSH/PKCS#11 workflows and depends on the core library for TPM operations.

The CLI should contain argument parsing, validation, stdout/stderr behavior, and dispatch only. TPM semantics should live in the core library so other frontends can reuse them without invoking the CLI. The PKCS#11 provider should not be a feature on the CLI; it should be a separate crate and artifact that can be built only when needed.

Derived key operations are deliberately separate from TPM signing. `derive` unseals or loads PRF material protected by TPM state, derives a p256/Ed25519/secp256k1 software key, performs the requested operation, zeroizes sensitive buffers, and exits.

## Proposed Layout

```text
crates/
  tpmctl-core/
    Cargo.toml
    src/
      lib.rs
      tpm.rs              # TPM context, TCTI, auth, handle, load helpers
      store.rs            # local registry paths, metadata, blob load/save
      keygen.rs           # key creation templates and persistence
      sign.rs             # TPM signing domain operation
      pubkey.rs           # public key export domain operation
      ecdh.rs             # TPM ECDH domain operation
      hmac.rs             # TPM HMAC and HMAC-to-seal operation
      seal.rs             # TPM seal/unseal domain operations
      output.rs           # reusable format encoding helpers
      crypto/
        mod.rs
        derive.rs         # PRF -> p256/Ed25519/secp256k1 derivation
        p256.rs
        ed25519.rs
        secp256k1.rs
        ethereum.rs       # checksummed address formatting
  tpmctl-cli/
    Cargo.toml
    src/
      main.rs
      args.rs             # clap parser and CLI validation
      commands/
        keygen.rs
        sign.rs
        pubkey.rs
        ecdh.rs
        hmac.rs
        seal.rs
        derive.rs
  tpmctl-pkcs11/
    Cargo.toml
    src/
      lib.rs              # PKCS#11 entrypoints, crate-type = ["cdylib"]
```

## Workspace Components

### `crates/tpmctl-core`

**Purpose**: Reusable library crate that implements TPM operations, local registry storage, output encoding, and derived-key crypto.

**Key Details**:

- Owns all TPM2-TSS / `tss-esapi` usage.
- Exposes typed Rust APIs for keygen, sign, pubkey, ECDH, HMAC, seal, unseal, and derive.
- Contains no CLI parser and no PKCS#11 entrypoints.

### `crates/tpmctl-cli`

**Purpose**: Thin `tpmctl` binary that validates CLI arguments and calls `tpmctl-core`.

**Key Details**:

- Owns clap parser, help text, stdout/stderr policy, and exit codes.
- Does not implement TPM semantics directly.
- Depends on `tpmctl-core`.

### `crates/tpmctl-pkcs11`

**Purpose**: OpenSSH-loadable PKCS#11 provider module.

**Key Details**:

- Builds as a `cdylib` `.so` artifact.
- Owns PKCS#11 entrypoints and `pkcs11-sys` dependency.
- Reuses TPM signing helpers from `tpmctl-core`.

## Cargo Plan

- [x] Convert the repository to a Cargo workspace with members under `crates/`.
- [x] Create `crates/tpmctl-core` as the reusable library crate.
- [x] Create `crates/tpmctl-cli` as the `tpmctl` binary crate.
- [x] Create `crates/tpmctl-pkcs11` as the PKCS#11 `cdylib` crate.
- [x] Put `tss-esapi` and TPM-domain dependencies in `tpmctl-core`.
- [x] Put `clap` and CLI-only dependencies in `tpmctl-cli`.
- [x] Put `pkcs11-sys` and PKCS#11-only dependencies in `tpmctl-pkcs11`.

Suggested workspace direction:

```toml
[workspace]
members = [
  "crates/tpmctl-core",
  "crates/tpmctl-cli",
  "crates/tpmctl-pkcs11",
]
resolver = "2"
```

Suggested crate roles:

```text
tpmctl-core    -> reusable library; no CLI parsing; no PKCS#11 entrypoints
tpmctl-cli     -> binary wrapper over tpmctl-core
tpmctl-pkcs11  -> cdylib PKCS#11 provider wrapper over tpmctl-core
```

Likely dependencies:

- [x] `clap` for CLI parsing.
- [x] `serde`, `serde_json` for local metadata and `--json`.
- [x] `zeroize` for derived secrets and software key material.
- [x] `rand_core` or `getrandom` for ephemeral derivation labels/salt.
- [x] `sha2`, `hkdf`, `hmac` for derivation.
- [x] `p256` for derived P-256 software operations and public key encoding.
- [x] `ed25519-dalek` for derived Ed25519 operations.
- [x] `k256` for derived secp256k1 operations.
- [x] `sha3` for Keccak-256 Ethereum address derivation.
- [x] `hex` for text encoding.

## Local Registry Model

Named `--id` values map to files under a local registry directory.

Default store root:

```text
${XDG_DATA_HOME:-~/.local/share}/tpmctl/
```

Store root precedence:

1. `--store <path>`
2. `TPMCTL_STORE`
3. `${XDG_DATA_HOME:-~/.local/share}/tpmctl/`

Example identity:

```text
~/.local/share/tpmctl/keys/org/acme/alice/main/
  meta.json
  public.tpm
  private.tpm
  public.pem
```

Example sealed object:

```text
~/.local/share/tpmctl/sealed/org/acme/alice/derived/foo/
  meta.json
  public.tpm
  private.tpm
```

Metadata checklist:

- [x] `id`
- [x] `kind`: `key` or `sealed`
- [x] `usage`: `sign`, `ecdh`, `hmac`, or `sealed`
- [x] `handle`: optional persistent handle
- [x] `persistent`: boolean
- [x] `curve`: for asymmetric ECC keys
- [x] `hash`: for HMAC keys and sealed HMAC output metadata
- [x] `created_at`
- [x] TPM parent/template information required to reload non-persistent objects
- [x] Public key cache where applicable

## Global CLI Rules

- [x] Support `-h` / `--help`.
- [x] Support `--version`.
- [x] Primary output goes to stdout.
- [x] Diagnostics and errors go to stderr.
- [x] Support `--json` for structured command results where useful.
- [x] Support `-o` / `--output <file>` for output-producing commands.
- [x] Support `-` as stdin/stdout where file input/output is expected.
- [x] Reject binary output to an interactive TTY unless format is text or `--force` is provided.
- [x] Support exactly one of `--id <id>` or `--handle <handle>` for operations over existing TPM material.
- [x] Make `--id` and `--handle` mutually exclusive everywhere they both appear.
- [x] Parse handles as hex strings like `0x81010010`.
- [x] Respect TCTI from `TPM2TOOLS_TCTI`, `TCTI`, or `TEST_TCTI`; otherwise default to device TCTI.
- [x] Support `--store <path>` and `TPMCTL_STORE` for local registry location, with flags taking precedence over env.
- [x] Use empty TPM object auth in v1; do not expose key auth flags yet.

## Command Specification

### `tpmctl keygen`

Create TPM-backed identities.

Examples:

```bash
tpmctl keygen --use sign --id org/acme/alice/main
tpmctl keygen --use ecdh --id org/acme/alice/comms
tpmctl keygen --use hmac --id org/acme/alice/kdf
tpmctl keygen --use sign --id org/acme/alice/main --handle 0x81010010
```

Flags:

| Flag | Required | Meaning |
| --- | --- | --- |
| `--use sign|ecdh|hmac` | yes | Key usage/template to create. |
| `--id <id>` | yes | Local registry name. |
| `--handle <handle>` | no | Persist created key at TPM persistent handle. |
| `--force` | no | Overwrite existing local ID or persistent handle if supported and safe. |
| `--json` | no | Emit structured result. |

Checklist:

- [x] Implement ECC P-256 sign key template.
- [x] Implement ECC P-256 ECDH key template.
- [x] Implement keyed-hash HMAC key template.
- [ ] Create/load parent key.
- [ ] Create child key.
- [ ] Store public/private blobs under `--id`.
- [ ] Persist key with `EvictControl` when `--handle` is provided.
- [ ] Cache/export public key for asymmetric keys.
- [ ] Reject duplicate IDs unless `--force` is provided.
- [ ] Reject occupied persistent handles unless `--force` is provided.

### `tpmctl sign`

TPM-backed signing using a signing identity or persistent handle.

Examples:

```bash
openssl dgst -sha256 -binary message.txt > message.sha256

tpmctl sign \
    --id org/acme/alice/main \
    --digest ./message.sha256 \
    --output ./sig.der

tpmctl sign \
    --id org/acme/alice/main \
    --input ./message.txt \
    --output ./sig.der

tpmctl sign \
    --id org/acme/alice/main \
    --input ./message.txt \
    --hash sha512 \
    --format der \
    --output ./sig.der

tpmctl sign \
    --id org/acme/alice/main \
    --input ./message.txt \
    --format hex \
    --output ./sig.hex

tpmctl sign \
    --id org/acme/alice/main \
    --input ./message.txt \
    --format raw
```

Rules:

- [x] Require exactly one of `--id` or `--handle`.
- [x] Require exactly one of `--input` or `--digest`.
- [x] Default `--hash` is `sha256` for `--input`.
- [x] Default `--format` is `der`.
- [x] For `--digest`, validate digest length against `--hash`.
- [x] `--format der` outputs ASN.1 DER ECDSA signature.
- [x] `--format raw` outputs P1363 `r || s` bytes.
- [x] `--format hex` outputs `hex(raw r||s)`.

Checklist:

- [ ] Load key by registry ID.
- [ ] Load key by persistent handle using `ReadPublic`/ESYS handle translation.
- [x] Validate key usage is `sign`.
- [x] Hash `--input` data according to `--hash`.
- [ ] Call TPM `Sign`.
- [x] Convert TPM signature to DER/raw/hex.
- [ ] Write to `--output` or stdout.

### `tpmctl pubkey`

Export public keys for TPM asymmetric identities.

Examples:

```bash
tpmctl pubkey --id org/acme/alice/main > alice-main.pem
tpmctl pubkey --id org/acme/alice/comms > alice-comms.pem

tpmctl pubkey --id org/acme/alice/main --format raw
tpmctl pubkey --id org/acme/alice/main --format hex
tpmctl pubkey --id org/acme/alice/main --format pem
tpmctl pubkey --id org/acme/alice/main --format der --output alice-main.der
tpmctl pubkey --id org/acme/alice/main --format ssh
```

Formats:

| Format | Meaning |
| --- | --- |
| `raw` | Raw public key bytes, default uncompressed SEC1 for ECC. |
| `hex` | `hex(raw public key bytes)`. |
| `pem` | PEM SubjectPublicKeyInfo. Default. |
| `der` | DER SubjectPublicKeyInfo. |
| `ssh` | OpenSSH public key line. |

Rules:

- [x] OpenSSH key comments use the ID with `/` replaced by `_` when exporting by `--id`.
- [x] OpenSSH key comments use the handle string when exporting by `--handle`.

Checklist:

- [x] Require exactly one of `--id` or `--handle`.
- [x] Reject HMAC and sealed objects.
- [x] Export from local cached public material where possible.
- [ ] Use `ReadPublic` for direct handles.
- [x] Implement raw/hex/pem/der/ssh encoders.

### `tpmctl ecdh`

Generate an ECDH shared secret with a TPM ECDH identity.

Examples:

```bash
tpmctl ecdh \
    --id org/acme/alice/comms \
    --peer-pub ./bob-comms.pem

tpmctl ecdh \
    --id org/acme/alice/comms \
    --peer-pub ./bob-comms.pem \
    --format raw

tpmctl ecdh \
    --id org/acme/alice/comms \
    --peer-pub ./bob-comms.pem \
    --format hex

tpmctl ecdh \
    --id org/acme/alice/comms \
    --peer-pub ./bob-comms.pem \
    --output ./shared-secret.bin
```

Rules:

- [x] Require exactly one of `--id` or `--handle`.
- [x] Default `--format` is `raw`.
- [x] `--format raw` outputs raw shared secret bytes.
- [x] `--format hex` outputs `hex(shared secret bytes)`.

Checklist:

- [ ] Load ECDH key.
- [x] Parse peer public key from PEM/DER/raw if supported.
- [ ] Convert peer key to TPM ECC point.
- [ ] Call TPM `ECDH_ZGen`.
- [x] Encode raw/hex output.

### `tpmctl hmac`

Compute HMAC/PRF output from a TPM HMAC identity, optionally sealing the output.

Examples:

```bash
tpmctl hmac \
    --id org/acme/alice/kdf \
    --input ./ctx.bin \
    --format hex

tpmctl hmac \
    --id org/acme/alice/kdf \
    --input ./ctx.bin \
    --format raw

tpmctl hmac \
    --id org/acme/alice/kdf \
    --input ./ctx.bin \
    --output ./prf.bin

tpmctl hmac \
    --id org/acme/alice/kdf \
    --input ./ctx.bin \
    --seal-at 0x81010020
# => sealed 32 bytes at 0x81010020

tpmctl hmac \
    --id org/acme/alice/kdf \
    --input ./ctx.bin \
    --seal-at 0x81010020 \
    --hash sha512 \
    --json
# => { "sealed_at": "0x81010020", "hash": "sha512" }

tpmctl hmac \
    --id org/acme/alice/kdf \
    --input ctx.bin \
    --seal-id org/acme/alice/derived/foo

tpmctl hmac \
    --id org/acme/alice/kdf \
    --input ctx.bin \
    --seal-id org/acme/alice/derived/foo \
    --hash sha512 \
    --json
# => { "sealed_id": "org/acme/alice/derived/foo", "hash": "sha512" }
```

Rules:

- [x] Require exactly one of `--id` or `--handle`.
- [x] `--seal-at` and `--seal-id` are mutually exclusive.
- [x] Default `--hash` is key metadata hash or `sha256`.
- [x] Default `--format` is `raw` when not sealing.
- [x] When sealing, do not print or write PRF bytes unless explicitly requested.
- [ ] JSON for sealed output uses `sealed_at` or `sealed_id` and `hash`.

Checklist:

- [ ] Load HMAC key.
- [x] Implement one-shot HMAC for small input.
- [ ] Implement HMAC sequence APIs for large input.
- [x] Encode raw/hex output.
- [ ] Implement `--seal-at` by sealing HMAC output and persisting at handle.
- [ ] Implement `--seal-id` by sealing HMAC output and storing under registry ID.
- [x] Zeroize HMAC output after sealing/writing where practical.

### `tpmctl seal`

Seal arbitrary input data to the TPM.

Examples:

```bash
tpmctl seal --input ./secret.bin --handle 0x81010020
tpmctl seal --input ./secret.bin --id org/acme/alice/sealed/foo
```

Rules:

- [x] Require exactly one of `--id` or `--handle`.
- [ ] `--handle` persists the sealed object at a TPM persistent handle.
- [ ] `--id` stores the sealed object under the local registry.

Checklist:

- [ ] Read input from file or stdin.
- [ ] Create sealed data object.
- [ ] Persist with `EvictControl` for `--handle`.
- [ ] Store TPM blobs and metadata for `--id`.
- [ ] Print concise success output or JSON.

### `tpmctl unseal`

Unseal arbitrary sealed data.

Examples:

```bash
tpmctl unseal --handle 0x81010020 --output ./secret.bin
tpmctl unseal --id org/acme/alice/sealed/foo --output ./secret.bin
```

Rules:

- [x] Require exactly one of `--id` or `--handle`.
- [x] Output to `--output` or stdout.
- [x] Refuse binary output to interactive TTY unless `--force` is provided.

Checklist:

- [ ] Load sealed object by registry ID.
- [ ] Load sealed object by persistent handle.
- [ ] Call TPM `Unseal`.
- [ ] Write unsealed bytes to file/stdout.
- [ ] Zeroize unsealed bytes after writing where practical.

### `tpmctl derive`

Derive p256, Ed25519, or secp256k1 software keys from TPM-protected PRF material, use them, zeroize, and exit.

Examples:

```bash
# derive ed25519 secret key and output hex
# defaults to --use secret
tpmctl derive \
    --id org/acme/alice/derived/foo \
    --label user1 \
    --algorithm ed25519 \
    --format hex

# derive p256 secret key from persisted handle
tpmctl derive \
    --handle 0x81010020 \
    --label user2 \
    --use secret \
    --algorithm p256 \
    --format hex

# derive secp256k1 secret key from persisted handle
tpmctl derive \
    --handle 0x81010020 \
    --label user3 \
    --use secret \
    --algorithm secp256k1 \
    --format hex

# derive and sign with an ephemeral p256 key
tpmctl derive \
    --handle 0x81010020 \
    --algorithm p256 \
    --use sign \
    --input ./message.txt \
    --format hex

# derive and sign with an ephemeral secp256k1 key
tpmctl derive \
    --handle 0x81010020 \
    --algorithm secp256k1 \
    --use sign \
    --input ./message.txt \
    --format hex

# derive deterministic ed25519 key and sign supplied digest/message bytes
tpmctl derive \
    --id org/acme/alice/derived/bar \
    --label eduser \
    --algorithm ed25519 \
    --use sign \
    --digest ./message.sha512 \
    --format hex \
    --output ./ed25519.sig.hex

# derive p256 public key, uncompressed by default
tpmctl derive \
    --id org/acme/bob/derived/p256-prf \
    --use pubkey \
    --algorithm p256 \
    --format hex

# derive secp256k1 public key, uncompressed by default
tpmctl derive \
    --id org/acme/bob/derived/eth-prf \
    --use pubkey \
    --algorithm secp256k1 \
    --format hex

# derive compressed secp256k1 public key
tpmctl derive \
    --id org/acme/bob/derived/eth-prf \
    --use pubkey \
    --algorithm secp256k1 \
    --compressed \
    --format hex

# derive checksummed Ethereum address
tpmctl derive \
    --id org/acme/bob/derived/eth-prf \
    --use pubkey \
    --algorithm secp256k1 \
    --format address
```

Rules:

- [x] Require exactly one of `--id` or `--handle`.
- [x] Default `--use` is `secret`.
- [x] Supported `--use`: `secret`, `pubkey`, `sign`.
- [x] Supported `--algorithm`: `p256`, `ed25519`, `secp256k1`.
- [x] `--label <label>` present means deterministic derivation from PRF + label.
- [x] Missing `--label` means ephemeral derivation using fresh randomness.
- [x] For `--use sign`, require exactly one of `--input` or `--digest`.
- [x] For `--algorithm ed25519 --use sign`, do not support `--hash`.
- [x] For `--algorithm ed25519 --use sign`, support only `raw` and `hex` formats.
- [x] For `--algorithm ed25519 --use sign --digest`, sign the supplied bytes as the Ed25519 message bytes; do not implement Ed25519ph in v1.
- [x] For `--algorithm p256 --use sign`, support `--hash sha256|sha384|sha512` with default `sha256`.
- [x] For `--algorithm secp256k1 --use sign`, support `--hash sha256|sha384|sha512` with default `sha256`.
- [x] For p256 and secp256k1 public keys, default to uncompressed public key bytes.
- [x] `--compressed` is valid only for secp256k1 `--use pubkey` with `raw` or `hex` output.
- [x] `--format address` is valid only for `--algorithm secp256k1 --use pubkey`.
- [x] Reject `--compressed --format address`.
- [x] Print a warning to stderr when `--label` is omitted for `--use pubkey` or `--use secret`, because the derived key is ephemeral and will change on each invocation.

Format matrix:

| Mode | Formats |
| --- | --- |
| `derive --use secret` | `raw`, `hex` |
| `derive --use pubkey --algorithm p256` | `raw`, `hex` |
| `derive --use pubkey --algorithm ed25519` | `raw`, `hex` |
| `derive --use pubkey --algorithm secp256k1` | `raw`, `hex`, `address` |
| `derive --use sign --algorithm p256` | `der`, `raw`, `hex` |
| `derive --use sign --algorithm ed25519` | `raw`, `hex` |
| `derive --use sign --algorithm secp256k1` | `der`, `raw`, `hex` |

Checklist:

- [ ] Load/unseal PRF seed from registry ID or persistent handle.
- [x] Implement deterministic KDF using PRF seed + algorithm + use + label.
- [x] Implement ephemeral KDF using PRF seed + algorithm + use + fresh randomness.
- [x] Implement p256 scalar derivation with retry/counter until valid non-zero scalar.
- [x] Implement Ed25519 seed derivation.
- [x] Implement secp256k1 scalar derivation with retry/counter until valid non-zero scalar.
- [x] Implement p256 ECDSA signing.
- [x] Implement Ed25519 signing.
- [x] Implement secp256k1 ECDSA signing.
- [x] Implement p256 public key encoding, uncompressed by default.
- [x] Implement secp256k1 public key encoding, uncompressed by default.
- [x] Implement `--compressed` secp256k1 public key output.
- [x] Implement checksummed Ethereum address output.
- [x] Zeroize PRF seed, derived scalar/seed, and intermediate buffers.

## Output and Encoding Rules

- [x] `sign --format hex` means `hex(raw r||s)`.
- [x] `sign --format raw` means P1363 `r || s`.
- [x] `sign --format der` means ASN.1 DER ECDSA signature.
- [x] Ed25519 signature `raw` is 64 bytes.
- [x] Ed25519 signature `hex` is hex of the 64-byte signature.
- [x] `pubkey --format hex` means `hex(raw public key bytes)`.
- [x] p256 and secp256k1 raw public keys default to uncompressed SEC1 points.
- [x] Ethereum address output is EIP-55 checksummed text.
- [x] Binary stdout to TTY should be rejected unless `--force` is provided.

## Parallel Worktree Execution Model

Implementation should be run by five subagents working in separate git worktrees. Use a contract-first flow: land crate boundaries and shared API contracts first, then let workstreams proceed in parallel with narrow file ownership.

### Subagent Ownership

| Agent | Branch | Primary Ownership | Main Files |
| --- | --- | --- | --- |
| 01 Foundation | `agent/01-foundation-workspace` | Workspace scaffolding, crate boundaries, shared public contracts | root `Cargo.toml`, `crates/*/Cargo.toml`, initial `lib.rs`/`main.rs` files |
| 02 Core | `agent/02-core-tpm-registry` | TPM context helpers, TCTI, handles, load/persist helpers, registry | `tpmctl-core/src/tpm.rs`, `store.rs`, core error/config types |
| 03 CLI | `agent/03-cli-validation-io` | Clap parser, validation, stdout/stderr policy, `--json`, `--output`, TTY guards | `tpmctl-cli/src/main.rs`, `args.rs`, `commands/*` stubs/adapters |
| 04 TPM Commands | `agent/04-tpm-commands` | TPM-backed `keygen`, `sign`, `pubkey`, `ecdh`, `hmac`, `seal`, `unseal` | `tpmctl-core/src/{keygen,sign,pubkey,ecdh,hmac,seal,output}.rs` |
| 05 Derived/PKCS#11/Docs | `agent/05-derived-pkcs11-tests` | `derive` crypto, p256/Ed25519/secp256k1, Ethereum address, PKCS#11 integration, tests/docs | `tpmctl-core/src/crypto/*`, `tpmctl-pkcs11/*`, `README.md`, tests |

### Dependency Graph

```text
01 Foundation/workspace contracts
├── 02 Core TPM + registry
│   ├── 04 TPM domain commands
│   │   ├── 03 CLI final command wiring
│   │   └── 05 PKCS#11 provider integration
│   └── 05 derive PRF seed load/unseal
├── 03 CLI parser/validation skeleton
└── 05 derived crypto skeleton/docs/tests
```

### Parallel Waves

| Wave | Work | Owners | Notes |
| --- | --- | --- | --- |
| 0 | Workspace/crate scaffolding and core API contracts | Agent 01 | Must land first; keep this small and compiling. |
| 1 | Core helpers, registry, CLI skeleton | Agents 02, 03 | Can run in parallel after Agent 01 merges. |
| 2 | Keygen/seal foundations and PKCS#11 scaffold | Agents 04, 05 | Agent 04 needs stable TPM/store APIs; Agent 05 can scaffold crypto and PKCS#11. |
| 3 | Pubkey/sign/ECDH/HMAC and derive implementation | Agents 04, 05 | Can run in parallel if domain API contracts are stable. |
| 4 | CLI command wiring, integration tests, docs | Agents 03, 04, 05 | Merge only after core behavior compiles and command APIs stabilize. |
| 5 | Final integration gate | All, coordinated by Agent 05 or lead | Run workspace-wide checks before merging integration to `main`. |

### Conflict Avoidance Rules

- [x] Agent 01 owns root workspace files until the foundation branch lands.
- [x] After Agent 01 lands, root `Cargo.toml` changes require coordination.
- [x] Avoid multiple agents editing `crates/tpmctl-core/src/lib.rs`; Agent 01 should declare module skeletons up front.
- [x] CLI argument parsing belongs to Agent 03; TPM semantics belong to `tpmctl-core` owners.
- [x] Agent 04 owns TPM domain operation modules; Agent 03 only calls their public APIs.
- [x] Agent 05 owns `crypto/*`, `tpmctl-pkcs11/*`, and final docs/tests.
- [x] Shared files such as `README.md`, root `Cargo.toml`, and top-level module exports require a checkpoint note before edits.
- [x] Prefer request/response structs in `tpmctl-core` over embedding business logic in CLI command handlers.

### Agent Scopes

#### Agent 01 — Foundation

- [x] `cargo metadata --format-version 1` succeeds.
- [x] `cargo check -p tpmctl-core` succeeds.
- [x] `cargo check -p tpmctl-cli` succeeds.
- [x] `cargo check -p tpmctl-pkcs11` succeeds.
- [x] `tpmctl-core` has no `clap` dependency.
- [x] `tpmctl-core` has no `pkcs11-sys` dependency.
- [x] `tpmctl-pkcs11` has `crate-type = ["cdylib"]`.

#### Agent 02 — Core TPM and Registry

- [x] `cargo test -p tpmctl-core store` passes.
- [x] `cargo test -p tpmctl-core handle` passes.
- [x] `cargo test -p tpmctl-core tcti` passes.
- [x] Store precedence is implemented: `--store`, then `TPMCTL_STORE`, then XDG default.
- [x] Registry IDs reject absolute paths, `..`, empty components, and invalid separators.
- [x] Persistent handles parse expected forms like `0x81010010`.
- [x] TPM errors map to stable core errors instead of panics.

#### Agent 03 — CLI Validation and I/O

- [x] `cargo test -p tpmctl-cli` passes.
- [x] `cargo run -p tpmctl-cli -- --help` succeeds.
- [x] `cargo run -p tpmctl-cli -- --version` succeeds.
- [x] `--id` and `--handle` are mutually exclusive for all relevant commands.
- [x] `sign` and `derive --use sign` require exactly one of `--input` or `--digest`.
- [x] `hmac --seal-at` and `hmac --seal-id` are mutually exclusive.
- [x] Binary stdout to interactive TTY is rejected unless `--force` is present.

#### Agent 04 — TPM Commands

- [x] `cargo check -p tpmctl-core` succeeds.
- [x] `cargo test -p tpmctl-core sign` passes.
- [x] `cargo test -p tpmctl-core pubkey` passes.
- [x] `cargo test -p tpmctl-core output` passes.
- [x] `keygen` supports `sign`, `ecdh`, and `hmac` usages.
- [x] `sign` supports DER, raw P1363, and hex P1363 output.
- [x] `pubkey` supports raw, hex, PEM, DER, and SSH output.
- [x] `ecdh`, `hmac`, `seal`, and `unseal` validate expected key/object usage.

#### Agent 05 — Derived Crypto, PKCS#11, Tests, Docs

- [x] `cargo test -p tpmctl-core derive` passes.
- [x] `cargo test -p tpmctl-core crypto` passes.
- [x] `cargo test -p tpmctl-core ethereum` passes.
- [x] `cargo build -p tpmctl-pkcs11 --release` succeeds.
- [x] p256 and secp256k1 scalar derivation retry until valid non-zero scalars.
- [x] Ed25519 rejects `--hash` for `--use sign`.
- [x] `--format address` emits EIP-55 checksummed Ethereum addresses.
- [x] Secret/scalar/seed/intermediate buffers use `zeroize` where practical.
- [x] README documents core library, CLI crate, PKCS#11 crate, runtime packages, and derived-key software model.

### Final Integration Gate

All subagents must run all checks and tests and make sure they are passing:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
```

Optional but preferred:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

TPM simulator tests, if available, should be gated separately:

```bash
TEST_TCTI=swtpm cargo test --workspace --features simulator-tests
```

## Implementation Order

| Phase | Component | Dependencies | Estimated Scope |
| --- | --- | --- | --- |
| 1 | Workspace restructuring and crate boundaries | Existing crate | M |
| 2 | Core TPM context/load/persist helpers | Phase 1 | M |
| 3 | Local registry and metadata model | Phase 1 | M |
| 4 | CLI skeleton and global validation | Phase 1 | S |
| 5 | `keygen` for sign/ecdh/hmac identities | Phases 2, 3, 4 | L |
| 6 | `pubkey` export | Phases 2, 3, 4, 5 | M |
| 7 | TPM `sign` | Phases 2, 3, 4, 5 | M |
| 8 | TPM `ecdh` | Phases 2, 3, 4, 5 | M |
| 9 | TPM `hmac` raw/hex output | Phases 2, 3, 4, 5 | M |
| 10 | `seal` / `unseal` | Phases 2, 3, 4 | M |
| 11 | `hmac --seal-at` / `--seal-id` | Phases 9, 10 | M |
| 12 | `derive` secret/pubkey/sign | Phases 3, 4, 10 | L |
| 13 | PKCS#11 provider crate integration | Phases 1, 2 | M |
| 14 | Integration tests and docs | All previous | M |

## Phase Checklists

### Phase 1 — Workspace restructuring and crate boundaries

- [x] Create root Cargo workspace.
- [x] Create `crates/tpmctl-core` library crate.
- [x] Create `crates/tpmctl-cli` binary crate.
- [x] Create `crates/tpmctl-pkcs11` `cdylib` crate.
- [x] Move TPM and crypto logic into `tpmctl-core`.
- [x] Move CLI parsing and dispatch into `tpmctl-cli`.
- [x] Move PKCS#11 entrypoints into `tpmctl-pkcs11`.
- [x] Ensure `cargo build -p tpmctl-cli` does not compile PKCS#11 entrypoint code.
- [x] Ensure `cargo build -p tpmctl-pkcs11 --release` builds the `.so`.

### Phase 2 — Core TPM helpers

- [x] Centralize TCTI resolution.
- [x] Centralize ESAPI context creation.
- [x] Implement persistent handle parsing.
- [x] Implement object loading from registry blobs.
- [x] Implement object loading from persistent handle.
- [x] Implement `ReadPublic` helper.
- [x] Implement `EvictControl` persistence helper.
- [x] Add consistent TPM error mapping.

### Phase 3 — Registry

- [x] Define registry root.
- [x] Implement store root precedence: `--store`, then `TPMCTL_STORE`, then XDG default.
- [x] Define metadata schema.
- [x] Implement safe ID-to-path mapping.
- [x] Reject path traversal in IDs.
- [x] Implement atomic metadata/blob writes.
- [x] Implement ID existence checks.
- [x] Implement load/save for key objects.
- [x] Implement load/save for sealed objects.

### Phase 4 — CLI skeleton

- [x] Add parser.
- [x] Add global output helpers.
- [x] Add mutual-exclusion validation.
- [x] Add stdin/stdout `-` support.
- [x] Add `--json` support where planned.
- [x] Add clear exit codes and error messages.

### Phase 5 — Key generation

- [ ] Implement sign key creation.
- [ ] Implement ECDH key creation.
- [ ] Implement HMAC key creation.
- [ ] Persist with handle where requested.
- [ ] Store local registry entries.
- [x] Test duplicate ID/handle behavior.

### Phase 6 — Public key export

- [x] Export raw ECC SEC1 bytes.
- [x] Export hex raw key.
- [x] Export PEM SPKI.
- [x] Export DER SPKI.
- [x] Export OpenSSH key line.
- [x] Reject non-asymmetric keys.

### Phase 7 — TPM signing

- [x] Implement input hashing.
- [x] Implement digest validation.
- [ ] Call TPM `Sign`.
- [x] Encode DER.
- [x] Encode raw P1363.
- [x] Encode hex P1363.

### Phase 8 — ECDH

- [x] Parse peer public key.
- [x] Validate local key usage.
- [ ] Call `ECDH_ZGen`.
- [x] Encode raw/hex output.

### Phase 9 — HMAC

- [x] Validate HMAC key usage.
- [ ] Implement one-shot HMAC.
- [ ] Implement sequence HMAC for large input.
- [x] Encode raw/hex output.
- [x] Support `--hash`.

### Phase 10 — Seal/unseal

- [ ] Create sealed object from input.
- [ ] Persist sealed object by handle.
- [ ] Store sealed object by ID.
- [ ] Load and unseal by handle.
- [ ] Load and unseal by ID.
- [ ] Zeroize unsealed data.

### Phase 11 — HMAC sealing convenience

- [ ] Compute HMAC output.
- [ ] Seal output at persistent handle for `--seal-at`.
- [ ] Seal output into registry for `--seal-id`.
- [x] Reject `--seal-at` and `--seal-id` together.
- [ ] Emit human success output.
- [ ] Emit JSON success output.

### Phase 12 — Derive

- [x] Unseal/load PRF seed.
- [x] Implement deterministic label mode.
- [x] Implement ephemeral randomness mode.
- [x] Implement p256 scalar retry derivation.
- [x] Implement Ed25519 secret derivation.
- [x] Implement secp256k1 scalar retry derivation.
- [x] Implement `--use secret`.
- [x] Implement `--use pubkey`.
- [x] Implement `--use sign`.
- [x] Implement secp256k1 Ethereum address output.
- [x] Enforce algorithm/format matrix.
- [x] Zeroize all sensitive buffers.

### Phase 13 — PKCS#11 provider crate integration

- [x] Reuse `tpmctl-core` TPM helpers in `tpmctl-pkcs11`.
- [x] Keep PKCS#11 sign-only behavior intact.
- [x] Keep PKCS#11 dependencies isolated to `tpmctl-pkcs11`.
- [x] Ensure CLI builds do not require PKCS#11 code or dependencies.
- [x] Update README to explain separate CLI and PKCS#11 crate builds.

### Phase 14 — Tests and docs

- [x] Unit-test format encoders.
- [x] Unit-test ID path safety.
- [x] Unit-test CLI parser validation.
- [x] Unit-test secp256k1 scalar derivation retry behavior.
- [ ] Add simulator/integration tests where available.
- [x] Document runtime packages and `pkg-config` requirements.
- [x] Document CLI examples.
- [x] Document derived-key software security model.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| TPM object template mismatch makes generated keys unusable for intended operations | Medium | High | Add explicit templates per `--use`; test each operation after keygen. |
| Context/blobs stored incorrectly, preventing reload | Medium | High | Store TPM public/private blobs, not transient contexts, as durable registry data. |
| Persistent handle collision destroys user material | Medium | High | Require explicit `--force`; read existing handle before evicting. |
| Binary output corrupts terminal | Medium | Low | Reject raw binary stdout to TTY unless `--force`. |
| Derived software keys leak in memory | Medium | High | Use `zeroize`; keep lifetimes short; avoid logging; no debug dumps of secrets. |
| p256/secp256k1 scalar derivation creates invalid scalar | Medium | High | Retry with counter/domain separation until valid non-zero scalar. |
| Ed25519 digest semantics are confused with Ed25519ph | Medium | Medium | For v1, no `--hash` on Ed25519; document `--digest` as bytes-to-sign unless Ed25519ph is explicitly added later. |
| Registry IDs allow path traversal | Medium | High | Normalize and validate ID components; reject `..`, absolute paths, empty components. |
| TSS library availability varies across systems | High | Medium | Document runtime/build deps; support Nix/devshell later if needed. |
| PKCS#11 crate split breaks current `.so` workflow | Medium | Medium | Add explicit build checks for `cargo build -p tpmctl-pkcs11 --release`. |

## Completion Checklist

- [x] `cargo build -p tpmctl-cli --release` succeeds without PKCS#11 dependencies.
- [x] `cargo build -p tpmctl-pkcs11 --release` produces PKCS#11 `.so`.
- [ ] `tpmctl keygen --use sign --id ...` creates reloadable signing identity.
- [ ] `tpmctl keygen --use ecdh --id ...` creates usable ECDH identity.
- [ ] `tpmctl keygen --use hmac --id ...` creates usable HMAC identity.
- [ ] `tpmctl sign` works by `--id` and by `--handle`.
- [x] `tpmctl pubkey` supports raw/hex/pem/der/ssh.
- [x] `tpmctl ecdh` supports raw/hex.
- [x] `tpmctl hmac` supports raw/hex and `--hash`.
- [x] `tpmctl hmac --seal-at` and `--seal-id` work and are mutually exclusive.
- [ ] `tpmctl seal` and `unseal` work by `--id` and by `--handle`.
- [x] `tpmctl derive` supports p256, Ed25519, and secp256k1 secret/pubkey/sign flows.
- [x] Derived key material is zeroized where practical.
- [x] README documents core library, CLI crate, and PKCS#11 provider crate builds separately.
