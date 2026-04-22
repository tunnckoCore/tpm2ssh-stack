# TPM2 Derive Plan

## Summary

`tpm2-derive` will be a reusable Rust crate + CLI for:

- **native TPM operations** when the local TPM supports them
- **TPM-backed PRF operations** when the TPM can act as a deterministic oracle over labeled context
- **TPM-sealed seed derivation** when native or PRF support is unavailable or unsuitable

Core positioning:

> `tpm2-derive` provides TPM-backed key operations with native, PRF, and seed modes.

Security goal:

> Protect TPM root material at rest with TPM policy; minimize exposure of derived secrets during use.

This crate is intended to become the shared core for `tpm2ssh` and future passkey/provider tooling.

---

## Honest security model

Three modes exist and they do **not** provide identical guarantees.

### 1) `native`
Use TPM-native key objects and operations when possible.

Target properties:
- private key material stays in TPM-managed flow
- best fit for algorithms/operations like P-256 signing when supported
- strongest hardware-backed story

Typical uses:
- P-256 signing
- RSA signing/decryption where available
- TPM-native public key export
- ECDH-like operations if supported and worth exposing

### 2) `prf`
Keep a TPM-resident secret and use TPM-backed PRF/HMAC-style operations to produce deterministic bytes from canonical labeled context.

Target properties:
- root secret stays in TPM-managed flow
- deterministic outputs suitable for downstream software derivation
- best fit for passkey PRF/HMAC-style use cases and software child-key derivation without unsealing a seed

Typical uses:
- passkey/provider PRF outputs
- deterministic child-key derivation inputs
- application-specific secret derivation
- WebAuthn-adjacent PRF/HMAC extension support

### 3) `seed`
Generates and keep high-entropy seed that gets sealed in the TPM on setup, then derive child material in software/userland.

Target properties:
- seed is TPM-protected at rest
- deterministic child keys for protocols the TPM does not support natively
- best fit for Ed25519, secp256k1, SSH agent loading, recovery/export, and universal fallback

Typical uses:
- Ed25519 child keys
- secp256k1/Ethereum child keys
- recovery-friendly deterministic identities
- software PRF fallback when TPM PRF is unavailable or insufficient

Important: `seed` mode is TPM-sealed at rest, but software-derived at use time.

---

## Why the three modes exist

TPM 2.0 chips usually support only a subset of useful cryptographic operations.

Common expectations:
- **often supported natively**: RSA, P-256 / NIST ECC, hashing, HMAC
- **often not supported natively**: Ed25519, X25519, secp256k1

So the crate should:
- detect real local TPM capabilities
- choose the best secure mode automatically when requested
- prefer `prf` over `seed` when deterministic derived output is needed and the TPM can support it cleanly
- allow explicit override with clear validation errors

---

## Threat model

### Assets
- TPM auth values / PINs / passphrases
- TPM-resident native key objects
- TPM-backed PRF root material
- sealed seed
- derived software child keys
- recovery/export artifacts
- profile metadata that influences derivation semantics

### Main adversaries
- offline disk thief
- local unprivileged attacker
- same-user malware
- root / live compromised host
- attacker who steals recovery exports

### Security goals
- protect TPM root material at rest
- avoid casual secret-on-disk exposure
- never put secrets in argv
- make export explicit and high-friction
- keep default CLI non-interactive and scriptable

### Important non-goal
A live compromised host can often observe or misuse operations at the moment secrets are entered or child keys are derived. Native TPM mode reduces exposure, but does not magically defeat a fully compromised running OS.

---

## Product shape

### Crate split

`tpm2-derive` should be:
- a **library crate** for downstream consumers
- a **thin CLI binary** over the library

Downstream examples:
- `tpm2ssh`
- passkey/provider services
- app-signing tools
- secp256k1 / Ethereum tooling
- agent/service wrappers

### Main design principle
Separate:
1. TPM capability/provisioning logic
2. PRF and seed storage/open flows
3. pure derivation/key/export logic
4. CLI UX and output formatting

---

## Capability detection plan

The setup flow should probe and classify the local TPM.

### What to detect
- TPM presence and accessibility
- supported commands
- supported algorithms
- supported ECC curves
- key creation feasibility for requested algorithm/operation combos
- seal/unseal feasibility
- HMAC/PRF feasibility
- relevant TPM properties and limits

### Detection sources
Primary implementation target:
- `tpm2_getcap algorithms`
- `tpm2_getcap commands`
- `tpm2_getcap ecc-curves`
- `tpm2_getcap properties-fixed`
- targeted command probes for creation / use feasibility

Secondary backend path:
- typed Rust TPM backend (`tss-esapi`) behind a feature flag

### Auto-resolution rules
- `p256` + `sign/verify` only -> prefer `native`
- deterministic derived-output workflows -> prefer `prf`
- `ed25519` -> prefer `prf`, fall back to `seed`
- `secp256k1` -> prefer `prf`, fall back to `seed`
- SSH agent workflows -> prefer `prf`, fall back to `seed`
- explicit unsupported native/PRF request -> fail clearly or fall back when `auto` is selected

---

## Security rules

### Must avoid
- writing raw seed material to predictable temp files
- passing PIN/auth secrets in argv
- printing secret material by default
- fixed-handle assumptions without justification
- cross-protocol reuse without strong domain separation
- exposing raw low-level HMAC gadgets instead of versioned PRF derivation semantics
- silent fallback between security modes during operational commands

### Export rules
- secret export is valid for backup/recovery
- secret export must be explicit and high-friction
- secret export should never be the default path
- `native` mode should usually refuse private export if the key is truly hardware-resident/non-exportable
- `prf` mode should expose deterministic derivation, not raw root-secret export
- `seed` mode should support explicit backup/recovery export with strong warnings and confirmations

### Secret handling
- use `secrecy` + `zeroize`
- minimize secret lifetime in memory
- no normal “show me the key” UX
- no secret inputs via ordinary CLI flags
- treat exported artifacts as break-glass operations

---

## Planned crate architecture

### Current scaffold

```text
tpm2-derive/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs
    ├── error.rs
    ├── model.rs
    ├── backend.rs
    ├── ops.rs
    ├── cli.rs
    └── bin/
        └── tpm2-derive.rs
```

### Target internal shape

```text
src/
  model/
  backend/
  ops/
  cli/
  crypto/
  export/
  storage/
```

### Core abstractions

#### Backend selection
- `Mode::Native`
- `Mode::Prf`
- `Mode::Seed`
- `Mode::Auto`

#### Capability probing
A backend probe should answer:
- what is supported
- what is recommended for a given algorithm/use set
- why the recommendation was made

#### Profile model
One profile should bind:
- profile name
- algorithm
- requested uses
- requested mode
- resolved mode
- backend metadata
- recovery/export policy

#### Backend strategy
The public API should stay backend-agnostic.

Backends:
- default lightweight subprocess backend
- optional `tss-esapi` backend via cargo features

---

## CLI design

The CLI should be:
- non-interactive by default
- stable for automation
- JSON-friendly
- explicit about dangerous operations

### Command tree

```text
tpm2-derive inspect
tpm2-derive setup
tpm2-derive derive
tpm2-derive sign
tpm2-derive verify
tpm2-derive encrypt
tpm2-derive decrypt
tpm2-derive export
tpm2-derive ssh-agent add
```

### Output conventions
- stdout for primary result only
- stderr for diagnostics in real implementations
- `--json` for stable machine-readable output
- no prompts unless explicitly requested by a future guided wrapper

### Exit/error conventions
Keep error codes small and stable:
- usage/validation error
- state/profile error
- TPM unavailable
- auth failure
- capability mismatch
- policy refusal
- internal failure

---

## Implementation scope

The implementation should cover all major workstreams:

- capability inspection / recommendation
- profile resolution and persistence
- PRF derivation core
- seed derivation fallback
- native TPM sign/verify support
- public export
- explicit recovery export flows
- machine-readable output
- SSH agent integration
- passkey/provider-oriented integration points

The work can be parallelized across a team of minions, but the architecture should stay coherent and backend-agnostic.

---

## Dependency plan

### Recommended now
- `clap`
- `thiserror`
- `serde`, `serde_json`
- `secrecy`
- `zeroize`
- `hkdf`
- `sha2`

### Backend strategy
Initial delivery path:
- keep the public API backend-agnostic
- start with a subprocess-oriented backend for speed and lower integration friction
- add `tss-esapi` as an optional backend via cargo features

Long-term preference from a security perspective:
- a typed Rust TPM API is better than shelling out with secret-bearing temp files or argv

---

## Implementation workstreams

### 1. Core model + persistence
- profile schema
- derivation context schema
- output envelopes
- state storage layout

### 2. Real TPM capability probing
- command/algorithm/curve inspection
- PRF/HMAC support detection
- native operation support matrix
- mode recommendation engine

### 3. PRF backend
- create/import TPM-backed PRF root material when supported
- derive deterministic bytes from canonical context
- support PRF/HMAC-oriented integrations

### 4. Seed backend
- create/import sealed seed
- seal/unseal through TPM
- derive software child key material safely
- support explicit recovery export flows

### 5. Native backend
- native P-256 sign/verify path
- native public material export
- keep native/non-exportable semantics explicit

### 6. Integration layer
- `tpm2ssh` migration to `tpm2-derive`
- SSH agent support
- passkey/provider-oriented integrations
- additional app/crypto-oriented consumers

---

## Current implementation status

Scaffold created at:
- `~/code/tpm2ssh-stack/tpm2-derive`

Current scaffold includes:
- library/binary split
- base models
- heuristic `inspect`
- heuristic `setup` mode resolution across `native`, `prf`, and `seed`
- README

It does **not** yet implement real TPM probing, PRF derivation, seed sealing/unsealing, signing, or export.

---

## Immediate next steps

1. flesh out the model types and profile persistence format
2. implement real TPM capability probing
3. implement PRF create/derive path
4. implement seed create/unseal without secret temp-file mistakes
5. implement native P-256 signing path
6. wire export / recovery flows
7. move `tpm2ssh` to consume this crate
