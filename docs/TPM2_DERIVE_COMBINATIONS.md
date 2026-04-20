# tpm2-derive Combinations Guide

_Which algorithm × mode × use combinations work today._

## Quick default

| Goal | Algorithm | Mode | Uses |
| --- | --- | --- | --- |
| TPM-native P-256 signer | `p256` | `native` | `sign`, `verify` |
| Deterministic app secrets | any | `prf` | `derive` |
| SSH identity (Ed25519) | `ed25519` | `seed` | `derive`, `ssh-agent` |
| SSH identity (P-256) | `p256` | `seed` | `derive`, `ssh-agent` |
| Recovery-friendly profile | any | `seed` | `derive` (+ export) |

**Seed mode** is the most versatile default — it supports all three algorithms,
SSH agent integration, recovery export/import, and software key derivation.

---

## Modes

| Mode | What it does |
| --- | --- |
| **`native`** | TPM-native key; signing & verification happen inside the TPM |
| **`prf`** | TPM HMAC/PRF-backed deterministic byte derivation |
| **`seed`** | One TPM-sealed seed → software derivation at use time |

They do **not** all support the same operations.

---

## 1. Native mode

Best for hardware-bound P-256 signing where the private key never leaves the TPM.

```bash
tpm2-derive setup \
  --profile prod-signer \
  --algorithm p256 \
  --mode native \
  --use sign \
  --use verify
```

```bash
tpm2-derive sign   --profile prod-signer --input message.bin
tpm2-derive verify --profile prod-signer --input message.bin --signature signature.der
tpm2-derive export --profile prod-signer --kind public-key --output prod-signer.spki.der
```

### Good native combos

- `p256 + native + sign + verify`
- `p256 + native + sign`
- `p256 + native + export public-key`

### Not useful / not wired

- `ed25519 + native` — no TPM-native Ed25519
- `secp256k1 + native` — no TPM-native secp256k1
- `native + derive`
- `native + ssh-agent`

---

## 2. PRF mode

Best for deterministic derived bytes: app secrets, child-key material, labeled contexts.

```bash
tpm2-derive setup \
  --profile app-prf \
  --algorithm p256 \
  --mode prf \
  --use derive
```

```bash
tpm2-derive derive \
  --profile app-prf \
  --purpose session \
  --namespace com.example \
  --context tenant=alpha \
  --length 32
```

### Good PRF combos

- `p256 + prf + derive`
- `ed25519 + prf + derive`
- `secp256k1 + prf + derive`

### Not wired yet

- `prf + sign`
- `prf + verify`
- `prf + ssh-agent`
- `prf + export public-key`

---

## 3. Seed mode

The practical default for most workflows. One TPM-sealed seed supports
Ed25519/P-256/secp256k1 software identities, SSH agent, recovery export & import.

### Setup + derive

```bash
tpm2-derive setup \
  --profile seed-user \
  --algorithm ed25519 \
  --mode seed \
  --use derive \
  --use ssh-agent
```

```bash
tpm2-derive derive \
  --profile seed-user \
  --purpose ssh-agent \
  --namespace tpm2ssh \
  --context account=alice \
  --length 32
```

### SSH agent

```bash
tpm2-derive ssh agent add --profile seed-user
```

Supported today for `ed25519` and `p256` seed profiles.

### Recovery export

```bash
tpm2-derive export \
  --profile seed-user \
  --kind recovery-bundle \
  --output seed-user.recovery.json \
  --reason "hardware migration" \
  --confirm-recovery-export \
  --confirm-sealed-at-rest-boundary \
  --confirmation-phrase "I understand this export weakens TPM-only protection"
```

### Recovery import

```bash
tpm2-derive import \
  --kind recovery-bundle \
  --input seed-user.recovery.json \
  --target-profile seed-user-restored
```

### Good seed combos

- `ed25519 + seed + derive`
- `ed25519 + seed + ssh-agent`
- `ed25519 + seed + verify`
- `ed25519 + seed + export public-key`
- `ed25519 + seed + recovery-bundle export`
- `p256 + seed + derive`
- `p256 + seed + ssh-agent`
- `p256 + seed + export public-key`
- `secp256k1 + seed + derive`
- `secp256k1 + seed + export public-key`

### Partial / not wired

- Seed `sign` as a first-class CLI signing flow
- Seed `verify` beyond Ed25519 is still partial
- `ssh-agent add` is not wired for secp256k1

---

## Combinations matrix

| Algorithm | Mode | Derive | Sign | Verify | Export pub | Recovery export | Recovery import | SSH agent add | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| p256 | native | no | yes | yes | yes | no | no | no | best native signer |
| p256 | prf | yes | no | no | no | no | no | no | derive-only |
| p256 | seed | yes | — | — | yes | yes | yes | yes | seed fallback; SSH/export support |
| ed25519 | native | no | no | no | no | no | no | no | not a target |
| ed25519 | prf | yes | no | no | no | no | no | no | derive root |
| ed25519 | seed | yes | limited | yes | yes | yes | yes | yes | primary seed SSH path |
| secp256k1 | native | no | no | no | no | no | no | no | not a target |
| secp256k1 | prf | yes | no | no | no | no | no | no | derive-only |
| secp256k1 | seed | yes | limited | limited | yes | yes | yes | limited | fallback with public export |

---

## Recommended presets

### Hardware-backed signer

```
algorithm = p256, mode = native, uses = sign + verify
```

### Deterministic app secrets

```
mode = prf (preferred) or seed (fallback), uses = derive
```

### SSH / Git identity

```
algorithm = ed25519 or p256, mode = seed, uses = derive + ssh-agent
```

### Recovery-friendly profile

```
mode = seed, uses = derive
# then: tpm2-derive export --kind recovery-bundle …
```

---

## State layout

`tpm2-derive` stores all persistent state under a single root directory
(default: `$XDG_STATE_HOME/tpm2-derive` or `~/.local/state/tpm2-derive`).

```
<state-root>/
├── profiles/          # per-profile JSON metadata
│   ├── prod-signer.json
│   └── seed-user.json
├── objects/           # TPM-sealed blobs & key handles
│   ├── prod-signer/
│   │   └── handle.ctx
│   └── seed-user/
│       ├── sealed.pub
│       └── sealed.priv
└── exports/           # exported public keys & recovery bundles
    ├── prod-signer.spki.der
    └── seed-user.recovery.json
```

| Directory | Contents | Permissions |
| --- | --- | --- |
| `profiles/` | JSON profile metadata (algorithm, mode, uses, storage pointers) | `0700` dir, `0600` files |
| `objects/` | TPM object blobs (`sealed.pub`, `sealed.priv`, `handle.ctx`) | `0700` dir, `0600` files |
| `exports/` | Public-key DER files, recovery-bundle JSON | `0700` dir, `0600` files |

All directories are created with mode `0700` and all files with mode `0600`.

---

## Current rough edges

- Some commands still report unsupported for certain mode/algorithm combinations
- PRF provisioning can fail due to TPM transport / TCTI environment issues (especially under `sudo`)
- Recovery import is a high-friction restore flow, not a broader migration UX
- `encrypt` / `decrypt` are placeholders

---

## See also

- `docs/TPM2_DERIVE_PLAN.md`
- `docs/progress.md`
