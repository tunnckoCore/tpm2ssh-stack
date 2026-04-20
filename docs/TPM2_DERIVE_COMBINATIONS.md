# TPM2 Derive Combinations Guide

_User-facing guide for which combinations currently make sense._

## Short version

If you just want a safe default:

- **P-256 sign/verify** → use **`native`**
- **Deterministic derivation** → use **`prf`** if your TPM/tooling path works
- **SSH / Ed25519 / fallback deterministic identities** → use **`seed`**
- **Recovery export** → only meaningful for **`seed`**

## Mental model

There are 3 modes:

- **`native`** = TPM-native keys and TPM-native operations
- **`prf`** = TPM-backed deterministic byte derivation via TPM HMAC/PRF-style flow
- **`seed`** = one TPM-sealed seed, then software derivation at use time

They do **not** all support the same operations.

---

## What works today

### 1. Native mode

Best for:

- `p256`
- `sign`
- `verify`
- public-key export

### Currently usable native combinations

#### P-256 signing profile

```bash
tpm2-derive setup \
  --profile prod-signer \
  --algorithm p256 \
  --mode native \
  --use sign \
  --use verify
```

Then:

```bash
tpm2-derive sign --profile prod-signer --input message.bin
tpm2-derive verify --profile prod-signer --input message.bin --signature signature.der
tpm2-derive export --profile prod-signer --kind public-key --output prod-signer.spki.der
```

### Good native combos

- `p256 + native + sign + verify`
- `p256 + native + sign`
- `p256 + native + verify` may still be rough depending on current setup constraints

### Bad / not-useful native combos

- `ed25519 + native`
- `secp256k1 + native`
- `native + derive`
- `native + ssh-agent add`

---

## 2. PRF mode

Best for:

- deterministic derived bytes
- app secrets
- software child-key inputs
- future broader non-native workflows

### Currently usable PRF combination

Setup:

```bash
tpm2-derive setup \
  --profile app-prf \
  --algorithm p256 \
  --mode prf \
  --use derive
```

Then:

```bash
tpm2-derive derive \
  --profile app-prf \
  --purpose session \
  --namespace com.example \
  --context tenant=alpha \
  --length 32
```

### Good PRF combos today

- `p256 + prf + derive`
- `ed25519 + prf + derive`
- `secp256k1 + prf + derive`

### PRF combinations that are still partial / not wired

- `prf + sign`
- `prf + verify`
- `prf + ssh-agent add`
- `prf + export public-key`

### Important note about your PRF error

If `--dry-run` works but real `setup --mode prf` fails, that usually means:

- profile validation and mode resolution succeeded
- the failure happened only when `tpm2-tools` actually tried to talk to the TPM

Your error:

- mentions **`com.intel.tss2.Tabrmd`**
- mentions DBus service lookup failure

That means the failure is **not really “PRF is unsupported” in the abstract**.
It means the subprocess TPM tool invocation tried to use the **abrmd/tabrmd TCTI path**, but that service was not available in the environment where the command ran.

So this is really closer to:

- **TPM access / TCTI transport configuration failure**
- not a semantic “bad algorithm/mode combination” failure

Why dry-run succeeded:

- dry-run never provisions the TPM object
- no actual `tpm2_create` / `tpm2_load` call was made

Why non-dry-run failed:

- it actually ran `tpm2_create`
- that subprocess hit a TCTI/service mismatch

Practical interpretation:

- the combination itself may be valid
- the runtime TPM transport path for root / `sudo` is what failed

Typical things to try manually:

```bash
sudo env TPM2TOOLS_TCTI=device ./target/debug/tpm2-derive setup ...
```

or preserve your TPM-related env when using sudo if your system already exports a working TCTI.

---

## 3. Seed mode

Best for:

- Ed25519 identities
- SSH-oriented deterministic identities
- recovery-friendly flows
- fallback when PRF/native is not what you want

### Currently usable seed combinations

#### Seed setup + derive

```bash
tpm2-derive setup \
  --profile seed-user \
  --algorithm ed25519 \
  --mode seed \
  --use derive \
  --use ssh-agent
```

Then:

```bash
tpm2-derive derive \
  --profile seed-user \
  --purpose ssh-agent \
  --namespace tpm2ssh \
  --context account=alice \
  --length 32
```

#### Seed recovery export

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

#### Seed ssh-agent add

Currently the best-supported path is:

- `seed + ed25519 + ssh-agent`

```bash
tpm2-derive ssh agent add --profile seed-user
```

### Good seed combos today

- `ed25519 + seed + derive`
- `ed25519 + seed + ssh-agent`
- `ed25519 + seed + recovery-bundle export`
- `secp256k1 + seed + derive` is conceptually reasonable, but check the specific consuming flow

### Seed combos that are partial / not wired

- seed sign/verify as first-class CLI signing flow
- recovery import as a first-class CLI command
- broader ssh-agent coverage beyond the current seed/ed25519-focused path

---

## Recommended presets

### A. Hardware-backed signer

Use when:

- you want TPM-native P-256 signing

Use:

- `algorithm=p256`
- `mode=native`
- `use=sign`
- `use=verify`

### B. Deterministic app secret / app derivation

Use when:

- you want deterministic bytes from labeled context

Prefer:

- `mode=prf`
- `use=derive`

Fallback:

- `mode=seed`
- `use=derive`

### C. SSH identity / user identity

Use when:

- you want a deterministic software key from TPM-protected-at-rest state

Prefer today:

- `algorithm=ed25519`
- `mode=seed`
- `use=ssh-agent`
- `use=derive`

### D. Recovery-friendly profile

Use when:

- you need a break-glass backup/export path

Use:

- `mode=seed`
- explicit recovery export workflow

---

## Combinations matrix

| Algorithm | Mode | Derive | Sign | Verify | Export public key | Recovery export | SSH agent add | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| p256 | native | no | yes | yes | yes | no | no | best-supported native path |
| p256 | prf | yes | no | no | no | no | no | derive-only useful today |
| p256 | seed | yes | partial/no | partial/no | no | yes | limited | fallback only |
| ed25519 | native | no | no | no | no | no | no | not a real target |
| ed25519 | prf | yes | no | no | no | no | no | useful derive root |
| ed25519 | seed | yes | limited | limited | no | yes | yes | best current SSH-style path |
| secp256k1 | native | no | no | no | no | no | no | not a real target |
| secp256k1 | prf | yes | no | no | no | no | no | derive-only useful today |
| secp256k1 | seed | yes | limited | limited | no | yes | limited | fallback path |

---

## If you’re unsure what to do

### Want a TPM-native signer?
Use:

- `p256`
- `native`
- `sign`, `verify`

### Want deterministic app secrets?
Use:

- `prf`
- `derive`

### Want SSH / Ed25519 user identity?
Use:

- `ed25519`
- `seed`
- `ssh-agent`, `derive`

### Want backup / migration export?
Use:

- `seed`
- `export --kind recovery-bundle`

---

## Current rough edges

- some commands still report unsupported for certain mode/algorithm combinations
- PRF provisioning can fail because of TPM transport/TCTI environment, especially under `sudo`
- recovery import exists in library code but is not yet a dedicated CLI command
- encrypt/decrypt are placeholders right now

---

## See also

- `docs/TPM2_DERIVE_PLAN.md`
- `docs/progress.md`
