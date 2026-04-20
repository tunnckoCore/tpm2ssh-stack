# TPM2 Derive Combinations Guide

_User-facing guide for which combinations currently make sense._

## Short version

If you just want a safe default:

- **TPM-native P-256 signing / verification** → use **`p256 + native`**
- **Deterministic app secrets / labeled bytes** → use **`prf`** if your TPM/tooling path works
- **SSH user key via `tpm2ssh`** → you can choose **`p256` _or_ `ed25519`**
- **Direct `tpm2-derive ssh agent add`** → today that is the **`seed + ed25519`** slice
- **Recovery export** → only meaningful for **`seed`**

The important distinction is:

- **SSH does not mean Ed25519 only** in this project
- but **the direct `tpm2-derive ssh agent add` command is still narrower than the higher-level `tpm2ssh` wrapper**

---

## Mental model

There are 3 modes:

- **`native`** = TPM-native keys and TPM-native operations
- **`prf`** = TPM-backed deterministic byte derivation via TPM HMAC/PRF-style flow
- **`seed`** = one TPM-sealed seed, then software derivation at use time

They do **not** all support the same operations.

There are also **two different SSH stories** right now:

1. **Direct `tpm2-derive ssh agent add`**
   - a narrow vertical slice in this CLI
   - currently wired for **seed-mode Ed25519** only
2. **`tpm2ssh` managed SSH/Git identity flow**
   - higher-level wrapper built on `tpm2-derive`
   - currently supports **OpenSSH P-256** and **Ed25519** user keys

That distinction is the main reason older docs could read like “SSH means Ed25519”.

---

## What works today

### 1. Native mode

Best for:

- `p256`
- `sign`
- `verify`
- public-key export

### Currently usable native combination

#### P-256 TPM-native signer

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
- `p256 + native + export public-key`

### Important native clarification

This is the best-supported **P-256 signing** path, but it is **not** the same thing as the current direct `tpm2-derive ssh agent add` path.

If what you want is:

- a TPM-native non-exportable signer → use **`p256 + native`** in `tpm2-derive`
- an OpenSSH user key loaded into `ssh-agent` for SSH/Git use → use **`tpm2ssh`**, where **P-256 is still a valid option**

### Bad / not-useful native combos

- `ed25519 + native`
- `secp256k1 + native`
- `native + derive`
- direct `native + ssh-agent add`

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
- direct `prf + ssh-agent add`
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

- Ed25519 / P-256 / secp256k1 software identities
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

Currently the direct CLI path is:

- `seed + ed25519 + ssh-agent`

```bash
tpm2-derive ssh agent add --profile seed-user
```

### Good seed combos today

- `ed25519 + seed + derive`
- `ed25519 + seed + ssh-agent`
- `ed25519 + seed + recovery-bundle export`
- `p256 + seed + derive` for downstream wrappers such as `tpm2ssh`
- `secp256k1 + seed + derive` is conceptually reasonable, but check the specific consuming flow

### Seed combos that are partial / not wired

- seed sign/verify as first-class CLI signing flow
- recovery import as a first-class CLI command
- broader direct `ssh-agent add` coverage beyond the current seed/ed25519 slice

---

## 4. SSH identity flows

This is the easiest place to get confused, so here is the explicit version.

### A. Want a direct `tpm2-derive ssh agent add` flow?

Use today:

- `algorithm=ed25519`
- `mode=seed`
- `use=ssh-agent`
- `use=derive`

This is the currently wired direct CLI SSH path.

### B. Want an SSH/Git identity through `tpm2ssh`?

Use `tpm2ssh` and choose whichever algorithm you want:

- **P-256** if you want an OpenSSH ECDSA NIST P-256 user key
- **Ed25519** if you want an OpenSSH Ed25519 user key

Interactive flow:

```bash
tpm2ssh --setup
tpm2ssh --login
```

When prompted, choose either:

- `1` → **NIST P-256**
- `2` → **Ed25519**

### Practical recommendation

If you are deciding between the two:

- choose **P-256** when you want the most explicit, user-friendly path for **P-256 SSH/Git signing identities** in this repo today
- choose **Ed25519** when you specifically want the currently wired direct `tpm2-derive ssh agent add` slice

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

### C. SSH / Git identity through `tpm2ssh`

Use when:

- you want an OpenSSH user key in `ssh-agent`
- you want to use the same public key for SSH auth and Git SSH signing

Choose either:

- `algorithm=p256` for OpenSSH ECDSA NIST P-256
- `algorithm=ed25519` for OpenSSH Ed25519

Then run:

```bash
tpm2ssh --setup
tpm2ssh --login
```

### D. Direct `tpm2-derive` SSH agent flow

Use when:

- you want to stay in `tpm2-derive` directly
- today’s Ed25519 seed-based ssh-agent flow is sufficient

Use:

- `algorithm=ed25519`
- `mode=seed`
- `use=ssh-agent`
- `use=derive`

### E. Recovery-friendly profile

Use when:

- you need a break-glass backup/export path

Use:

- `mode=seed`
- explicit recovery export workflow

---

## Combinations matrix

This matrix is about **current `tpm2-derive` CLI coverage**, not every higher-level wrapper built on top of it.

| Algorithm | Mode | Derive | Sign | Verify | Export public key | Recovery export | Direct `tpm2-derive ssh agent add` | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| p256 | native | no | yes | yes | yes | no | no | best-supported native signer path |
| p256 | prf | yes | no | no | no | no | no | derive-only useful today; can still feed downstream SSH/Git wrappers |
| p256 | seed | yes | partial/no | partial/no | no | yes | no | fallback derive path; useful for downstream wrappers such as `tpm2ssh` |
| ed25519 | native | no | no | no | no | no | no | not a real target |
| ed25519 | prf | yes | no | no | no | no | no | useful derive root |
| ed25519 | seed | yes | limited | limited | no | yes | yes | best current direct `tpm2-derive` SSH-style path |
| secp256k1 | native | no | no | no | no | no | no | not a real target |
| secp256k1 | prf | yes | no | no | no | no | no | derive-only useful today |
| secp256k1 | seed | yes | limited | limited | no | yes | limited | fallback path |

### Matrix footnote

If you are thinking “but I want **P-256 SSH**”, the answer is:

- yes, that is a valid project flow
- use **`tpm2ssh`** for that user-facing SSH/Git identity today
- do **not** read the direct `ssh agent add` column as “SSH in this repo only works with Ed25519”

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

### Want P-256 SSH / Git signing identity?
Use:

- `tpm2ssh --setup`
- `tpm2ssh --login`
- choose **P-256** when prompted

### Want Ed25519 SSH identity directly from `tpm2-derive`?
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

- direct `tpm2-derive ssh agent add` is still narrower than the broader `tpm2ssh` wrapper
- some commands still report unsupported for certain mode/algorithm combinations
- PRF provisioning can fail because of TPM transport/TCTI environment, especially under `sudo`
- recovery import exists in library code but is not yet a dedicated CLI command
- encrypt/decrypt are placeholders right now

---

## See also

- `docs/TPM2_DERIVE_PLAN.md`
- `docs/progress.md`
- `tpm2ssh/README.md`
