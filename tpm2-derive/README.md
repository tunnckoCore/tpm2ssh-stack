# tpm2-derive

TPM-backed identity operations with native, PRF, and seed modes.

## CLI contract

The persisted unit is a named **identity**:

```bash
tpm2-derive identity <name> --mode <auto|native|prf|seed> --algorithm <p256|ed25519|secp256k1> --use <...>
```

Operational commands stay flat and select an identity with `--with`:

```bash
tpm2-derive sign --with <name> ...
tpm2-derive verify --with <name> ...
tpm2-derive encrypt --with <name> ...
tpm2-derive decrypt --with <name> ...
tpm2-derive derive --with <name> ...
tpm2-derive export --with <name> --kind <public-key|secret-key|keypair|recovery-bundle> ...
tpm2-derive ssh-add --with <name> ...
```

Derivation inputs use the unified ADR vocabulary:

- `--org`
- `--purpose`
- repeated `--context key=value`

For PRF and seed identities, command-line derivation inputs override or merge with identity defaults.
For native identities, derivation-input flags are rejected.

## Modes

### native

Uses TPM-native keys and TPM-native operations.

Supported today:

- `sign`
- `verify`
- public-key export

Not supported today:

- `derive`
- `ssh-add`
- secret-key export
- native encrypt/decrypt in this prototype slice

### prf

Uses a TPM-backed PRF root and derives operation material from the effective identity inputs.

Supported:

- `sign`
- `verify`
- `encrypt`
- `decrypt`
- `derive`
- `ssh-add`
- public-key export
- secret-key and keypair export when the identity was created with `--use export-secret`

### seed

Uses a TPM-sealed seed and derives child material in software after unsealing.

Supported:

- `sign`
- `verify`
- `encrypt`
- `decrypt`
- `derive`
- `ssh-add`
- public-key export
- secret-key and keypair export when the identity was created with `--use export-secret`
- recovery-bundle export/import

## Examples

Inspect the local TPM and recommendation surface:

```bash
tpm2-derive inspect --algorithm p256 --use sign --use verify
```

Create a native signing identity:

```bash
tpm2-derive identity prod-signer \
  --mode native \
  --algorithm p256 \
  --use sign \
  --use verify
```

Create a PRF identity with derivation defaults:

```bash
tpm2-derive identity app-prf \
  --mode prf \
  --algorithm p256 \
  --use all \
  --org com.example \
  --purpose app \
  --context tenant=alpha
```

Use that identity for sign/derive/export/ssh-add:

```bash
tpm2-derive sign --with prod-signer --input message.bin

tpm2-derive derive \
  --with app-prf \
  --org com.example \
  --purpose session \
  --context tenant=alpha \
  --length 32

tpm2-derive export \
  --with app-prf \
  --kind public-key \
  --format spki-pem \
  --output app-prf.pem

tpm2-derive ssh-add --with app-prf --org com.example --context account=prod
```

Create an export-enabled seed identity:

```bash
tpm2-derive identity backup-seed \
  --mode seed \
  --algorithm ed25519 \
  --use all \
  --use export-secret \
  --org com.example \
  --purpose personal
```

Secret-bearing export stays explicit and high-friction:

```bash
tpm2-derive export \
  --with backup-seed \
  --kind secret-key \
  --confirm \
  --reason backup \
  --output backup-seed.secret.hex

tpm2-derive export \
  --with backup-seed \
  --kind keypair \
  --confirm \
  --reason "hardware migration" \
  --output backup-seed.keypair.json
```

Recovery-bundle import:

```bash
tpm2-derive import --bundle backup.json --identity restored-user --confirm
```

## Notes

- `--use all` expands according to the resolved mode and the native capability matrix.
- `ssh-add` is intentionally separate from `use=ssh` and rejects native identities.
- The legacy `keygen` command is no longer part of the public ADR surface; use `export --kind ...` instead.
- The accepted ADR for this CLI is in `decisions/2026-04-22-unify-cli-surface-across-native-prf-seed.md`.
