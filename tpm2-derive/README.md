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
tpm2-derive export --with <name> --kind <public-key|secret-key|keypair> ...
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
- `ssh-add`
- public-key export
- secret-key and keypair export when the identity was created with `--use export-secret`

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

Use that identity for sign/export/ssh-add:

```bash
tpm2-derive sign \
  --with prod-signer \
  --input message.bin \
  --format base64 \
  --output message.sig

tpm2-derive verify \
  --with prod-signer \
  --input message.bin \
  --signature message.sig \
  --format base64

tpm2-derive export \
  --with app-prf \
  --kind public-key \
  --format pem \
  --output app-prf.pem

tpm2-derive export \
  --with wallet-seed \
  --kind public-key \
  --format eth \
  --output wallet.address

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
  --format base64 \
  --confirm \
  --reason backup \
  --output backup-seed.secret.base64

tpm2-derive export \
  --with backup-seed \
  --kind keypair \
  --format pem \
  --confirm \
  --reason "hardware migration" \
  --output backup-seed.keypair.json
```


## Testing

The default `cargo test` suite stays mock-only.

The real TPM integration suite is feature-gated, spins up an isolated `swtpm`, and exercises the supported library flows against real `tpm2-tools` subprocesses without touching a hardware TPM:

```bash
cargo test --features real-tpm-tests --test real_tpm_cli
```

The harness will try PATH first and can auto-resolve missing tool binaries from Nix when available. A deterministic Nix-based invocation is:

```bash
nix shell nixpkgs#swtpm nixpkgs#tpm2-tools -c cargo test --features real-tpm-tests --test real_tpm_cli
```

## Notes

- `--use all` expands according to the resolved mode and the native capability matrix.
- `ssh-add` is intentionally separate from `use=ssh` and rejects native identities.
- There is no standalone `derive` command anymore; use the operational commands for actual work, and use `export` when you intentionally need key material artifacts from an existing identity with derivation overrides/default merges.
- The old raw-byte `derive --format hex|base64 --length N` workflow is intentionally gone from the public CLI.
- `export --kind public-key --format hex|base64` emits raw public key bytes (Ed25519 raw key bytes; secp curves as uncompressed SEC1 bytes), not SPKI-wrapped bytes.
- `export --format openssh` is currently wired for the SSH-capable key shapes in this project (ed25519 and p256), not secp256k1.
- `export --kind public-key --format eth` emits a checksummed Ethereum address for secp256k1 identities.
- `export --kind secret-key --format eth` aliases the secret key to hex output.
- `export --kind keypair --format eth` is secp256k1-only and writes JSON with hex-encoded `private_key`, hex-encoded uncompressed `public_key`, and an `address` entry with format `eth`.
- `export --kind keypair` always writes JSON with explicit `private_key` and `public_key` entries, and each entry declares its own emitted format.
- The legacy `keygen` command is no longer part of the public ADR surface; use `export --kind ...` instead.
- The accepted ADR for this CLI is in `decisions/2026-04-22-unify-cli-surface-across-native-prf-seed.md`.
