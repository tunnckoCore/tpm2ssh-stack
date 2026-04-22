---
status: accepted
date: 2026-04-22
decision-makers: arcka
---

# Unify the CLI surface across native, PRF, and seed identities

## Context and Problem Statement

The current Rust CLI already has three meaningful backing modes:

- `native` — use TPM-native objects and TPM-native operations
- `prf` — use a TPM-backed PRF root and derive operation material from it
- `seed` — use a TPM-sealed seed and derive operation material in software

Those modes are intentionally different and should remain different. The redesign is not trying to erase that distinction.

The problem is the current CLI surface and command/use matrix do not reflect that intent well:

- the user-facing verbs are not mostly shared across the modes
- `prf` is artificially constrained in the current CLI even though it can back the same high-level operations as `seed`
- `setup` describes an implementation step rather than a reusable named thing
- the current context flag names are not what we want long-term
- `ssh-agent` the command and `ssh-agent` the use bit are conflated
- `auto` mode selection exists, but the native capability matrix is not the first-class thing driving what a named identity can or cannot do

The redesign goal is:

1. keep the three modes distinct in backing behavior
2. make the user-facing CLI mostly the same across those modes
3. let inspection and auto-resolution decide what is possible for a given TPM and algorithm
4. make a named identity the reusable unit
5. make per-command overrides work the same way for `prf` and `seed`, and reject them for `native`

This decision file defines the target CLI contract, mode/use matrix, naming, and examples. It intentionally does **not** define an implementation plan.

## Decision

### 1. The reusable named thing is an identity

The CLI will model the persisted thing as a named **identity**.

Identity creation uses a flat form with explicit `--mode`:

```bash
tpm2x identity <name> --mode <auto|native|prf|seed> [identity options]
```

Examples:

```bash
# fully explicit native identity
tpm2x identity wgw --mode native --algorithm p256 --use sign --use verify

# auto-resolved identity
tpm2x identity wgw --mode auto --algorithm p256 --use sign --use verify

# PRF identity with default derivation inputs
tpm2x identity wgwprf --mode prf --algorithm p256 --use all --org com.example --purpose user1

# seed identity with default derivation inputs
tpm2x identity wgwseed --mode seed --algorithm ed25519 --use all --org com.example --purpose user1
```

`setup` is replaced by `identity` in the public CLI vocabulary.

### 2. Operational commands stay flat and select an identity with `--with`

The operational verbs remain flat and use `--with <identity>`.

```bash
tpm2x sign --with <name> ...
tpm2x verify --with <name> ...
tpm2x encrypt --with <name> ...
tpm2x decrypt --with <name> ...
tpm2x export --with <name> ...
tpm2x ssh-add --with <name> ...
```

Examples:

```bash
tpm2x sign --with wgw --input msg.txt
tpm2x verify --with wgwprf --input msg.txt --signature msg.sig
tpm2x encrypt --with wgwseed --input secret.txt --output secret.bin

tpm2x export --with wgw --kind public-key --output wgw.spki.der
tpm2x export --with wgwprf --kind public-key --output wgwprf.spki.der
tpm2x ssh-add --with wgwprf
tpm2x ssh-add --with wgwprf --org com.acme --context account=wgw:user1
```

`--with` is the canonical selector for all identity-bound operations.

### 3. `auto` remains a real mode choice at identity creation time

`auto` remains supported as an identity creation mode.

Its job is to resolve the identity to exactly one backing mode using inspection/probing logic.

`auto` resolution must consider all of the following:

- requested algorithm
- requested use set
- TPM-native support for the requested algorithm and each requested native action/use
- TPM availability for PRF backing
- TPM availability for seed backing

`auto` must obey these rules:

- it chooses one mode for the whole identity
- it must never resolve to a mode that cannot satisfy the full requested use set
- it must not silently drop requested uses
- it must not silently create identity with different mode that support all uses - it should throw and notify the reason like "encrypt/decrypt use is not supported for native mode for that tpm for that algorithm"
- it must not silently switch modes - eg. if `native` is set, but the TPM does not support some of the uses - it should not create `prf` identity because it supports the set of uses 
- it must not create hybrid identities
- if the requested use set can only be satisfied by a different identity in a different mode, the user must create another identity and be informed about that

This means a user may legitimately need:

- one `native` identity for TPM-native sign/verify or encrypt/decrypt
- another `prf` or `seed` identity for operations not available natively for that algorithm on that TPM

The probe/recommender may keep its own ranking logic, but compatibility is not optional.

### 4. `inspect` becomes the authoritative native capability view

`inspect` must expose the capability matrix that matters for identity creation and auto-resolution.

At minimum, inspection must make it visible, per relevant algorithm, whether native TPM support exists for:

- `sign`
- `verify`
- `encrypt`
- `decrypt`
- does it support actual PRF on the TPM

And whether backing is available for:

- `prf`
- `seed`

This capability view is what drives whether `native` and `auto` can accept a requested use set.

### 5. `use` is a mode-and-capability contract, not a wish list

The user-facing use vocabulary is:

- `sign`
- `verify`
- `encrypt`
- `decrypt`
- `ssh`

The current `ssh-agent` "use" bit is renamed to just `ssh`.

The `--use all` remains supported, but its expansion depends on the resolved mode and native capability matrix.

The `--use` flag is required. This helps users be mindful and explicit about what their identity should be able to do.

The use contract also has coupling rules:

- `verify` requires `sign`
- `decrypt` requires `encrypt`
- `ssh` requires `sign`

Those pairings are intentional because the current implementation derives the same signing/encryption identity material for those coupled operations.

#### 5.1 Native use rules

A `native` identity may declare only the native-compatible uses that are actually supported for its algorithm on the current TPM.

The intended native surface is:

- `sign`
- `verify`
- `encrypt`
- `decrypt`
- `ssh`

with these constraints:

- `ssh` as a use bit is allowed on `native` as a future-facing intent bit for helper-based flows that use `sign` rather than daemon agents, eg. git helper for signing commits should be allowed only if the identity has `ssh` use bit set.
- `encrypt` and `decrypt` are allowed only if inspection says the TPM natively supports them for that algorithm
- `all` expands only to the native-compatible uses that are actually available for that algorithm on that TPM
- `export-secret` is never allowed on `native`

So `native` support is both mode-dependent and capability-dependent.

The `auto` mode should start from `native` then try `prf` then `seed` - in that exact order.

#### 5.2 Seed and PRF use rules

A `prf` identity supports the same high-level operational surface as `seed`. But differs in the lower-level, fundamentally - it is backed by the PRF on the TPM, while `seed` seals a generated secret on the TPM which gets unsealed and sits in-memory when operation/action is requested, until the action is done then cleared from memory.

Allowed seed/PRF uses are:

- `sign`
- `verify`
- `encrypt`
- `decrypt`
- `ssh`

The `--use all` on `prf` and `seed` expands to all of the above.

The `--use all` never includes `export-secret`. The `--use export-secret` is always required as explicit separate flag.

The export of public and private/secret keys are supported for both `prf` and `seed` modes, but the important nuance is that to be able to export the private key user must add `export-secret` use bit when creating the identity.

For export of the whole key pair, the user should create the identity like so:

```bash
tpm2x identity acme --mode prf --use all --use export-secret

# later they can export both keys at once, or each one separately
tpm2x export --kind keypair --confirm --reason "hardware migration" --output acme-keypair.json
tpm2x export --kind secret-key --confirm --reason "hardware migration" --format hex --output acme-secret.key

# prints to stdout
tpm2x export --kind public-key --format <pem/openssh/der/eth/hex/base64>

# secp256k1-only ethereum address surface

tpm2x export --kind public-key --format eth

tpm2x export --kind keypair --format eth --confirm --reason "wallet migration" --output acme-wallet.json
```

In short: `--kind keypair` and `--kind secret-key` require `export-secret` use bit on the identity to be enabled. The `--kind public-key` is perfectly valid even without the `export-secret` use bit.

### 6. Shared command surface, different backing behavior

The CLI contract is intentionally unified while the backing remains different.

#### 6.1 Native behavior

A `native` identity performs operations using TPM-native keys and TPM-native operations.

Native supports:

- sign
- verify
- encrypt
- decrypt
- public-key export

Native does not support:

- secret-key export
- `ssh-add`

If the TPM does not support a requested native action for the chosen algorithm, identity creation in `native` mode must fail, and on `auto` it should not resolve to `native` for that use set.

#### 6.2 PRF behavior

A `prf` identity performs operations by resolving the identity plus derivation inputs, invoking the TPM-backed PRF flow, and using the resulting child material for the requested operation.

PRF supports:

- sign
- verify
- encrypt
- decrypt
- `ssh-add`
- public-key export
- secret-key export (only if `export-secret` use bit)

The exported public key for a PRF identity is the public key of the resolved child key for the effective derivation inputs, not a public key of the PRF root itself.

The export of BOTH public and secret key is supported. But the export of secret key is only possible if the user created the identity with `export-secret` use bit. The `export` command must fail if this use bit is not present in the identity. 

#### 6.3 Seed behavior

A `seed` identity performs operations by resolving the identity plus derivation inputs, unsealing the seed, deriving child material based on the derivation inputs, and using that child material for the requested operation.

Seed supports:

- sign
- verify
- encrypt
- decrypt
- `ssh-add`
- public-key export
- secret-key export (only if `export-secret` use bit)

Seed export rules:

- public-key export is allowed
- secret-key export is allowed
- the `export-secret` use bit on the identity is REQUIRED to be able to use `export --kind keypair` or `export --kind secret-key`
- the `export` command still requires `--confirm` and `--reason` even if the identity has `export-secret` use bit

### 7. `ssh-agent` the command is renamed to `ssh-add`

The command name becomes:

```bash
tpm2x ssh-add --with <name>
```

This command supports only:

- `prf`
- `seed`

For now, `ssh-add` is implemented only for algorithms that map cleanly to the current SSH/OpenSSH support in this project:

- `ed25519`
- `p256`

It is not currently implemented for `secp256k1`.

It must reject `native` identities.

This is separate from `use=ssh`.

Rationale:

- `ssh-add` is the user action the command performs
- `use=ssh` describes intended identity usage, not daemon integration
- native identities may still declare `ssh` use for future helper-driven flows that rely on `sign` and allowing to avoid daemon agents like `ssh-agent` and `gpg-agent` entirely

Examples:

```bash
# allowed
tpm2x ssh-add --with wgwprf
tpm2x ssh-add --with wgwseed

# rejected (assuming `wgw` identity is native)
tpm2x ssh-add --with wgw
```

### 8. Derivation input flags are renamed and unified

The user-facing derivation input flags are:

- `--org` instead of `--namespace`
- `--context` stays `--context`
- `--purpose` stays `--purpose`

The public CLI shape is:

- `--org <string>`
- `--purpose <string>`
- `--context <key=value>` repeated as needed

Examples:

```bash
tpm2x identity wgwprf --mode prf \
  --algorithm p256 \
  --use all \
  --org com.example \
  --purpose user1 \
  --context tenant=alpha \
  --context role=teamlead

tpm2x sign --with wgwprf --input msg.txt

# same org, same tenant=alpha, but different "purpose" eg. "user2"
tpm2x sign \
  --with wgwprf \
  --org com.example \
  --purpose user2 \
  --context tenant=alpha \
  --input msg.txt
```

### 9. Derivation input precedence rules

All operational commands that use an identity accept `--org`, `--purpose`, and repeated `--context`.

For `prf` and `seed`:

- identity creation may store default derivation inputs
- command-line `--org` and `--purpose` override identity defaults when provided
- command-line `--context` merges with the identity defaults by key
- if a command provides a context key that does not exist in the identity defaults, that key is appended to the effective context set
- if a command provides a context key that already exists in the identity defaults, the command value replaces the default value for that key
- if the same context key is repeated multiple times on one command, the last provided value wins
- omitted derivation inputs fall back to the identity defaults
- the effective derivation input set is what determines the derived child material for sign/verify/encrypt/decrypt/export/ssh-add

For `native` identity:

- `--org` is invalid
- `--purpose` is invalid
- `--context` is invalid
- passing any of them is throwing an error

This applies both when the identity was explicitly created as `native` and when it resolved to `native` through `auto`.

### 10. Standalone `derive` is removed

The standalone `derive` command is removed from the public CLI surface.

The underlying PRF/seed derivation behavior still exists, but it is now reached through the identity-bound operational commands and through `export` with derivation overrides/default merges.

That means:

- no standalone `derive` command in the public surface
- no `use=derive` in the public use vocabulary
- the old raw-byte derive workflow is intentionally removed from the public CLI
- PRF/seed derivation remains the internal mechanism that powers `sign`, `verify`, `encrypt`, `decrypt`, `export`, and `ssh-add`
- for `seed`, operations still use derived child material rather than exposing the raw sealed seed
- for `prf`, operations still use finalized PRF-derived output rather than exporting the PRF root itself

### 11. Export rules are unified at the command level and differentiated by mode

`export` remains a shared command:

```bash
tpm2x export --with <name> --kind <kind> [other options]
```

Mode-specific export policy:

| Mode   | Public key export | Secret key export                      |
|--------|-------------------|----------------------------------------|
| native | yes               | no                                     |
| prf    | yes               | yes (requires `export-secret` use bit) |
| seed   | yes               | yes (requires `export-secret` use bit) |

For `prf` and `seed`, export resolves against the effective derivation inputs.

For `native`, export refers to the native TPM-backed key itself.

Examples:

```bash
# native public key
tpm2x export --with wgw --kind public-key --output wgw.spki.der

# prf public key for the effective derived child key
tpm2x export --with wgwprf --kind public-key --output wgwprf.spki.der

# seed secret key export remains explicit and high-friction
tpm2x export --with wgwseed --kind secret-key --output wgwseed.sec --confirm --reason backup
```

Important: exporting the secret key or the keypair requires `export-secret` use bit set on the identity at creation time.

### 12. Command/mode matrix

#### 12.1 Operational command matrix

| Command    | native | prf | seed |
|------------|:------:|:---:|:----:|
| sign       | yes    | yes | yes  |
| verify     | yes    | yes | yes  |
| encrypt    | yes¹   | yes | yes  |
| decrypt    | yes¹   | yes | yes  |
| export public key | yes | yes | yes |
| export secret key | no | yes² | yes² |
| ssh-add    | no     | yes³ | yes³  |

- `yes¹` means subject to per-algorithm native TPM capability.
- `yes²` means supported, but only if the identity has `export-secret` use bit set.
- `yes³` means currently implemented for `ed25519` and `p256`, but not `secp256k1`.

#### 12.2 The `use` matrix

| Use      | native | prf | seed |
|----------|:------:|:---:|:----:|
| sign     | yes*   | yes | yes  |
| verify   | yes*   | yes | yes  |
| encrypt  | yes*   | yes | yes  |
| decrypt  | yes*   | yes | yes  |
| ssh      | yes    | yes | yes  |
| export-secret | no | yes | yes  |

Again, `yes*` means subject to native TPM support for the chosen algorithm.

Important: `export-secret` is disallowed on `native` identities, e.g. `tpm2x identity wgw --mode native --use all --use export-secret` should fail.

### 13. Example flows

#### 13.1 Native signing and public export

```bash
tpm2x identity wgw --mode native --algorithm p256 --use sign --use verify

tpm2x sign --with wgw --input msg.txt
tpm2x verify --with wgw --input msg.txt --signature msg.sig

tpm2x export --with wgw --kind public-key --output wgw.spki.der
```

And it throws/fails because there is no `encrypt` use bit set on `wgw` identity:

```bash
# throws error
tpm2x encrypt --with wgw --input msg.txt --output ciphertext.bin
```

#### 13.2 Native identity rejected for derivation flags

```bash
tpm2x sign --with wgw --org com.example --input msg.txt
# error: --org/--purpose/--context are invalid for native identities
```

#### 13.3 Auto chooses a native identity when native capability is sufficient

```bash
tpm2x identity wgw --mode auto --algorithm p256 --use sign --use verify
```

If native sign/verify exists for `p256`, `auto` may resolve to `native`.

#### 13.4 Auto does not create a hybrid identity

```bash
tpm2x identity mixed_id --mode auto --algorithm p256 --use sign --use verify --use export-secret
```

This must resolve to exactly one mode that can satisfy the full use set. If no single mode is valid, identity creation fails.

If the operator wants native sign/verify plus separate secret-export workflows, they must create separate identities.

If `auto` would otherwise choose `native`, but the TPM does not support one of the requested native uses for the selected algorithm, identity creation must fail instead of silently switching modes.

```bash
# throws if the TPM does not support native encrypt/decrypt for the selected algorithm
tpm2x identity wgw_failing --mode auto --algorithm secp256k1 --use sign --use verify --use encrypt --use decrypt
```

For `prf` and `seed`, identity creation must fail only when the selected backing mode itself is unavailable or cannot satisfy the requested use set. It must not be rejected based on unrelated missing native TPM support for encrypt/decrypt.

#### 13.5 PRF identity with default derivation inputs

```bash
tpm2x identity wgwprf --mode prf \
  --algorithm p256 \
  --use all \
  --org com.example \
  --purpose user1 \
  --context tenant=alpha

tpm2x sign --with wgwprf --input msg.txt
tpm2x verify --with wgwprf --input msg.txt --signature msg.sig
tpm2x encrypt --with wgwprf --input secret.txt --output secret.bin
tpm2x decrypt --with wgwprf --input secret.bin --output secret.txt
tpm2x export --with wgwprf --kind public-key --output wgwprf.spki.der
tpm2x ssh-add --with wgwprf
```

#### 13.6 Context merge examples

```bash
# identity defaults
tpm2x identity wgwprf --mode prf \
  --algorithm p256 \
  --use all \
  --org com.acme \
  --purpose user1 \
  --context tenant=alpha
  
tpm2x sign --with wgwprf --input msg.txt

# merges into `context: { tenant:alpha , role: git }`
tpm2x sign --with wgwprf --context role=git --input msg.txt

# becomes `context: { tenant:beta }`
tpm2x sign --with wgwprf --context tenant=beta --input msg.txt

# becomes `context: { tenant:gamma }`
tpm2x sign \
  --with wgwprf \
  --context tenant=beta \
  --context tenant=gamma \
  --input msg.txt
```

These examples show the intended `context` use bit behavior:

- `sign --with wgwprf --input msg.txt` uses the identity defaults as-is
- `--context role=git` adds a new context key to the effective derivation input set
- `--context tenant=beta` replaces the identity default value for the `tenant` key
- repeating `--context tenant=...` on the same command uses the last provided value

#### 13.7 PRF per-command override

```bash
tpm2x sign \
  --with wgwprf \
  --purpose deploy \
  --context tenant=beta \
  --input msg.txt
```

The command-level derivation inputs override the identity defaults for `--org` and `--purpose`. `--context` merges by key: new keys are appended, existing keys are replaced by the command value.

#### 13.8 Seed/PRF identity with exportable secret material

```bash
tpm2x identity wgwseed --mode seed \
  --algorithm ed25519 \
  --use all \
  --use export-secret \
  --org com.example \
  --purpose personal

tpm2x sign --with wgwseed --input msg.txt
tpm2x export --with wgwseed --kind public-key --output wgwseed.pub
tpm2x export --with wgwseed --kind secret-key --output wgwseed.sec --confirm --reason backup
tpm2x ssh-add --with wgwseed

# or exporting the whole keypair
tpm2x export --with wgwseed --kind keypair --output wgwseed.json --confirm --reason "hardware migration"
```

## Consequences

- Good, because the CLI becomes mode-consistent without flattening away the meaningful difference between TPM-native, TPM-PRF, and sealed-seed backing.
- Good, because `prf` and `seed` now expose the same high-level verbs even though their internal derivation sources remain different.
- Good, because native capability becomes explicit and inspectable per algorithm and action instead of being hidden behind a coarse mode-level assumption.
- Good, because `auto` remains useful but is constrained to honest, single-mode resolution.
- Good, because `--with <identity>` gives a stable, reusable selector across all operational commands.
- Good, because `ssh-add` the command is separated from `use=ssh` the use bit, which leaves room for future native helper flows without daemon-agent requirements.
- Good, because derivation-input overrides now work uniformly for `prf` and `seed` and are rejected clearly for `native`.
- Good, because the operational commands and `export` now carry the whole derivation story without a redundant standalone `derive` command.
- Good, because adds explicit `export-secret` for `prf` and `seed` modes, disallowing secret/keypair export if the `use=export-secret` is missing for the selected identity.
- Good, because adds separate kinds for the `export` command like `--kind public-key`, `--kind secret-key`, and `--kind keypair`.
- Good, because makes the `export` command require `use=export-secret` for `--kind secret-key` and `--kind keypair`.
- A single conceptual user may need multiple identities when native TPM capability does not cover all desired uses for one algorithm.
- Good, because `prf` public-key export must be understood as export of a derived child key, not export of the PRF root, and therefore requires clearer help text and examples.
- Good, because renaming and unifying commands (`setup` → `identity`, `ssh-agent` → `ssh-add`, `--namespace` → `--org`) is acceptable during the current prototyping phase.
- Bad, because allowing `use=ssh` on native while rejecting `ssh-add` on native introduces an intentional distinction that must be documented carefully.

## Alternatives Considered

- Keep the current mode-specific matrix and only rename commands: rejected because it preserves the main design problem — the public CLI stays asymmetrical even though `prf` and `seed` should expose the same high-level verbs.
- Collapse `prf` and `seed` into one derived mode: rejected because they are fundamentally different backing mechanisms and that difference matters for security properties, export behavior, and implementation.
- Keep `ssh-agent` as both command name and `--use` bit name: rejected because it ties a user intent bit to a specific daemon-based transport mechanism and blocks cleaner native-helper flows.
- Keep the old derivation flag names: rejected because `--org` / `--purpose` / `--context` is the desired public vocabulary for this redesign.

## More Information

- This decision intentionally specifies CLI behavior, naming, and compatibility rules only.
- It intentionally does **not** include an implementation plan.
- Review of this decision should focus on:
  - command naming
  - command/mode matrix correctness
  - use matrix correctness
  - auto-resolution contract
  - export policy by mode
  - derivation flag semantics and precedence
