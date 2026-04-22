---
status: proposed
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

Identity creation uses a flat mode-first form:

```bash
tpm2x identity <auto|native|prf|seed> <name> [identity options]
```

Examples:

```bash
# fully explicit native identity
tpm2x identity native wgw --algorithm p256 --use sign --use verify

# auto-resolved identity
tpm2x identity auto wgw --algorithm p256 --use sign --use verify

# PRF identity with default derivation inputs
tpm2x identity prf wgwprf --algorithm p256 --use all --org com.example --purpose user1

# seed identity with default derivation inputs
tpm2x identity seed wgwseed --algorithm ed25519 --use all --org com.example --purpose user1
```

`setup` is replaced by `identity` in the public CLI vocabulary.

### 2. Operational commands stay flat and select an identity with `--with`

The operational verbs remain flat and use `--with <identity>`.

```bash
tpm2x sign --with <name> ...
tpm2x verify --with <name> ...
tpm2x encrypt --with <name> ...
tpm2x decrypt --with <name> ...
tpm2x derive --with <name> ...
tpm2x export --with <name> ...
tpm2x import ...
tpm2x ssh-add --with <name> ...
```

Examples:

```bash
tpm2x sign --with wgw --input msg.txt
tpm2x verify --with wgwprf --input msg.txt --signature msg.sig
tpm2x encrypt --with wgwseed --input secret.txt --output secret.bin
tpm2x derive --with wgwprf --length 32
tpm2x export --with wgw --kind public-key --output wgw.spki.der
tpm2x ssh-add --with wgwprf
```

`--with` is the canonical selector for all identity-bound operations.

### 3. `auto` remains a real mode choice at identity creation time

`auto` remains supported as an identity creation mode.

Its job is to resolve the identity to exactly one backing mode using inspection/probing logic.

`auto` resolution must consider all of the following:

- requested algorithm
- requested use set
- TPM-native support for the requested algorithm and each requested native action
- TPM availability for PRF backing
- TPM availability for seed backing

`auto` must obey these rules:

- it chooses one mode for the whole identity
- it must never resolve to a mode that cannot satisfy the full requested use set
- it must not silently drop requested uses
- it must not create hybrid identities
- if the requested use set can only be satisfied by a different identity in a different mode, the user must create another identity

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
- `derive`
- `ssh`

`ssh-agent` the use bit is renamed to `ssh`.

`--use all` remains supported, but its expansion depends on the resolved mode and native capability matrix.

#### 5.1 Native use rules

A `native` identity may declare only the native-compatible uses that are actually supported for its algorithm on the current TPM.

The intended native surface is:

- `sign`
- `verify`
- `encrypt`
- `decrypt`
- `ssh`

with these constraints:

- `derive` is never allowed on `native`
- `ssh-add` is never allowed on `native`
- `ssh` as a use bit is allowed on `native` as a future-facing intent bit for helper-based flows that use `sign` rather than daemon agents
- `encrypt` and `decrypt` are allowed only if inspection says the TPM natively supports them for that algorithm
- `all` expands only to the native-compatible uses that are actually available for that algorithm on that TPM

So `native` support is both mode-dependent and capability-dependent.

#### 5.2 PRF use rules

A `prf` identity supports the same high-level operational surface as `seed`, except for export restrictions described below.

Allowed PRF uses are:

- `sign`
- `verify`
- `encrypt`
- `decrypt`
- `derive`
- `ssh`

`--use all` on `prf` expands to all of the above.

#### 5.3 Seed use rules

A `seed` identity supports:

- `sign`
- `verify`
- `encrypt`
- `decrypt`
- `derive`
- `ssh`

`--use all` on `seed` expands to all of the above.

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

- derive
- secret-key export
- `ssh-add`

If the TPM does not support a requested native action for the chosen algorithm, identity creation in `native` must fail, and `auto` must not resolve to `native` for that use set.

#### 6.2 PRF behavior

A `prf` identity performs operations by resolving the identity plus derivation inputs, invoking the TPM-backed PRF flow, and using the resulting child material for the requested operation.

PRF supports:

- sign
- verify
- encrypt
- decrypt
- derive
- `ssh-add`
- public-key export

PRF export rules:

- public-key export is allowed
- secret-key export is not allowed

The exported public key for a PRF identity is the public key of the resolved child key for the effective derivation inputs, not a public key of the PRF root itself.

#### 6.3 Seed behavior

A `seed` identity performs operations by resolving the identity plus derivation inputs, unsealing the seed, deriving child material in software, and using that child material for the requested operation.

Seed supports:

- sign
- verify
- encrypt
- decrypt
- derive
- `ssh-add`
- public-key export
- secret-key export

Seed export rules:

- public-key export is allowed
- secret-key export is allowed
- secret-bearing export remains a high-friction path

### 7. `ssh-agent` the command is renamed to `ssh-add`

The command name becomes:

```bash
tpm2x ssh-add --with <name>
```

This command supports only:

- `prf`
- `seed`

It must reject `native` identities.

This is separate from `use=ssh`.

Rationale:

- `ssh-add` is the user action the command performs
- `use=ssh` describes intended identity usage, not daemon integration
- native identities may still declare `ssh` use for future helper-driven flows that rely on `sign` and avoid daemon agents entirely

Examples:

```bash
# allowed
tpm2x ssh-add --with wgwprf
tpm2x ssh-add --with wgwseed

# rejected
tpm2x ssh-add --with wgw
```

### 8. Derivation input flags are renamed and unified

The user-facing derivation input flags are:

- `--org` instead of `--namespace`
- `--purpose` stays `--purpose`
- `--label` instead of `--context`

`--label` replaces the old repeatable context field input and is repeatable.

The public CLI shape is:

- `--org <string>`
- `--purpose <string>`
- `--label <key=value>` repeated as needed

The old free-form `--label` meaning is removed from the public CLI to avoid a naming collision with the new repeatable `--label key=value` input.

Examples:

```bash
tpm2x identity prf wgwprf \
  --algorithm p256 \
  --use all \
  --org com.example \
  --purpose user1 \
  --label tenant=alpha \
  --label role=git

tpm2x sign --with wgwprf --input msg.txt

tpm2x sign \
  --with wgwprf \
  --org com.example \
  --purpose user2 \
  --label tenant=beta \
  --input msg.txt
```

### 9. Derivation input precedence rules

All operational commands that use an identity accept `--org`, `--purpose`, and repeated `--label`.

For `prf` and `seed`:

- identity creation may store default derivation inputs
- command-line derivation inputs override identity defaults
- omitted derivation inputs fall back to the identity defaults
- the effective derivation input set is what determines the derived child material for sign/verify/encrypt/decrypt/export/ssh-add/derive

For `native`:

- `--org` is invalid
- `--purpose` is invalid
- `--label` is invalid
- passing any of them with a `native` identity is an error

This applies both when the identity was explicitly created as `native` and when it resolved to `native` through `auto`.

### 10. `derive` becomes the explicit surfaced form of the PRF/seed internal flow

`derive` works only with:

- `prf`
- `seed`

It does not work with:

- `native`

`derive` is not a special second derivation model. It simply exposes the same derivation pipeline that powers PRF/seed-backed operational commands.

That means:

- no extra HKDF layer beyond the mode’s normal derivation flow
- no double expansion
- the bytes returned by `derive` are the direct surfaced output of the effective PRF/seed derivation path

More specifically:

- for `prf`, the command must return the single derived output of the PRF pipeline for the effective derivation spec
- for `seed`, the command must return the single derived output of the seed HKDF pipeline for the effective derivation spec

`derive` is therefore the third-party integration escape hatch for PRF/seed identities.

Example:

```bash
tpm2x derive \
  --with wgwprf \
  --org com.example \
  --purpose session \
  --label tenant=alpha \
  --length 32
```

### 11. Export rules are unified at the command level and differentiated by mode

`export` remains a shared command:

```bash
tpm2x export --with <name> --kind <kind> [other options]
```

Mode-specific export policy:

| Mode   | Public key export | Secret key export |
|--------|-------------------|-------------------|
| native | yes               | no                |
| prf    | yes               | no                |
| seed   | yes               | yes               |

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

### 12. Command/mode matrix

#### 12.1 Operational command matrix

| Command    | native | prf | seed |
|------------|:------:|:---:|:----:|
| sign       | yes    | yes | yes  |
| verify     | yes    | yes | yes  |
| encrypt    | yes*   | yes | yes  |
| decrypt    | yes*   | yes | yes  |
| derive     | no     | yes | yes  |
| export public key | yes | yes | yes |
| export secret key | no | no | yes |
| ssh-add    | no     | yes | yes  |

`yes*` means subject to per-algorithm native TPM capability.

#### 12.2 Use matrix

| Use      | native | prf | seed |
|----------|:------:|:---:|:----:|
| sign     | yes*   | yes | yes  |
| verify   | yes*   | yes | yes  |
| encrypt  | yes*   | yes | yes  |
| decrypt  | yes*   | yes | yes  |
| derive   | no     | yes | yes  |
| ssh      | yes    | yes | yes  |

Again, `yes*` means subject to native TPM support for the chosen algorithm.

### 13. Example flows

#### 13.1 Native signing and public export

```bash
tpm2x identity native wgw --algorithm p256 --use sign --use verify

tpm2x sign --with wgw --input msg.txt
tpm2x verify --with wgw --input msg.txt --signature msg.sig

tpm2x export --with wgw --kind public-key --output wgw.spki.der
```

#### 13.2 Native identity rejected for derivation flags

```bash
tpm2x sign --with wgw --org com.example --input msg.txt
# error: --org/--purpose/--label are invalid for native identities
```

#### 13.3 Auto chooses a native identity when native capability is sufficient

```bash
tpm2x identity auto wgw --algorithm p256 --use sign --use verify
```

If native sign/verify exists for `p256`, `auto` may resolve to `native`.

#### 13.4 Auto does not create a hybrid identity

```bash
tpm2x identity auto mixed --algorithm p256 --use sign --use verify --use derive
```

This must resolve to exactly one mode that can satisfy the full use set. If no single mode is valid, identity creation fails.

If the operator wants native sign/verify plus separate derived workflows, they must create separate identities.

#### 13.5 PRF identity with default derivation inputs

```bash
tpm2x identity prf wgwprf \
  --algorithm p256 \
  --use all \
  --org com.example \
  --purpose git \
  --label tenant=alpha

tpm2x sign --with wgwprf --input msg.txt
tpm2x verify --with wgwprf --input msg.txt --signature msg.sig
tpm2x encrypt --with wgwprf --input secret.txt --output secret.bin
tpm2x decrypt --with wgwprf --input secret.bin --output secret.txt
tpm2x export --with wgwprf --kind public-key --output wgwprf.spki.der
tpm2x ssh-add --with wgwprf
```

#### 13.6 PRF per-command override

```bash
tpm2x sign \
  --with wgwprf \
  --purpose deploy \
  --label tenant=beta \
  --input msg.txt
```

The command-level derivation inputs override the identity defaults.

#### 13.7 Seed identity with exportable secret material

```bash
tpm2x identity seed wgwseed \
  --algorithm ed25519 \
  --use all \
  --org com.example \
  --purpose personal

tpm2x sign --with wgwseed --input msg.txt
tpm2x export --with wgwseed --kind public-key --output wgwseed.pub
tpm2x export --with wgwseed --kind secret-key --output wgwseed.sec --confirm --reason backup
tpm2x ssh-add --with wgwseed
```

## Consequences

- Good, because the CLI becomes mode-consistent without flattening away the meaningful difference between TPM-native, TPM-PRF, and sealed-seed backing.
- Good, because `prf` and `seed` now expose the same high-level verbs even though their internal derivation sources remain different.
- Good, because native capability becomes explicit and inspectable per algorithm and action instead of being hidden behind a coarse mode-level assumption.
- Good, because `auto` remains useful but is constrained to honest, single-mode resolution.
- Good, because `--with <identity>` gives a stable, reusable selector across all operational commands.
- Good, because `ssh-add` the command is separated from `use=ssh`, which leaves room for future native helper flows without daemon-agent requirements.
- Good, because derivation-input overrides now work uniformly for `prf` and `seed` and are rejected clearly for `native`.
- Good, because `derive` becomes a first-class surface of the same PRF/seed derivation path rather than a special unrelated command.
- Bad, because a single conceptual user may need multiple identities when native TPM capability does not cover all desired uses for one algorithm.
- Bad, because `prf` public-key export must be understood as export of a derived child key, not export of the PRF root, which requires clearer help text and examples.
- Bad, because renaming flags and commands (`setup` → `identity`, `ssh-agent` → `ssh-add`, `--namespace` → `--org`, `--context` → `--label`) is a breaking CLI change.
- Bad, because allowing `use=ssh` on native while rejecting `ssh-add` on native introduces an intentional distinction that must be documented carefully.

## Alternatives Considered

- Keep the current mode-specific matrix and only rename commands: rejected because it preserves the main design problem — the public CLI stays asymmetrical even though `prf` and `seed` should expose the same high-level verbs.
- Collapse `prf` and `seed` into one derived mode: rejected because they are fundamentally different backing mechanisms and that difference matters for security properties, export behavior, and implementation.
- Keep `ssh-agent` as both command name and use name: rejected because it ties a user intent bit to a specific daemon-based transport mechanism and blocks cleaner native-helper flows.
- Keep the old derivation flag names: rejected because `--org` / `--purpose` / `--label` is the desired public vocabulary for this redesign.

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
