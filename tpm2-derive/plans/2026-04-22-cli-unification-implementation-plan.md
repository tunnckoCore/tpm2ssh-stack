# CLI unification implementation plan

Implements the accepted ADR in `decisions/2026-04-22-unify-cli-surface-across-native-prf-seed.md`.

This is a **prototype-phase hard-cut plan**.

That means:

- no CLI compatibility shims
- no deprecated aliases
- no attempt to preserve old command grammar
- no attempt to preserve old internal `profile` naming
- no attempt to preserve old on-disk profile schema as-is
- rename `profile` to `identity` through the codebase and storage model

The plan is written so multiple parallel agents can work on it.

---

# Implementation constraints

## Hard rules

- The public CLI must use `identity` and `--with`.
- Internal types, modules, state naming, and persisted schema should also move from `profile` to `identity` unless there is a very strong technical reason not to.
- The command surface is a hard cut to the ADR design.
- `ssh-agent` the command becomes `ssh-add`.
- `ssh-agent` the use bit becomes `ssh`.
- `export-secret` is a real use bit and must gate `export --kind secret-key` and `export --kind keypair`.
- `--org`, `--purpose`, `--context` are the public derivation-input flags.
- `native` rejects derivation-input flags.
- `prf` and `seed` share the same top-level command surface.
- `derive` must not do double HKDF expansion.
- `auto` must choose exactly one mode or fail.

## Explicit non-goals

- Renaming the binary from `tpm2-derive` to `tpm2x` in this implementation.
- Keeping old `setup`, `--profile`, `--namespace`, or `ssh agent add` spellings alive.
- Preserving the current persisted profile JSON layout unchanged.
- Preserving the current command-specific derived-key mismatch if the ADR requires unified identity semantics.

---

# High-level delivery strategy

The work is split into **7 workstreams**.

Some workstreams can run in parallel. Some have hard dependencies.

## Dependency order

- **WS1 CLI surface** and **WS2 model/schema rename** can start immediately.
- **WS3 capability/auto** can start immediately.
- **WS4 derivation merge + PRF finalization** depends on WS2.
- **WS5 operation parity (sign/verify/export/ssh-add)** depends on WS2 + WS4.
- **WS6 native matrix and honest native support** depends on WS3 and partially on current backend audit.
- **WS7 tests/docs cleanup** runs continuously but finishes last.

---

# Workstream checklist

## WS1 — CLI surface rewrite

**Goal:** hard-cut the CLI to the new grammar from the ADR.

### Ownership

- best for 1 agent focused on `clap` structures and CLI dispatch

### Files

- `src/cli/args.rs`
- `src/cli/mod.rs`
- `src/cli/render.rs`
- `src/bin/tpm2-derive.rs`

### Checklist

- [ ] Replace `setup` with `identity`
- [ ] Replace nested `ssh agent add` with flat `ssh-add`
- [ ] Replace `--profile` / `--from-profile` with `--with`
- [ ] Replace `--namespace` with `--org`
- [ ] Remove public `--label`
- [ ] Keep `--purpose`
- [ ] Keep repeated `--context key=value`
- [ ] Add `--mode <auto|native|prf|seed>` to identity creation
- [ ] Make `--use` required on identity creation
- [ ] Add `export-secret` to CLI use enum
- [ ] Add `all` handling at the CLI level only if it cleanly delegates to mode-aware expansion later
- [ ] Apply derivation override flags to all identity-bound commands:
  - [ ] `sign`
  - [ ] `verify`
  - [ ] `encrypt`
  - [ ] `decrypt`
  - [ ] `derive`
  - [ ] `export`
  - [ ] `ssh-add`
- [ ] Remove derive-specific ssh-agent flags:
  - [ ] `--ssh-agent-add`
  - [ ] `--ssh-agent-comment`
  - [ ] `--ssh-agent-socket`
- [ ] Update help text and examples to the ADR vocabulary
- [ ] Update command paths / renderer expectations for `identity` and `ssh-add`

### Deliverables

- CLI parser only accepts the new grammar
- command dispatch paths line up with the ADR

### Acceptance checks

- [ ] `tpm2-derive identity wgw --mode native --algorithm p256 --use sign --use verify` parses
- [ ] `tpm2-derive sign --with wgw --input msg.txt` parses
- [ ] `tpm2-derive ssh-add --with wgwprf` parses
- [ ] `tpm2-derive derive --with wgwprf --org com.example --purpose session --context tenant=alpha --length 32` parses
- [ ] old `setup` no longer parses
- [ ] old `ssh agent add` no longer parses
- [ ] old `--namespace` no longer parses

---

## WS2 — Rename internal model from profile to identity

**Goal:** align the internal codebase with the ADR instead of keeping `profile` as a lingering abstraction.

### Ownership

- best for 1 agent doing broad refactor / rename work

### Files

- `src/model/profile.rs`
- `src/model/mod.rs`
- `src/model/command.rs`
- `src/model/core.rs`
- `src/model/state.rs`
- `src/ops.rs`
- `src/cli/mod.rs`
- all `src/ops/*.rs`
- tests touching profile naming

### Checklist

- [ ] Rename `Profile` to `Identity`
- [ ] Rename `ModeResolution` references where needed to identity-oriented naming
- [ ] Rename `SetupRequest` / `SetupResult` to identity-creation naming
- [ ] Rename command request fields from `profile` to `identity` or `with` where appropriate
- [ ] Rename persisted state helpers from profile-oriented naming to identity-oriented naming
- [ ] Rename storage path helpers from `profile_path` to `identity_path`
- [ ] Rename profile-loading APIs to identity-loading APIs
- [ ] Rename comments/docs/tests to use `identity`
- [ ] Remove leftover public/internal “setup profile” wording

### Schema checklist

- [ ] Add typed identity defaults for:
  - [ ] `org`
  - [ ] `purpose`
  - [ ] `context`
- [ ] Add `export-secret` to persisted uses
- [ ] Remove persisted policy assumptions that contradict the new mode/use matrix
- [ ] Decide whether old export-policy struct remains, is reduced, or is deleted
- [ ] Bump schema version if schema remains versioned

### Deliverables

- internal code refers to identities, not profiles
- request/response models are identity-oriented

### Acceptance checks

- [ ] no public-facing `profile` naming remains in CLI args/help/output where it should be `identity`
- [ ] core model types and request objects are identity-oriented
- [ ] stored identity data includes derivation defaults

---

## WS3 — Capability matrix and auto-resolution rewrite

**Goal:** make `inspect` and `auto` truthful and mode-complete.

### Ownership

- best for 1 agent focused on backend probe / recommendation logic

### Files

- `src/model/capability.rs`
- `src/backend.rs`
- `src/backend/recommend.rs`
- `src/backend/subprocess.rs`
- `src/backend/parser.rs`
- `src/backend/tss_esapi.rs`
- `src/ops.rs`

### Checklist

- [ ] Replace the coarse native capability summary with a per-algorithm action matrix
- [ ] Represent native support separately for:
  - [ ] sign
  - [ ] verify
  - [ ] encrypt
  - [ ] decrypt
- [ ] Represent PRF availability explicitly as “actual PRF support on the TPM”
- [ ] Represent seed availability explicitly
- [ ] Update `inspect` rendering/output to surface the matrix
- [ ] Rewrite `auto` mode resolution to:
  - [ ] try `native`
  - [ ] then `prf`
  - [ ] then `seed`
  - [ ] evaluate the full requested use set against one mode at a time
  - [ ] never create a hybrid identity
  - [ ] never silently switch away from an explicit mode
  - [ ] fail with a reason when no one mode satisfies the request
- [ ] Move `--use all` expansion to a point where the resolved mode + capability matrix are known

### Deliverables

- honest `inspect`
- honest `auto`
- mode-aware `use=all`

### Acceptance checks

- [ ] `inspect` can tell whether native encrypt/decrypt exists for a given algorithm
- [ ] explicit `--mode prf` fails if PRF backing is unavailable even if seed is available
- [ ] `auto` chooses one mode only
- [ ] `auto` fails instead of silently downgrading or switching explicit mode requests

---

## WS4 — Shared derivation resolution and PRF finalization fix

**Goal:** centralize derivation-default merging and remove PRF double expansion.

### Ownership

- best for 1 agent focused on crypto/derivation plumbing

### Files

- `src/model/command.rs`
- `src/crypto/mod.rs`
- `src/ops/prf.rs`
- `src/ops/derive.rs`
- `src/ops/encrypt.rs`
- `src/ops/keygen.rs`
- `src/ops/ssh.rs`
- `src/ops.rs`

### Checklist

- [ ] Introduce one shared helper to compute effective derivation inputs
- [ ] Implement ADR merge rules exactly:
  - [ ] `org` command override wins
  - [ ] `purpose` command override wins
  - [ ] `context` merges by key
  - [ ] new key appends
  - [ ] same key replaces default value
  - [ ] repeated same command key → last wins
  - [ ] native rejects all derivation overrides
- [ ] Route all identity-bound PRF/seed commands through the same effective-input helper
- [ ] Audit PRF call sites for double-expansion behavior
- [ ] Expose one PRF helper that returns final derived bytes once
- [ ] Remove second HKDF expansion from current PRF consumers

### Deliverables

- one derivation merge implementation
- one PRF finalization path

### Acceptance checks

- [ ] `derive` PRF output is finalized exactly once
- [ ] `encrypt` PRF path no longer re-derives already-finalized output
- [ ] `keygen` PRF path no longer re-derives already-finalized output
- [ ] native rejects `--org`, `--purpose`, and `--context`
- [ ] context merge semantics behave exactly as described in the ADR

---

## WS5 — Operation parity across PRF and seed

**Goal:** make PRF and seed expose the same high-level operational surface.

### Ownership

- best for 1–2 agents if split by sub-area:
  - sign/verify/export
  - ssh-add + key material alignment

### Files

- `src/cli/mod.rs`
- `src/ops.rs`
- `src/ops/derive.rs`
- `src/ops/encrypt.rs`
- `src/ops/keygen.rs`
- `src/ops/ssh.rs`
- `src/ops/seed.rs`
- `src/ops/prf.rs`
- likely new `src/ops/sign.rs`
- likely new `src/ops/verify.rs`

### Checklist

#### Sign/verify
- [ ] Extract sign logic out of `src/cli/mod.rs`
- [ ] Extract verify logic out of `src/cli/mod.rs`
- [ ] Implement PRF sign
- [ ] Implement PRF verify
- [ ] Keep seed sign/verify working through the shared derivation helper
- [ ] Keep native sign/verify working

#### Export
- [ ] Expand export kinds to:
  - [ ] `public-key`
  - [ ] `secret-key`
  - [ ] `keypair`
- [ ] Keep or consciously isolate `recovery-bundle` if still needed for `import`
- [ ] Implement PRF public-key export for effective derived identity key
- [ ] Implement PRF secret-key export gated on `export-secret`
- [ ] Implement PRF keypair export gated on `export-secret`
- [ ] Implement seed secret-key export gated on `export-secret`
- [ ] Implement seed keypair export gated on `export-secret`
- [ ] Keep native export limited to public-key

#### Secret-material policy
- [ ] Enforce `export-secret` for `secret-key`
- [ ] Enforce `export-secret` for `keypair`
- [ ] Enforce `--confirm`
- [ ] Enforce `--reason`
- [ ] Ensure `keygen` cannot bypass this policy
- [ ] Decide whether to remove `keygen`, hide it, or make it a thin alias over export logic

#### SSH
- [ ] Rename command flow to `ssh-add`
- [ ] Implement PRF `ssh-add`
- [ ] Keep seed `ssh-add`
- [ ] Keep native rejected for `ssh-add`
- [ ] Make sure `use=ssh` is separate from the `ssh-add` command behavior

### Important semantic check

The ADR implies identity-level consistency. For the same effective identity inputs, confirm which operations must share the same asymmetric key material:

- [ ] sign
- [ ] verify
- [ ] export public-key
- [ ] export secret-key / keypair
- [ ] ssh-add

If one of these intentionally uses a different derivation branch, that must be made explicit in code comments/tests. Otherwise they should be unified.

### Deliverables

- PRF and seed support the same top-level commands
- secret-bearing export is policy-gated
- ssh-add works for PRF and seed

### Acceptance checks

- [ ] PRF sign/verify round-trip works
- [ ] seed sign/verify round-trip still works
- [ ] PRF public-key export works
- [ ] PRF secret-key and keypair export require `export-secret`
- [ ] seed secret-key and keypair export require `export-secret`
- [ ] native secret export fails
- [ ] PRF ssh-add works
- [ ] native ssh-add fails

---

## WS6 — Native action support audit and implementation

**Goal:** make native support truthful, and add native encrypt/decrypt only if actually implementable now.

### Ownership

- best for 1 agent focused on TPM-native backend details

### Files

- `src/ops/native.rs`
- `src/ops/native/subprocess.rs`
- `src/ops.rs`
- `src/backend/recommend.rs`
- `src/backend/subprocess.rs`

### Checklist

- [ ] Audit current native support assumptions
- [ ] Confirm exactly what native actions are truly executable today
- [ ] If native encrypt/decrypt is implementable:
  - [ ] implement native encrypt
  - [ ] implement native decrypt
  - [ ] expose capability matrix truthfully
- [ ] If native encrypt/decrypt is not implementable in this prototype slice:
  - [ ] keep capability matrix false
  - [ ] keep explicit failures truthful
  - [ ] ensure `use=all` excludes unsupported native actions
- [ ] Keep native public-key export working
- [ ] Keep native secret export forbidden

### Deliverables

- truthful native matrix
- native behavior aligned with what the backend can actually do

### Acceptance checks

- [ ] native never advertises unsupported actions
- [ ] if native encrypt/decrypt is implemented, round-trip tests exist
- [ ] if native encrypt/decrypt is not implemented, inspect/auto/errors all reflect that cleanly

---

## WS7 — Test matrix and final cleanup

**Goal:** make the refactor safe for parallel work and future follow-up.

### Ownership

- can be shared across all agents, but one final owner should normalize and finish

### Files

- `src/cli/args.rs`
- `src/cli/mod.rs`
- `src/model/profile.rs` (or renamed identity file)
- `src/model/core.rs`
- `src/model/capability.rs`
- `src/ops/enforcement.rs`
- `src/ops/derive.rs`
- `src/ops/encrypt.rs`
- `src/ops/keygen.rs`
- `src/ops/ssh.rs`
- `src/ops.rs`
- new sign/verify ops tests
- `README.md`

### Checklist

#### Parsing and CLI tests
- [ ] new identity grammar tests
- [ ] `--with` tests
- [ ] `ssh-add` tests
- [ ] `--org` / `--purpose` / `--context` tests
- [ ] rejection tests for removed old grammar

#### Model/schema tests
- [ ] identity schema round-trip tests
- [ ] use-bit serialization tests
- [ ] derivation-default persistence tests

#### Capability/auto tests
- [ ] inspect matrix tests
- [ ] explicit mode no-fallback tests
- [ ] `auto` ordering tests
- [ ] `use=all` expansion tests

#### Derivation merge tests
- [ ] defaults-only case
- [ ] org override case
- [ ] purpose override case
- [ ] context new-key append case
- [ ] context same-key replace case
- [ ] repeated same command key last-wins case
- [ ] native derivation-flag rejection case

#### Operation tests
- [ ] seed sign/verify tests
- [ ] PRF sign/verify tests
- [ ] seed encrypt/decrypt tests
- [ ] PRF encrypt/decrypt tests
- [ ] derive no-double-expansion PRF regression tests
- [ ] export public-key tests for native/prf/seed
- [ ] export secret-key tests for prf/seed
- [ ] export keypair tests for prf/seed
- [ ] export-secret gating tests
- [ ] ssh-add seed tests
- [ ] ssh-add PRF tests
- [ ] ssh-add native rejection tests

#### Output/docs cleanup
- [ ] update README examples
- [ ] update CLI help examples
- [ ] remove lingering public `profile` wording
- [ ] remove lingering public `setup` wording

### Deliverables

- end-to-end test coverage for the new contract
- cleaned help/docs consistent with the ADR

---

# Parallel-agent task breakdown

Use this if multiple agents are working concurrently.

## Agent A — CLI + model rename

### Owns
- WS1
- WS2

### Must deliver
- CLI grammar rewrite
- internal rename from profile → identity
- new request/schema surface

### Cannot finalize without
- WS3 decisions about capability matrix shape
- WS4 decisions about derivation override structure

---

## Agent B — capability + auto + native audit

### Owns
- WS3
- WS6

### Must deliver
- inspect matrix
- truthful auto-resolution
- native support truthfulness

### Cannot finalize without
- final use enum from WS2

---

## Agent C — derivation + PRF finalization + operation parity

### Owns
- WS4
- WS5

### Must deliver
- one derivation merge helper
- no double PRF expansion
- PRF sign/verify/export/ssh-add parity
- export-secret gating

### Cannot finalize without
- request/schema work from WS2
- capability model expectations from WS3

---

## Agent D — tests + cleanup

### Owns
- WS7

### Must deliver
- test matrix completion
- docs/help cleanup
- final consistency pass

### Should start after
- WS1/WS2 interfaces are stable enough to test against

---

# Final integration checklist

Before calling the refactor done:

- [ ] public CLI uses `identity` and `--with`
- [ ] internal code no longer treats `profile` as the main public abstraction
- [ ] `inspect` shows a truthful capability matrix
- [ ] `auto` chooses exactly one valid mode or fails
- [ ] `native` rejects derivation-input flags
- [ ] `prf` and `seed` support the same top-level command surface
- [ ] `derive` does not double-expand PRF output
- [ ] `export-secret` gates secret-bearing export
- [ ] `keygen` cannot bypass secret-export policy
- [ ] `ssh-add` works for PRF and seed, and rejects native
- [ ] native support advertised by inspect matches real backend execution
- [ ] README/help/examples match the accepted ADR

# Suggested commit slicing

1. `refactor(cli): hard-cut grammar to identity/with/org/ssh-add`
2. `refactor(model): rename profile to identity and persist derivation defaults`
3. `refactor(capabilities): add truthful inspect matrix and auto resolution`
4. `refactor(policy): implement new mode/use/export-secret rules`
5. `refactor(derivation): centralize effective-input merge and fix prf finalization`
6. `feat(prf): add sign verify export ssh-add parity`
7. `feat(export): add public-key secret-key keypair kinds and enforce export-secret`
8. `feat(native): implement or truthfully defer native encrypt/decrypt`
9. `test(docs): finish regression suite and cleanup`
