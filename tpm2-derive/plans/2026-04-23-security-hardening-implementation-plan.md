# Security hardening implementation plan

Scope for this plan:

- assume a properly secured host/server
- do **not** spend time on generic host-compromise advice
- recovery/import/recovery-bundle are out of scope and being dropped
- preserve intentional semantics:
  - the same identity/context may intentionally derive the same key across sign/verify/encrypt/decrypt/export/ssh
  - seed/prf may intentionally derive reusable key material for third-party/software use

Primary priorities from the agreed review:

1. **#9 zeroization / secret lifetime**
2. **#10 native persistent handle allocation / native concurrency**
3. **#11 bounded input reads + streaming**

This plan is written for multiple agents working in parallel.

---

# Hardening goals

## Must fix in this wave

- derived secret material must stay in secret/zeroizing containers as long as practical
- native setup and native sign must be safe under concurrency
- native key location must fail closed when durable host state is missing or ambiguous
- large file/stdin inputs must have sane limits now
- large operational paths must move toward streaming instead of full buffering
- every hardening change must ship with tests for the changed behavior
- changed operational paths must be validated against real `tpm2-tools` on `swtpm`, not only mocks/unit fakes

## Also fix in this wave if they naturally fit the same changes

- `ssh-add` should be treated as secret egress, not a loose special case
- `decrypt` should not default to inline plaintext output
- native support should stay truthful when runtime behavior is narrower than use-bit advertising

## Explicit non-goals for this plan

- recovery/import/recovery-bundle redesign
- generic server hardening advice
- changing intentional per-identity derivation semantics across sign/export/ssh

---

# Workstream layout

## Dependency order

- **WS1 native concurrency/correctness** can start immediately.
- **WS2 bounded inputs** can start immediately.
- **WS3 secret-container/zeroization substrate** can start immediately.
- **WS4 streamed sign/verify + encrypt/decrypt** depends on WS2 and partially on WS3.
- **WS5 secret-egress semantics (`ssh-add`, decrypt plaintext policy)** depends on WS3.
- **WS6 regression + real swtpm coverage** runs continuously and finishes last.

---

# WS1 — Native concurrency and correctness

**Priority:** P0

**Goal:** make native setup/sign safe under concurrency and fail closed on ambiguous state.

### Files

- `src/ops.rs`
- `src/ops/sign.rs`
- `src/ops/native/subprocess.rs`

### Checklist

- [x] add a global native persistent-handle allocation lock
- [x] add a per-identity native setup lock
- [x] replace fixed native setup scratch dir with unique temp staging dir
- [x] replace fixed native sign digest/signature artifact paths with unique per-request temp paths
- [x] remove raw persistent-handle fallback when serialized handle state is missing
- [x] add retry/rollback around persistent handle allocation collisions
- [x] add rollback on native setup failure after TPM object persistence but before identity persistence
- [x] add explicit transient cleanup where needed

### Acceptance checks

- [x] parallel native sign for the same identity cannot clobber files or return the wrong signature
- [x] same-name native setup cannot race successfully
- [x] handle allocation is no longer a naked scan-then-use race
- [x] missing serialized handle state causes hard failure, not fallback to arbitrary persistent handle use

---

# WS2 — Bounded input loading

**Priority:** P0

**Goal:** stop unbounded reads immediately and centralize input-size policy.

### Files

- `src/ops/shared.rs`
- `src/cli/mod.rs`
- `src/model/identity.rs`
- `src/ops/sign.rs`
- `src/ops/verify.rs`
- `src/ops/encrypt.rs`

### Checklist

- [x] replace duplicated input-loading helpers with one shared bounded helper
- [x] add bounded identity JSON loading
- [x] add bounded signature-input loading for verify
- [x] add explicit buffered input caps for Ed25519 sign/verify paths
- [x] add explicit buffered caps for any remaining non-streaming encrypt/decrypt paths
- [x] reject oversized stdin with `take(limit + 1)` style bounded reads
- [x] reject oversized files with metadata pre-check where possible

### Initial limits

- [x] identity JSON cap
- [x] verify signature input cap
- [x] buffered Ed25519 message cap
- [x] temporary buffered encrypt/decrypt cap until streaming lands

### Acceptance checks

- [x] no unbounded `read_to_end` / `fs::read` / `read_to_string` remain on large operational paths
- [x] oversize identity JSON is rejected cleanly
- [x] oversize signature input is rejected cleanly
- [x] oversize buffered message/stdin input is rejected cleanly

---

# WS3 — Secret-container and zeroization substrate

**Priority:** P0

**Goal:** keep derived secret material out of ordinary heap/string/json forms as long as possible.

### Files

- `src/ops/shared.rs`
- `src/ops/keygen.rs`
- `src/ops.rs`
- `src/ops/ssh.rs`
- `src/ops/encrypt.rs`
- `src/ops/seed.rs`
- `src/ops/prf.rs`

### Checklist

- [x] make derived-secret helpers return secret/zeroizing containers instead of plain `Vec<u8>`
- [x] eliminate `.expose_secret().to_vec()` fan-out where possible
- [x] wrap unavoidable temporary secret buffers in zeroizing containers
- [x] zeroize temporary key/scalar/symmetric-key buffers after use
- [x] minimize secret-bearing `String` creation in export and ssh-add flows
- [x] audit temp-file secret lifetime and shorten it where practical

### Acceptance checks

- [x] core derived-key helpers no longer return plain `Vec<u8>`
- [x] explicit `zeroize` usage appears in real secret paths
- [x] export and ssh-add no longer create unnecessary duplicate plaintext copies of private material

---

# WS4 — Streaming for large operational paths

**Priority:** P1

**Goal:** move large-message operations away from full buffering.

### Files

- `src/ops/shared.rs`
- `src/ops/sign.rs`
- `src/ops/verify.rs`
- `src/ops/encrypt.rs`
- `src/cli/mod.rs`

### Checklist

- [x] add streaming SHA-256 hashing helper for native / p256 / secp256k1 sign/verify
- [x] switch native sign to stream-hash input before TPM signing
- [x] switch native verify to stream-hash input before TPM verification
- [x] switch p256/secp256k1 sign/verify to prehash-based APIs
- [x] keep Ed25519 buffered but capped
- [x] redesign encrypt/decrypt around chunked streaming reader->writer APIs
- [x] remove encrypt/decrypt hex encode -> decode round-trips for file output
- [x] require `--output` or equivalent for large non-inline payloads

### Acceptance checks

- [x] native/p256/secp256k1 sign/verify no longer need full-message buffering
- [x] encrypt/decrypt file paths do not materialize giant hex strings in memory
- [x] large payloads work through streaming paths without inline JSON/plaintext dumps

---

# WS5 — Secret-egress semantics and plaintext policy

**Priority:** P1

**Goal:** treat real secret egress consistently.

### Files

- `src/ops/ssh.rs`
- `src/ops.rs`
- `src/model/command.rs`
- `src/cli/mod.rs`
- `src/cli/render.rs`
- `src/model/capability.rs`
- `src/backend/recommend.rs`

### Checklist

- [x] classify `ssh-add` as secret egress and gate it accordingly
- [x] decide whether `ssh-add` requires `use=export-secret` or a dedicated equivalent policy bit
- [x] add confirmation/reason friction for `ssh-add` if it remains a secret-egress path
- [x] stop `decrypt` from defaulting to inline plaintext output
- [x] require explicit opt-in for stdout/plaintext decrypt output, or require `--output`
- [x] make native `ssh` / inspect / `use=all` behavior truthful with actual runtime behavior

### Acceptance checks

- [x] `ssh-add` is no looser than other secret-bearing egress paths
- [x] decrypt does not emit plaintext inline by default
- [x] inspect/use-bit advertising matches actual runtime support semantics

---

# WS6 — Tests, regressions, and real swtpm validation

**Priority:** P1

**Goal:** lock the hardening in with tests for every changed path, and require real `swtpm` validation for changed operational behavior rather than mock-only coverage.

### Files

- `tests/real_tpm_cli.rs`
- `tests/support/mod.rs`
- targeted unit tests in `src/ops.rs`, `src/ops/sign.rs`, `src/ops/verify.rs`, `src/ops/shared.rs`, `src/model/identity.rs`

### Checklist

- [x] add regression test for parallel native sign same identity
- [x] add regression test for repeated/concurrent native setup
- [x] add regression test for missing serialized native handle state -> hard failure
- [x] add oversize identity JSON rejection tests
- [x] add oversize signature input rejection tests
- [x] add oversize buffered message/stdin rejection tests
- [x] add real swtpm tests for native create/sign/verify/export after concurrency changes
- [x] add real swtpm tests for seed/prf large operational paths after streaming changes
- [x] add tests for ssh-add policy gating
- [x] add tests for decrypt plaintext policy

### Acceptance checks

- [x] every changed file/path has regression coverage for the exact hardening behavior it introduces
- [x] no hardening change is considered done with mock-only coverage if the changed path can be exercised against real `tpm2-tools`
- [x] `cargo test` passes
- [x] `cargo build` passes
- [x] `cargo check` passes
- [x] `nix shell nixpkgs#swtpm nixpkgs#tpm2-tools nixpkgs#openssh -c cargo test --features real-tpm-tests --test real_tpm_cli -- --nocapture` passes

---

# Parallel agent assignment

## Agent 1 — WS1 native concurrency/correctness

- own `src/ops.rs`
- own `src/ops/sign.rs`
- own `src/ops/native/subprocess.rs`

## Agent 2 — WS2 bounded inputs

- own `src/ops/shared.rs`
- own `src/cli/mod.rs`
- own `src/model/identity.rs`
- coordinate with Agent 4 for streaming follow-through

## Agent 3 — WS3 zeroization substrate

- own `src/ops/shared.rs`
- own `src/ops/keygen.rs`
- own `src/ops.rs`
- own `src/ops/ssh.rs`
- coordinate with Agent 5 for tests

## Agent 4 — WS4 streaming

- own `src/ops/shared.rs`
- own `src/ops/sign.rs`
- own `src/ops/verify.rs`
- own `src/ops/encrypt.rs`
- own `src/cli/mod.rs`

## Agent 5 — WS5/WS6 policy + regression coverage

- own `src/ops/ssh.rs`
- own `src/model/command.rs`
- own `src/cli/render.rs`
- own `src/model/capability.rs`
- own `src/backend/recommend.rs`
- own `tests/real_tpm_cli.rs`
- own `tests/support/mod.rs`

---

# Merge order

1. **WS1 native concurrency/correctness**
2. **WS2 bounded inputs**
3. **WS3 zeroization substrate**
4. **WS5 secret-egress semantics / plaintext policy**
5. **WS4 streaming**
6. **WS6 final regression + real swtpm validation**

---

# Required verification commands

Every agent working this plan should know and use these commands.

## Default repo validation

Run from `tpm2-derive/`:

```bash
cargo fmt
cargo build
cargo check
cargo test
```

## Real swtpm validation

Run from `tpm2-derive/`:

```bash
nix shell nixpkgs#swtpm nixpkgs#tpm2-tools nixpkgs#openssh -c cargo test --features real-tpm-tests --test real_tpm_cli -- --nocapture
```

## Rule

- If a changed path can be exercised by the real swtpm suite, the agent must run the real swtpm command before calling the work done.
- Mock/unit-only validation is not enough for changed operational TPM paths.

---

# Exit criteria for the hardening wave

- [x] #9 zeroization/secret lifetime is materially improved in real secret paths
- [x] #10 native handle allocation/setup/sign concurrency issues are fixed
- [x] #11 unbounded reads are removed or bounded, with streaming added for large-path operations
- [x] secret-egress behavior is consistent and explicit
- [x] every implemented hardening change has tests
- [x] changed operational paths are validated with real `tpm2-tools` on `swtpm`, not just mocks
- [x] real swtpm integration coverage validates the hardened paths
