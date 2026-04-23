# Security review follow-up plan

Scope for this follow-up wave:

- fix only the concrete outcomes accepted from the 2026-04-23 Mythos red-team review
- keep work repo-specific; no generic host-hardening advice
- preserve the accepted `refactor/hardening` semantics outside these targeted fixes
- require tests for each production-code change

---

# Follow-up workstreams

## WS1 — ssh-add socket path pinning and ancestor symlink rejection

**Goal:** ensure `ssh-add` cannot validate one socket path and later send a private key to a different socket through ancestor symlink tricks or post-validation swaps.

### Files

- `src/ops/ssh.rs`
- tests as needed

### Checklist

- [x] reject symlinked ancestor path components
- [x] pin and use only the verified socket path
- [x] add regression coverage for ancestor symlink and swap attempts

---

## WS2 — identity name character policy

**Goal:** make identity names accept only `[a-zA-Z0-9_-]` and fail closed before any backend layout logic can interpret path-like or alias-like values.

### Files

- `src/model/identity.rs`
- `src/ops/prf.rs`
- `src/ops/seed.rs`
- `src/ops/native/subprocess.rs`
- tests as needed

### Checklist

- [x] enforce `[a-zA-Z0-9_-]` consistently for identity/profile validators
- [x] add focused rejection tests for `.`, `/`, `\\`, whitespace, and mixed-invalid names

---

## WS3 — strict per-identity object-dir invariants

**Goal:** guarantee computed identity object directories are strict descendants of `objects_dir` before overwrite/delete/rename flows.

### Files

- `src/ops.rs`
- backend paths as needed
- tests as needed

### Checklist

- [x] add a shared strict-child path invariant helper for identity object roots
- [x] apply it to destructive overwrite/delete flows
- [x] add regression coverage proving malformed names cannot touch shared root state

---

## WS4 — recommendation/enforcement truthfulness parity

**Goal:** keep recommendation-layer support checks aligned with the canonical coupled-use contract enforced elsewhere.

### Files

- `src/backend/recommend.rs`
- `src/model/core.rs`
- tests as needed

### Checklist

- [ ] reuse one canonical coupled-use validation path in recommendation logic
- [ ] add negative recommendation tests for verify-only, decrypt-only, and ssh-only requests

---

## WS5 — review artifact cleanup for non-promoted rejected items

**Goal:** remove the explicitly unwanted low-value rejected artifacts from the test/subprocess review output.

### Files

- `.mythos-review/2026-04-23-tests-subprocess/**`

### Checklist

- [ ] delete `R-001-fixed-tool-set-no-shell-injection.md`
- [ ] delete `R-002-env-mutation-not-promoted.md`
- [ ] delete `R-003-port-race-availability-only.md`
- [ ] update any summary docs that still point at those rejected items
