# Hotspot Ranking

Scope-ranked from `rank-hotspots.ts` plus manual trust-boundary review.

| Curated Priority | Raw Score | Path / Component | Risk Signals | Why It Matters | Assigned Agent |
|------------------|-----------|------------------|--------------|----------------|----------------|
| 5 | 14 | `src/ops/ssh.rs` | secret-bearing key export, local IPC boundary, explicit socket validation, external `ssh-add` invocation | Only scoped path that intentionally releases private key material to another process; path trust mistakes can redirect the key | `segment-hunter-01` |
| 4 | 9 | `src/ops/sign.rs` | native TPM subprocess flow, per-request temp workspaces, output formatting/persistence | Signs attacker-supplied data and stages native artifacts; mistakes here can misroute writes or mishandle untrusted input | `segment-hunter-02` |
| 3 | 8 | `src/ops/verify.rs` | signature parser ambiguity, native public-key export, same-material sign/verify model | Verification is security-sensitive but mostly fail-closed in this slice; reviewed for format confusion and state misuse | `segment-hunter-03` |
| 2 | 5 | `src/ops/shared.rs` | shared path/I/O helpers, output-file atomics, size limits, decode logic | Common helpers can amplify mistakes across the scoped commands | `segment-hunter-03` |
| 1 | n/a | cross-refs (`src/ops.rs`, `src/backend/subprocess.rs`, `src/ops/seed.rs`) | identity validation, trusted binary resolution, derivation plumbing | Read only as needed to validate scoped hypotheses | lead reviewer |

## Notes
- Highest-yield file first: `src/ops/ssh.rs` because it crosses from TPM-derived private key material into another local process.
- Parsers / auth / unsafe / crypto clusters: socket trust validation, native sign staging, signature parser acceptance, and shared path/I/O helpers.
- Deferred low-value areas: no deep exploit work on sign/verify beyond scoped validation once no stronger boundary-crossing issues were found.
