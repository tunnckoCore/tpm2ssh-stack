# Hotspot Ranking

## Script output retained
- Canonical ranking JSON: `rankings/top-80.json`
- Segment-only filtered ranking: `rankings/segment-top.json`
- Generated briefs: `briefs/segment-hunter-*.md`

## Manual segment ranking

| Rank | Path | Score | Why it stayed hot |
|---|---|---:|---|
| 1 | `src/ops.rs` | 5/5 | Secret-bearing export sinks, subprocess orchestration, metadata/path validation, native handle persistence, lock/file semantics |
| 2 | `tests/support/mod.rs` | 4/5 | Process env mutation, local binary resolution, `nix shell` fallback, spawned helper daemons, port reservation, ssh-agent/swtpm harnessing |
| 3 | `tests/real_tpm_cli.rs` | 4/5 | Real-world oracle coverage for policy gates, socket checks, concurrency behavior, and native setup fail-closed behavior |
| 4 | `Cargo.toml` | 2/5 | Default subprocess backend, gated `real-tpm-tests`, dependency/default-feature posture |

## Cross-references used to validate or reject hypotheses
- `src/backend/subprocess.rs` — trusted program resolution and environment clearing
- `src/ops/shared.rs` — atomic output helpers and symlink defenses
- `src/ops/ssh.rs` — ssh-agent socket validation and subprocess behavior
- `src/model/identity.rs` / `src/model/state.rs` — persistence and state-layout roots
- `src/ops/native/subprocess.rs` — public-key export planning and identifier validation
- `src/ops/seed.rs` / `src/ops/prf.rs` — path/identity validation reused by scoped flows

## Analyst take
The highest-yield attack surface in this slice was `src/ops.rs`: it is where untrusted path inputs, persisted metadata, subprocess invocations, and secret export policies converge. The tests and harness files were then reviewed mainly as oracle quality and failure-mode multipliers rather than primary production sinks.
