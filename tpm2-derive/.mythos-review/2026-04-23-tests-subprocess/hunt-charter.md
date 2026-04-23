# Hunt Charter

## Target
- Name: tpm2-derive
- Path / binary: /home/arcka/code/tpm2ssh-stack-worktrees/hardening-review-tests-and-subprocess/tpm2-derive
- Owner: local authorized review
- Authorization confirmed by: user instruction in this session

## Scope
- In scope: `src/ops.rs`, `tests/real_tpm_cli.rs`, `tests/support/mod.rs`, `Cargo.toml`, plus cross-references needed to validate subprocess/path/env handling (`src/backend/subprocess.rs`, `src/ops/shared.rs`, `src/ops/ssh.rs`, `src/model/{identity,state}.rs`, `src/ops/native/subprocess.rs`, `src/ops/seed.rs`, `src/ops/prf.rs`)
- Out of scope: unrelated modules unless required to confirm or reject a scoped hypothesis; production code changes
- Source available? [yes/no]: yes
- Binary review needed? [yes/no]: no
- Internet access allowed? [yes/no]: no requirement; review stayed local
- Offline/container-only required? [yes/no]: local-only review requested; honored

## Goal
- Primary objective: aggressive red-team review of subprocess spawning, path handling, secret-export sinks, real-TPM test harness behavior, and feature/defaults in the scoped segment
- Desired output: Mythos workspace with ranked hotspots, rejected/validated candidate trail, oracle log, and final report
- Fix agents expected downstream: only if fix-ready findings were validated

## Reporting boundary
- Full internal path: ./.mythos-review/2026-04-23-tests-subprocess/reports
- Restricted summary needed? [yes/no]: no
- Public-safe summary needed? [yes/no]: no

## Hunt plan
- Hotspot ranking owner: lead reviewer
- Parallel clusters: `src/ops.rs`; `tests/real_tpm_cli.rs`; `tests/support/mod.rs`; `Cargo.toml` with cross-referenced subprocess/path helpers
- Validation tools/oracles: targeted static tracing, `cargo test` unit oracles, `cargo test --features real-tpm-tests --test real_tpm_cli` integration oracles, Mythos dedupe/pack/validate scripts
- Finding ledger path: ./.mythos-review/2026-04-23-tests-subprocess/ledgers/finding-ledger.md
