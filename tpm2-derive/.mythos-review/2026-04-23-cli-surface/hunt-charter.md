# Hunt Charter

## Target
- Name: tpm2-derive-cli-surface
- Path / binary: /home/arcka/code/tpm2ssh-stack-worktrees/hardening-review-cli-surface/tpm2-derive
- Owner: local authorized review by user instruction
- Authorization confirmed by: user message authorizing local review on branch `refactor/hardening-review-cli-surface`

## Scope
- In scope: `src/cli/args.rs`, `src/cli/mod.rs`, `src/model/command.rs`, `src/model/capability.rs`, `README.md`, and minimal cross-references needed to validate hypotheses (`src/ops.rs`, `src/ops/shared.rs`, `src/model/identity.rs`, `src/ops/encrypt.rs`, `src/ops/ssh.rs`)
- Out of scope: unrelated backend internals except where needed to prove or reject a CLI-surface finding
- Source available? yes
- Binary review needed? no
- Internet access allowed? no dependency on internet used for review logic
- Offline/container-only required? local-only review requested; stayed local

## Goal
- Primary objective: red-team the CLI surface for security-significant validation gaps, unsafe defaults, injection-adjacent behavior, and secret-egress failures
- Desired output: fix-ready internal findings with strong local oracles and minimal noise
- Fix agents expected downstream: repo maintainers / hardening follow-up agents

## Reporting boundary
- Full internal path: ./.mythos-review/2026-04-23-cli-surface/reports
- Restricted summary needed? no
- Public-safe summary needed? no

## Hunt plan
- Hotspot ranking owner: lead reviewer
- Parallel clusters:
  - Cluster A: parsing and request construction (`src/cli/args.rs`, `src/cli/mod.rs`)
  - Cluster B: model/invariant cross-checks and persistence (`src/model/command.rs`, `src/model/capability.rs`, cross-ref `src/ops.rs`, `src/ops/shared.rs`, `src/model/identity.rs`)
- Validation tools/oracles:
  - Mythos bootstrap/ranking/dedupe/validate/pack scripts
  - local Rust oracle programs stored under `evidence/`
  - targeted `cargo run` / `cargo`-based harnesses only
- Finding ledger path: ./.mythos-review/2026-04-23-cli-surface/ledgers/finding-ledger.md

## User steer
- Supplementary directive received verbatim: "assume host/server is properly protected, do not suggest things general advices and obvious things"
- Application: findings are constrained to code-specific behavior; no generic host-hardening advice is included.
