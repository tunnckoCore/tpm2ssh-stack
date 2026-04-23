# Hunt Charter

## Target
- Name: tpm2-derive-ops-crypto-backends
- Path / binary: /home/arcka/code/tpm2ssh-stack-worktrees/hardening-review-ops-crypto-backends/tpm2-derive
- Owner: local authorized review
- Authorization confirmed by: user message dated 2026-04-23 authorizing local review in the hardening-review-ops-crypto-backends worktree

## Scope
- In scope: src/ops/encrypt.rs, src/ops/prf.rs, src/ops/seed.rs, src/ops/native/subprocess.rs, src/backend/subprocess.rs, src/backend.rs, and cross-references only as needed
- Out of scope: production code changes, unrelated repo areas except minimal cross-references needed to validate findings
- Source available? yes
- Binary review needed? no
- Internet access allowed? no
- Offline/container-only required? local-only review in worktree

## Goal
- Primary objective: aggressively red-team the crypto/backend subprocess segment, validate only real issues with the strongest available oracle, and hand off fix-ready reports
- Desired output: validated findings, repro evidence, dedupe output, workspace validation, and packed final report under this slug only
- Fix agents expected downstream: maintainers or follow-on hardening agents

## Reporting boundary
- Full internal path: ./.mythos-review/2026-04-23-crypto-backends/reports
- Restricted summary needed? no
- Public-safe summary needed? no

## Hunt plan
- Hotspot ranking owner: lead reviewer
- Parallel clusters: (1) seed/prf state and secret handling, (2) encrypt framing and inline-output paths, (3) subprocess/backend trust boundaries
- Validation tools/oracles: cargo unit tests, standalone local rust repro harnesses linked against the current crate, static path tracing, Mythos dedupe/validation/pack scripts
- Finding ledger path: ./.mythos-review/2026-04-23-crypto-backends/ledgers/finding-ledger.md
