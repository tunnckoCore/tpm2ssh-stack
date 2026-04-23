# Hunt Charter

## Target
- Name: tpm2-derive
- Path / binary: /home/arcka/code/tpm2ssh-stack-worktrees/hardening-review-state-and-model/tpm2-derive
- Owner: authorized local review in user-provided worktree
- Authorization confirmed by: user instruction "Authorized local review only" for this worktree/branch

## Scope
- In scope: src/model/identity.rs, src/model/core.rs, src/model/state.rs, src/ops/enforcement.rs, src/backend/recommend.rs
- Out of scope: production code changes; unrelated subsystems except targeted cross-references needed to validate state/model findings
- Source available? [yes]
- Binary review needed? [no]
- Internet access allowed? [no]
- Offline/container-only required? [local-only]

## Goal
- Primary objective: aggressive red-team review of state/model correctness, capability truthfulness, path/state handling, and policy enforcement edges
- Desired output: validated, fix-ready findings only; deduped and packaged under the unique slug workspace
- Fix agents expected downstream: hardening/refactor implementers on this branch

## Reporting boundary
- Full internal path: ./.mythos-review/2026-04-23-state-model/reports
- Restricted summary needed? [no]
- Public-safe summary needed? [no]

## Hunt plan
- Hotspot ranking owner: lead review agent
- Parallel clusters: (1) persisted identity/state trust boundary, (2) mode/use truthfulness and recommendation logic, (3) enforcement/oracle cross-checks
- Validation tools/oracles: code-path cross-reference, existing unit tests, cargo test targeted execution, workspace validation + pack scripts
- Finding ledger path: ./.mythos-review/2026-04-23-state-model/ledgers/finding-ledger.md

## User steer applied
- Steer (verbatim): "assume host/server is properly protected, do not suggest things general advices and obvious things"
- Handling: excluded generic host-hardening advice and focused only on concrete code-level mismatches in scoped files.
