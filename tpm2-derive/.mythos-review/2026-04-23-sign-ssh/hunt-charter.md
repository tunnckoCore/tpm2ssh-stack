# Hunt Charter

## Target
- Name: tpm2-derive
- Path / binary: /home/arcka/code/tpm2ssh-stack-worktrees/hardening-review-ops-sign-ssh/tpm2-derive
- Owner: authorized local review in user-provided worktree
- Authorization confirmed by: user instruction on 2026-04-23 for branch `refactor/hardening-review-ops-sign-ssh`

## Scope
- In scope: `src/ops/sign.rs`, `src/ops/verify.rs`, `src/ops/ssh.rs`, `src/ops/shared.rs`, and direct cross-references required to validate findings
- Out of scope: unrelated subsystems except where needed to prove or reject a scoped hypothesis
- Source available? [yes]
- Binary review needed? [no]
- Internet access allowed? [not used]
- Offline/container-only required? [local only]

## Goal
- Primary objective: aggressively red-team signing, verification, SSH-agent export, and shared I/O/path-handling code for trust-boundary failures, unsafe defaults, path abuse, and secret-egress mistakes
- Desired output: fix-ready validated findings plus repro evidence and a final packaged report
- Fix agents expected downstream: maintainers / hardening follow-up agents

## Reporting boundary
- Full internal path: ./.mythos-review/2026-04-23-sign-ssh/reports
- Restricted summary needed? [no]
- Public-safe summary needed? [no]

## Hunt plan
- Hotspot ranking owner: lead reviewer
- Parallel clusters: `ssh.rs`; `sign.rs`; `verify.rs + shared.rs`
- Validation tools/oracles: Mythos scripts, focused cargo tests, code audit, and a custom local repro harness for socket-path redirection
- Finding ledger path: ./.mythos-review/2026-04-23-sign-ssh/ledgers/finding-ledger.md
