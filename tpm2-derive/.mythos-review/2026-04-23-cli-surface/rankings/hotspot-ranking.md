# Segment Hotspot Ranking

Scope segment requested by user:
- src/cli/args.rs
- src/cli/mod.rs
- src/model/command.rs
- src/model/capability.rs
- README.md

Cross-references pulled only where needed to validate concrete hypotheses.

| Score | Path | Why it matters |
|---|---|---|
| 5 | src/cli/args.rs | Entry parser for derivation defaults, secret-egress flags, and repeated context fields. |
| 5 | src/cli/mod.rs | Converts parsed flags into request models; owns `DerivationOverrides` collection and decrypt egress gating. |
| 5 | src/ops.rs | `build_identity_record` persists defaults; strongest cross-ref for setup-time validation gaps. |
| 5 | src/ops/shared.rs | Shared derivation path validates org/purpose/context later during real crypto operations. |
| 4 | src/model/command.rs | Secret-bearing request/response carrier with no invariant enforcement. |
| 4 | src/model/identity.rs | Persist/load lifecycle can preserve malformed defaults. |
| 3 | src/model/capability.rs | Mode/use expansion controls whether risky flows are reachable. |
| 2 | README.md | Security contract for operator-visible behavior; useful to detect contract drift. |

## Ranked hunt hypotheses
1. Setup-time/default-time validation mismatch for derivation inputs.
2. CLI collection semantics on repeated `--context` flags may silently rewrite derivation identity.
3. Decrypt/export/ssh-add egress controls may diverge from documented contract.

## User-steer handling
Received steer: "assume host/server is properly protected, do not suggest things general advices and obvious things".
This review therefore avoided host-hardening recommendations and focused on repo-specific codepaths only.
