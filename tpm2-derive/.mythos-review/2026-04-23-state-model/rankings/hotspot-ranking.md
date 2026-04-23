# Focused Hotspot Ranking

Scoped segment ranking for 2026-04-23-state-model.

| Rank | File | Score | Why it mattered |
|------|------|-------|-----------------|
| 1 | src/backend/recommend.rs | 5/5 | Capability truthfulness drives inspect output, auto-mode selection, and explicit-mode acceptance checks. |
| 2 | src/model/identity.rs | 5/5 | Persisted identity JSON is a state trust boundary; loader hardening determines whether tampered/stale state is accepted. |
| 3 | src/model/core.rs | 4/5 | Canonical use-contract rules live here; any drift from recommendation logic creates security-model inconsistency. |
| 4 | src/model/state.rs | 3/5 | State-root fallback and permissioning determine fail-closed behavior for missing environment and persisted material layout. |
| 5 | src/ops/enforcement.rs | 3/5 | Test-only file, but high-value oracle because it encodes the intended coupled-use contract across modes. |

## Cross-references pulled in
- src/ops.rs — real resolve path using `probe.supports_mode(...)` before final validation.
- src/model/capability.rs — `expand_mode_requested_uses(...)` and supported-surface expansion.
- src/backend.rs — default `CapabilityProbe` behavior and front-door wiring.

## Ranked hypotheses checked
1. Recommendation/support logic might overclaim capabilities relative to setup-time enforcement.
2. Persisted identity loader might accept repointed or incompatible state.
3. State-root fallback might silently degrade into insecure or surprising behavior.
4. Export-policy / root-material metadata might be trusted without recomputation.

Outcome: hypothesis #1 validated; #2 and #3 looked hardened in current branch; #4 did not reach a fix-ready impact threshold in this pass.
