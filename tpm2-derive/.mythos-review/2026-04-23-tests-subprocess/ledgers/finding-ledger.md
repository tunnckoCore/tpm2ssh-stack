# Finding Ledger

| ID | Status | Title | Component | Root Cause Key | Severity | Confidence | Owner | Duplicate Of | Notes |
|----|--------|-------|-----------|----------------|----------|------------|-------|--------------|-------|
| R-001 | rejected | `find_via_nix` shell injection concern not reachable from attacker-controlled input | `tests/support/mod.rs` | tests-support:find_via_nix:fixed-tool-set:no-untrusted-shell-input | none | high | lead |  | `tool` is drawn from fixed internal names; no external input reaches `sh -lc` |
| R-002 | rejected | Process env mutation unsoundness concern not promoted | `tests/support/mod.rs` | tests-support:env-mutation:serialized-harness:insufficient-trigger | none | medium | lead |  | Code uses unsafe `set_var/remove_var`, but scoped binary's tests all acquire the same harness and mutate only before worker thread spawn; no concrete failing oracle obtained |
| R-003 | rejected | Consecutive-port reservation TOCTOU in swtpm harness is availability-only and test-gated | `tests/support/mod.rs` | tests-support:reserve_ports:toctou:startup-flake | low | medium | lead |  | Real local race exists conceptually, but impact is flaky test startup only, not a fix-ready security break in production code |

## Status meanings
- candidate
- validating
- validated
- fix-ready
- restricted
- rejected
- duplicate
