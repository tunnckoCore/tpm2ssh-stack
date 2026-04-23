# Rejected Candidate

- ID: R-001
- Title: `find_via_nix` shell injection concern not reachable from attacker-controlled input
- Component: `tests/support/mod.rs`
- Severity: none
- Confidence: high
- Root Cause Key: tests-support:find_via_nix:fixed-tool-set:no-untrusted-shell-input

## Why it looked interesting
`find_via_nix()` shells out via `sh -lc` with `format!("command -v {tool}")`, which is normally a command-injection smell.

## Why it was rejected
Within the scoped code, `tool` is only sourced from a fixed internal tool list (`swtpm`, `ssh-add`, `ssh-agent`, `tpm2_*`). No user-controlled argument or persisted state feeds this value, and the helper is private to the test harness.

## Oracle used
Static data-flow tracing from `RealTpmHarness::start()` -> `ToolPaths::resolve()` -> `resolve_tool()` -> `find_via_nix()`.

## Conclusion
Interesting pattern, but not exploitable in the reviewed call graph.
