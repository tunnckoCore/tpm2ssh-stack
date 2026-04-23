# Rejected Candidate

- ID: R-002
- Title: Process env mutation unsoundness concern not promoted
- Component: `tests/support/mod.rs`
- Severity: none
- Confidence: medium
- Root Cause Key: tests-support:env-mutation:serialized-harness:insufficient-trigger

## Why it looked interesting
The harness uses `unsafe { env::set_var(...) }` and `unsafe { env::remove_var(...) }`, which is only sound when no concurrent environment access exists.

## Why it was rejected
This integration test binary has 15 tests and every one acquires `RealTpmHarness::start()`. The scoped review did not find a concrete concurrent read/write oracle inside this binary while mutations occur. Worker-thread activity observed in the file happens after mutation, while the environment remains stable.

## Oracle used
Static call-graph review plus test inventory (`15/15` tests in `tests/real_tpm_cli.rs` instantiate `RealTpmHarness`).

## Conclusion
The pattern deserves code-owner awareness, but it did not meet the bar for a validated finding in this scoped review.
