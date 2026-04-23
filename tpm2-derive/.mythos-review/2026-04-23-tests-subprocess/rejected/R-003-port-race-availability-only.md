# Rejected Candidate

- ID: R-003
- Title: Consecutive-port reservation TOCTOU in swtpm harness is availability-only and test-gated
- Component: `tests/support/mod.rs`
- Severity: low
- Confidence: medium
- Root Cause Key: tests-support:reserve_ports:toctou:startup-flake

## Why it looked interesting
`reserve_ports()` binds command/control ports, drops the listeners, and then `swtpm` is spawned later. A competing local binder could steal one of the ports in the gap.

## Why it was rejected
This is a real race pattern, but the scoped impact is startup flakiness in `real-tpm-tests`, not a production trust-boundary break. The user asked for fix-ready, high-signal security issues; this did not clear that bar.

## Oracle used
Static review of `reserve_ports()` and `RealTpmHarness::start()` sequencing.

## Conclusion
Recorded as a failure mode, not promoted as a security finding.
