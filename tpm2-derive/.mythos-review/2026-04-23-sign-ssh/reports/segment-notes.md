# Segment Review Notes

## Scope pass summary
- `ssh.rs`: full red-team pass on socket-path trust, export gating, and process invocation. One validated high-severity finding.
- `sign.rs`: reviewed native staging, digest handling, signature persistence, and format constraints. No additional validated issue.
- `verify.rs`: reviewed parsing, signature limits, native public-key export, and sign/verify derivation symmetry. No additional validated issue.
- `shared.rs`: reviewed input-size limits, streaming hash helpers, atomic output writes, and symlink checks. No additional in-scope validated issue.

## Supporting evidence
- `evidence/scoped-tests.txt`: targeted unit tests for scoped modules.
- `evidence/ssh-symlink-race/repro.rs`: local public-API repro harness.
- `evidence/ssh-symlink-race/output.txt`: proof output showing post-validation socket redirection.
