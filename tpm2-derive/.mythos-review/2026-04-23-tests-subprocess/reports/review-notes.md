# Review Notes

## Scope recap
Focused on `src/ops.rs`, `tests/real_tpm_cli.rs`, `tests/support/mod.rs`, and `Cargo.toml`, with cross-reference reads limited to subprocess/path/output helpers needed to validate hypotheses.

## Production-path conclusions
- `src/ops.rs` subprocess paths are argument-vector based, not shell-concatenated.
- Native TPM command execution resolves executables through a constrained allowlist path search in `src/backend/subprocess.rs` and clears inherited environment.
- Secret-bearing exports in `src/ops.rs` use dedicated output-path validation plus temp-file + `create_new` + `0600` permissions.
- Native serialized-handle metadata resolution fails closed on absolute paths, parent traversal, ambiguous paths, and missing handle state.
- SSH-agent socket handling is defended in production path code (`src/ops/ssh.rs`) and exercised by the real-TPM integration tests.

## Highest-signal rejected ideas
1. Test harness `find_via_nix()` uses a shell, but the command token set is fixed and internal.
2. Harness environment mutation uses unsafe std APIs, but no concrete concurrent read/write oracle was established in this scoped binary.
3. Consecutive port reservation in the harness is raceable, but only into test-startup denial/flakiness.

## Cargo.toml notes
- Default feature remains `backend-tpm-tools`, so subprocess TPM tooling is the normal build path.
- `real-tpm-tests` is opt-in for the integration test target and did not expose an unexpected default-enabled surface in this review.

## Bottom line
After an aggressive pass, no validated vulnerabilities were found in the scoped segment.
