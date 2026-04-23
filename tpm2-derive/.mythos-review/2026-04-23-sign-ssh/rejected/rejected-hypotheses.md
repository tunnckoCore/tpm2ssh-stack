# Rejected / Deferred Hypotheses

## Reviewed but not promoted

1. **`sign.rs` native workspace path handling**
   - Hypothesis: `stage_native_sign()` could follow a hostile state-directory symlink and redirect internal artifact writes.
   - Result: not promoted in this review segment. The pattern exists only if the caller already points the tool at an attacker-controlled state root, which collapses the local trust boundary for this CLI anyway. No independent exploit beyond that prerequisite was proven.

2. **`verify.rs` signature-format auto-detection ambiguity**
   - Hypothesis: `InputFormat::Auto` might misparse some signatures and create a verification bypass.
   - Result: rejected. The reviewed parsers fail closed and no signature accepted under the wrong algorithm/encoding was reproduced.

3. **`shared.rs` output-file parent symlink handling**
   - Hypothesis: `with_output_file()` only rejects a symlink at the final file path and could redirect writes through parent symlinks.
   - Result: deferred. The destination is user-selected output, not an internal secret-bearing sink in the reviewed sign/verify/ssh paths, so no concrete boundary-crossing issue was validated in-scope.
