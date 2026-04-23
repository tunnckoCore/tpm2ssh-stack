# Oracle Log

## Mythos workflow commands
- `deno run --allow-read --allow-write .../bootstrap-hunt.ts tpm2-derive --output-dir ./.mythos-review/2026-04-23-tests-subprocess --target-path /home/arcka/code/tpm2ssh-stack-worktrees/hardening-review-tests-and-subprocess/tpm2-derive`
- `deno run --allow-read .../rank-hotspots.ts . --limit 80 --json > ./.mythos-review/2026-04-23-tests-subprocess/rankings/top-80.json`
- `deno run --allow-read --allow-write .../plan-subagents.ts ./.mythos-review/2026-04-23-tests-subprocess/rankings/segment-top.json --agents 3 --output-dir ./.mythos-review/2026-04-23-tests-subprocess/briefs --prefix segment-hunter`

## Targeted unit-test oracles
- `cargo test --quiet export_native_public_key_rejects_symlink_output_path --lib` -> PASS
- `cargo test --quiet resolve_native_key_locator_rejects_absolute_metadata_paths --lib` -> PASS

## Targeted integration-test oracles
- `cargo test --quiet --features real-tpm-tests --test real_tpm_cli ssh_add_rejects_group_writable_socket_parent_with_real_swtpm` -> PASS
- `cargo test --quiet --features real-tpm-tests --test real_tpm_cli concurrent_native_setup_same_identity_allows_only_one_winner` -> PASS

## Interpretation
The strongest available local oracles in scope confirmed the existing fail-closed behavior around symlink export rejection, metadata path confinement, ssh-agent socket hardening, and concurrent native setup serialization.
