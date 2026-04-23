# Candidate Finding

## Summary
- ID: F-002
- Title: Repeated `--context` keys silently last-win during request construction
- Component: CLI derivation-input collection
- Path(s): src/cli/args.rs:94-95, src/cli/mod.rs:120-125
- Bug class: ambiguous input / silent key overwrite
- Root Cause Key: cli-derivation-inputs:duplicate-context-key:last-write-wins

## Hypothesis
- Suspected issue: repeated `--context key=value` flags with the same key are accepted and silently collapsed into one map entry, so later entries overwrite earlier ones without warning.
- Why it may matter: derivation context selects signing/encryption/export identity material; a duplicated key can silently retarget the effective derived identity.
- Trust boundary involved: operator / wrapper-script input into crypto derivation context

## Evidence so far
- Static evidence: `derivation_overrides()` converts `Vec<(String, String)>` into `BTreeMap` via `.collect()` with no duplicate-key check.
- Dynamic evidence: `./.mythos-review/2026-04-23-cli-surface/evidence/context-dup-oracle/output.txt` shows `[("tenant", "alpha"), ("tenant", "beta")]` becomes `{"tenant": "beta"}`.
- Oracle strength: moderate

## Reproduction status
- Repro available? yes
- Minimal trigger idea: parse `identity dupctx --context tenant=alpha --context tenant=beta`
- Preconditions: duplicated context key in CLI input

## Root cause
- Suspected root cause: repeated context pairs are intentionally or accidentally funneled through `BTreeMap::collect()` without duplicate detection.
- Confidence: medium
- Competing explanations: maintainers may consider last-write-wins acceptable map semantics rather than a bug.

## Next step to validate or reject
- Best next oracle: prove a concrete operator-visible integrity failure (for example, duplicate-order-dependent derived public keys) and compare it against intended CLI contract.
- Owner: lead reviewer
