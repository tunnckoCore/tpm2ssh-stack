# Finding Ledger

| ID | Status | Title | Component | Root Cause Key | Severity | Confidence | Owner | Duplicate Of | Notes |
|----|--------|-------|-----------|----------------|----------|------------|-------|--------------|-------|
| F-001 | fix-ready | Identity setup/load accepts invalid derivation defaults that later hard-fail crypto operations | CLI identity setup + identity persistence | cli-identity+model-identity:missing-derivation-default-validation:deferred-crypto-failure | low | high | lead |  | Strong oracle in `evidence/invalid-defaults-oracle/output.txt` |
| F-002 | rejected | Repeated `--context` keys silently last-win during request construction | CLI derivation-input collection | cli-derivation-inputs:duplicate-context-key:last-write-wins |  | medium | lead |  | Real behavior confirmed, but not promoted without a stronger exploit/contract-break oracle |

## Status meanings
- candidate
- validating
- validated
- fix-ready
- restricted
- rejected
- duplicate

## Root cause key guidance
Use a stable key such as:
`component:function:condition:sink`

Example:
`auth/session.c:parse_token:missing-length-check:heap-write`
