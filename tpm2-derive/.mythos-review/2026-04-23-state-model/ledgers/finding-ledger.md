# Finding Ledger

| ID | Status | Title | Component | Root Cause Key | Severity | Confidence | Owner | Duplicate Of | Notes |
|----|--------|-------|-----------|----------------|----------|------------|-------|--------------|-------|
| F-001 | fix-ready | Capability recommendation layer falsely reports unsupported one-sided PRF/Seed use contracts as supported | capability recommendation / mode selection | backend/recommend.rs:supports_mode:missing-coupled-use-contracts:false-capability-acceptance | low | high | review agent | | Validated via targeted cargo tests and code-path cross-reference |

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
