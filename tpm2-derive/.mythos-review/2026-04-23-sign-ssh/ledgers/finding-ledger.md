# Finding Ledger

| ID | Status | Title | Component | Root Cause Key | Severity | Confidence | Owner | Duplicate Of | Notes |
|----|--------|-------|-----------|----------------|----------|------------|-------|--------------|-------|
| 2026-04-23-sign-ssh-F001 | fix-ready | `ssh-add` socket validation can be bypassed with an intermediate symlink and post-validation swap | SSH agent export / socket validation | `ssh:add:resolve_socket:intermediate-symlink-socket-redirection` | High | High | lead reviewer | | validated via local repro harness and code audit |

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
