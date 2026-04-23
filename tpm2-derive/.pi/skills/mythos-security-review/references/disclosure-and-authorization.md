# Disclosure and Authorization

## Authorization first
Do not begin a hunt until the user has authorized the target.

Check:
- local repo vs external target
- private vs public ownership
- source vs binary scope
- internet access allowed or prohibited
- whether outputs are internal-only

## Reporting tiers
### Full internal
For the user and fix agents.
May include detailed repro steps and file paths.

### Restricted triage
For internal stakeholders who need prioritization without full detail.
Include impact, confidence, and affected area.

### Public-safe
Use only when asked.
Abstract specifics and omit sensitive trigger detail.

## Sensitive findings
Prefer restricted handling when:
- the target is unpatched
- the target is externally owned
- the issue is closed-source
- exploitability is high
- the audience is broader than the fix team

## Never include
- unrelated secrets or credentials
- unnecessary operational detail
- claims stronger than the evidence supports
