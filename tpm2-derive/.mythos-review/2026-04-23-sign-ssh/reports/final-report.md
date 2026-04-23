# Mythos Security Review Report - 2026-04-23-sign-ssh

Generated: 2026-04-23T05:13:31.246Z

## Summary

- Total validated findings: 1

## By Severity

- High: 1

## By Confidence

- High: 1

## Findings

| ID | Severity | Confidence | Title | Component | Path(s) | Handoff |
|----|----------|------------|-------|-----------|---------|---------|
| 2026-04-23-sign-ssh-F001 | High | High | `ssh-add` socket validation can be bypassed with an intermediate symlink and post-validation swap | SSH agent export / socket validation | `src/ops/ssh.rs:159-207`, `src/ops/ssh.rs:401-476` | ./.mythos-review/2026-04-23-sign-ssh/handoffs/2026-04-23-sign-ssh-F001.md |

## Why fix now

### 2026-04-23-sign-ssh-F001: `ssh-add` socket validation can be bypassed with an intermediate symlink and post-validation swap
this is the last gate before private key material leaves TPM-only protection; a destination-confusion bug here nullifies the operator's intent and can exfiltrate a long-lived SSH key to an attacker-controlled agent.
