# Mythos Security Review Report - 2026-04-23-crypto-backends

Generated: 2026-04-23T05:11:30.572Z

## Summary

- Total validated findings: 1

## By Severity

- High: 1

## By Confidence

- High: 1

## Findings

| ID | Severity | Confidence | Title | Component | Path(s) | Handoff |
|----|----------|------------|-------|-----------|---------|---------|
| MSR-2026-04-23-crypto-backends-001 | High | High | Singleton-dot identity names collapse backend state roots and turn seed overwrite into shared-state deletion | seed/prf/native state layout and subprocess backends | src/ops/seed.rs; src/ops/prf.rs; src/ops/native/subprocess.rs; src/ops.rs | ./.mythos-review/2026-04-23-crypto-backends/handoffs/MSR-2026-04-23-crypto-backends-001.md |

## Why fix now

### MSR-2026-04-23-crypto-backends-001: Singleton-dot identity names collapse backend state roots and turn seed overwrite into shared-state deletion
this is a one-input integrity/availability break on the shared object store. The demonstrated failure deleted unrelated state even though the operation ultimately errored, so retry/rollback does not contain the damage.
