# Mythos Security Review Report - 2026-04-23-state-model

Generated: 2026-04-23T05:09:12.398Z

## Summary

- Total validated findings: 1

## By Severity

- low: 1

## By Confidence

- high: 1

## Findings

| ID | Severity | Confidence | Title | Component | Path(s) | Handoff |
|----|----------|------------|-------|-----------|---------|---------|
| F-001 | low | high | Capability recommendation layer falsely reports unsupported one-sided PRF/Seed use contracts as supported | capability recommendation / mode selection truthfulness | src/backend/recommend.rs; src/model/core.rs; src/ops/enforcement.rs; cross-ref: src/ops.rs; src/model/capability.rs | ./.mythos-review/2026-04-23-state-model/handoffs/F-001.md |

## Why fix now

### F-001: Capability recommendation layer falsely reports unsupported one-sided PRF/Seed use contracts as supported
this branch is explicitly hardening state/model truthfulness. Leaving the drift in place preserves a false-positive capability surface that can mislead automation, tests, and future refactors.
