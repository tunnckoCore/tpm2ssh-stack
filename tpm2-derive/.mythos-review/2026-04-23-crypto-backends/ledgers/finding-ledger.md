# Finding Ledger

| ID | Status | Title | Component | Root Cause Key | Severity | Confidence | Owner | Duplicate Of | Notes |
|----|--------|-------|-----------|----------------|----------|------------|-------|--------------|-------|
| MSR-2026-04-23-crypto-backends-001 | fix-ready | Singleton-dot identity names collapse backend state roots and turn seed overwrite into shared-state deletion | seed/prf/native state layout and subprocess backends | identity-name-single-dot-collapses-state-root | High | High | lead reviewer | | Strong local repro showed unrelated shared objects state deleted before the operation failed. |
