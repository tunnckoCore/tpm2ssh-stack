# Segment Brief: state/model hardening review

## Scope
- src/model/identity.rs
- src/model/core.rs
- src/model/state.rs
- src/ops/enforcement.rs
- src/backend/recommend.rs

## Hunt focus
- Truthfulness of supported identity surfaces by mode
- Divergence between recommendation-layer support and setup-time enforcement
- Persisted identity/state fail-closed behavior
- Disk layout, path, and permission assumptions

## Do not spend time on
- Generic host hardening or filesystem advice
- Unscoped backend subprocess review except where required to prove a scoped finding
