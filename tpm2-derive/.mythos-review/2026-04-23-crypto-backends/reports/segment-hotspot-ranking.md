# Segment Hotspot Ranking

1. **src/ops/seed.rs** — 5/5 hotspot  
   High-value trust boundary: recovery import/export, overwrite semantics, sealed-object path layout, subprocess secret staging, and TPM unseal output handling.

2. **src/ops/prf.rs** — 5/5 hotspot  
   TPM-backed derived-secret path with workspace creation, output-file handling, and identity-to-state path mapping.

3. **src/ops/encrypt.rs** — 4/5 hotspot  
   Secret-bearing stream/legacy decrypt split, inline plaintext/ciphertext behavior, and framed AEAD parsing.

4. **src/ops/native/subprocess.rs** — 4/5 hotspot  
   Native TPM subprocess plan construction, persistent-handle locators, auth-source translation, and export/sign file paths.

5. **src/backend/subprocess.rs** — 4/5 hotspot  
   Command execution trust boundary, allowlisted binary resolution, env clearing, and capability probing behavior.

6. **src/backend.rs** — 2/5 hotspot  
   Aggregation layer; mainly relevant as a public re-export surface for subprocess execution primitives.

## Cross-references used
- `src/ops.rs` — identity-name validation, metadata-path resolution, native-key locator helpers
- `src/ops/shared.rs` — PRF workspace creation and path confinement helpers
- `src/model/identity.rs`, `src/model/state.rs` — persisted state layout and identity storage roots

## Ranked root-cause themes
- identity/profile name validation feeding filesystem layouts
- overwrite/rename state transitions in seed material staging
- subprocess workspaces that temporarily hold secret material
- stream decrypt mode splits and bounded/unbounded output paths
