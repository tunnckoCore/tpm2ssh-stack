# TPM2 Derive Status

_As of 2026-04-20._

## What is implemented now

- **CLI skeleton exists** with structured JSON/plain output envelopes and subcommands for `inspect`, `setup`, `derive`, `sign`, `verify`, `encrypt`, `decrypt`, `export`, and `ssh agent add`.
- **Capability probing is real**:
  - default backend is the **subprocess / `tpm2-tools` probe**
  - probes tool availability plus `tpm2_getcap` groups (`algorithms`, `commands`, `ecc-curves`, `properties-fixed`)
  - produces a capability report and mode recommendation
- **Profile/state scaffolding is real**:
  - validates profile names
  - resolves requested vs recommended mode
  - persists profile JSON under the state layout (`profiles/`, `objects/`, `exports/`)
- **Core derivation model is implemented**:
  - canonical derivation context/spec encoding
  - HKDF-based output derivation from PRF material
  - output kinds for secret bytes / Ed25519 / secp256k1 / P-256 scalar material
- **Mode-specific library work exists but is not CLI-wired yet**:
  - **native**: validated request/response types plus subprocess planning for setup, sign, and public-key export
  - **prf**: request model, `tpm2_hmac`/`tpm2_load` execution planning, subprocess execution, and final derivation
  - **seed**: profile/policy model, create/open/export planning, subprocess seal/unseal backend, and HKDF software derivation after unseal
- **Current confidence**: `cargo test -p tpm2-derive` passes (**40 tests**).

## Commands / modes actually usable today

### Usable CLI commands

| Command | Status | What it really does |
| --- | --- | --- |
| `tpm2-derive inspect` | usable | Probes TPM/tooling capabilities and returns a recommendation (`native` / `prf` / `seed`) when possible. |
| `tpm2-derive setup` | partially usable | Validates inputs, resolves a mode, and writes profile metadata. **It does not create TPM objects / PRF roots / sealed seeds yet.** |

### Commands that are only placeholders

These commands parse arguments, but currently return a structured `unsupported` result with a `planned-command` diagnostic:

- `tpm2-derive derive`
- `tpm2-derive sign`
- `tpm2-derive verify`
- `tpm2-derive encrypt`
- `tpm2-derive decrypt`
- `tpm2-derive export`
- `tpm2-derive ssh agent add`

### Modes

- **`native`**: modeled and partially implemented in the library; today it is only used for recommendation/planning, not end-to-end CLI execution.
- **`prf`**: the deepest executable library path right now, but still not connected to persisted profiles or CLI commands.
- **`seed`**: substantial library/backend implementation exists, but also not connected to the CLI/profile flow yet.
- **`backend-tss-esapi`**: currently a stub/placeholder; the active implementation is the subprocess backend.

## What is scaffolded / planned

- End-to-end mode-specific `setup` that actually provisions TPM-backed state:
  - native persistent key/object setup
  - PRF root creation/loading
  - sealed-seed creation and persistence
- Real implementations behind `derive`, `sign`, `verify`, `export`, and `ssh agent add`
- Profile/state expansion to persist backend-specific locators/artifacts, not just generic metadata
- Recovery/export flow for seed mode
- Better TPM auth/policy handling beyond the current scaffold
- Any `encrypt` / `decrypt` path is still **planned** and explicitly outside the current MVP

## Immediate next steps

1. **Make `setup` real**: after mode resolution, call the native / PRF / seed backend and persist the resulting object locators/artifacts.
2. **Wire CLI commands to profiles**: load persisted profiles and connect `derive`, `sign`, and `export` to the existing library paths.
3. **Finish the vertical slices**:
   - native: execute sign/export from persisted state, add verify path
   - PRF: create/store PRF roots and hook `derive`
   - seed: hook create/open/export into CLI
4. **Either implement or hide placeholders** so the CLI surface matches reality.

For the fuller design/architecture direction, see [TPM2_DERIVE_PLAN.md](./TPM2_DERIVE_PLAN.md).
