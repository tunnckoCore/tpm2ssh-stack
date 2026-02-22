# tpm2ssh-prfd

> **TPM2SSH PRF Backend Service** - SSH server providing Zero-knowledge partial PRF seeds for WebAuthn-compatible secret derivation.

## Overview

`tpm2ssh-prfd` is the VPS backend component of the tpm2ssh PRF architecture. It provides a zero-knowledge PRF (Pseudo-Random Function) service where neither the server nor the client alone can derive the final secret.

## Architecture

```
Browser (WebAuthn) → Virtual USB → tpm2ssh-authenticator → SSH to tpm2ssh-prfd → TPM (user_secret)
                                                   ↓
                                            pre_prf_seed derivation
                                                   ↓
                                            final_prf = HKDF(pre_prf_seed + user_secret)
```

## Security Model

1. **VPS Side**: `pre_prf_seed = HKDF(service_secret + user_id + user_reg_sig)`
2. **User Side**: `final_prf = HKDF(pre_prf_seed + user_secret)`
3. Neither side knows the complete secret

## Installation

```bash
cargo build --release
```

## Usage

### Start the Server

```bash
# With random service secret (generates one on startup and outputs it for us on next runs)
./target/release/tpm2ssh-prfd

# With custom service secret (32 bytes hex)
TPM2SSH_PRFD_SECRET=0123456789abcdef... ./target/release/tpm2ssh-prfd

# Custom port (default: 2222)
TPM2SSH_PRFD_PORT=22 ./target/release/tpm2ssh-prfd

# Custom registry path (defaults to ~/.config/tmp2ssh-prfd/registry.json)
TPM2SSH_PRFD_REGISTRY=/var/lib/tpm2ssh-prfd/registry.json ./target/release/tpm2ssh-prfd
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TPM2SSH_PRFD_SECRET` | 32-byte service secret (64 hex chars) | Generated on startup |
| `TPM2SSH_PRFD_PORT` | Server port | `2222` |
| `TPM2SSH_PRFD_REGISTRY` | Path to credentials registry | `~/.config/tpm2ssh-prfd/registry.json` |

## SSH Commands

### Registration (Two-Phase)

**Phase 1 - Register public key (unverified):**
```bash
# Using auth_none with pubkey as username (base64 encoded)
ssh -o PreferredAuthentications=none -o PubkeyAuthentication=no \
    <pubkey_base64>@localhost -p 2222
```

**Phase 2 - Authenticate and verify:**
```bash
# Using publickey authentication
ssh -i ~/.ssh/tpm2/id_user_ed25519_tpm2 user@localhost -p 2222
```

### Exec Commands

Once authenticated:

```bash
# Get PRF seed
ssh -i ~/.ssh/tpm2/id_user_ed25519_tpm2 user@localhost -p 2222 "prf"

# Check status
ssh -i ~/.ssh/tpm2/id_user_ed25519_tpm2 user@localhost -p 2222 "status"

# Register a key via exec
ssh -i ~/.ssh/tpm2/id_user_ed25519_tpm2 user@localhost -p 2222 "register <pubkey_base64>"
```

## Registry Format

Credentials are stored in JSON format:

```json
{
  "credentials": {
    "SHA256:abc123...": {
      "pubkey_b64": "base64-encoded-public-key",
      "verified": true,
      "registered_at": "2026-01-15T10:30:00Z"
    }
  }
}
```

## Integration with tpm2ssh-authenticator

The `tpm2ssh-authenticator` daemon connects to this server to:
1. Register user's TPM-backed public key
2. Retrieve `pre_prf_seed` for WebAuthn PRF operations
3. Combine with local `user_secret` to derive `final_prf`
