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

1. **VPS Side**: `pre_prf_seed = HKDF(service_secret + fingerprint + signature + pubkey)`
2. **User Side**: `final_prf = HKDF(pre_prf_seed + user_secret)`
3. Neither side knows the complete secret

## Installation

```bash
cargo build --release
```

## Usage

### Start the Server

```bash
# With random service secret (generates one on startup and outputs it for use on next runs)
./target/release/tpm2ssh-prfd

# With custom service secret (32 bytes hex)
TPM2SSH_PRFD_SECRET=0123456789abcdef... ./target/release/tpm2ssh-prfd

# Custom port (default: 2222)
TPM2SSH_PRFD_PORT=22 ./target/release/tpm2ssh-prfd

# Custom registry path (defaults to ~/.config/tpm2ssh-prfd/registry.json)
TPM2SSH_PRFD_REGISTRY=/var/lib/tpm2ssh-prfd/registry.json ./target/release/tpm2ssh-prfd
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TPM2SSH_PRFD_SECRET` | 32-byte service secret (64 hex chars) | Generated on startup |
| `TPM2SSH_PRFD_PORT` | Server port | `2222` |
| `TPM2SSH_PRFD_REGISTRY` | Path to credentials registry | `~/.config/tpm2ssh-prfd/registry.json` |

## Response Format

All commands return standardized responses:

```
SUCCESS <result>
FAILURE <code> <message>
```

**Error codes:**
- `400` - Bad request (invalid input, verification failed)
- `403` - Forbidden (auth required, credential not verified)

## Protocol

### Phase 1: Register (auth-none)

Register a pubkey without verification:

```bash
ssh -o PreferredAuthentications=none -o PubkeyAuthentication=no \
    user@localhost -p 2222 "register <pubkey_base64>"
```

**Response:** `SUCCESS SHA256:abc123...`

The fingerprint returned should match what the client/requester can derive from their pubkey.

### Phase 2: Verify (auth-pubkey)

Verify ownership by signing the message `register-v1` with namespace `tpm2ssh-prfd`:

```bash
# Create signature using ssh-keygen
echo -n "register-v1" | ssh-keygen -Y sign -n tpm2ssh-prfd -f ~/.ssh/tpm2/id_user_ed25519_tpm2 - > /tmp/sig.pem

# Connect with pubkey auth and verify
ssh -i ~/.ssh/tpm2/id_user_ed25519_tpm2 user@localhost -p 2222 "verify $(cat /tmp/sig.pem)"
```

**Response:** `SUCCESS true`

**Errors:**
- `FAILURE 403 pubkey auth required` - auth-none connection
- `FAILURE 400 signature verification failed` - invalid signature

### Phase 3: Get PRF Seed

Once verified, retrieve the pre_prf_seed:

```bash
ssh user@localhost -p 2222 "prf <pubkey_base64>"
```

**Response:** `SUCCESS <base64-encoded-32-byte-seed>`

**Errors:**
- `FAILURE 403 credential not registered` - unknown pubkey
- `FAILURE 403 credential not verified` - not yet verified

## Commands

| Command | Auth | Description |
|---------|------|-------------|
| `register <pubkey_b64>` | none | Register pubkey, returns fingerprint |
| `verify <sshsig_pem>` | pubkey | Verify with signature, returns `true` |
| `prf <pubkey_b64>` | any | Get pre_prf_seed (verified only) |
| `help` | any | Show usage |

## Signature Format

Signatures must be [SshSig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig) PEM format:

```
-----BEGIN SSH SIGNATURE-----
...
-----END SSH SIGNATURE-----
```

Created with:
```bash
echo -n "register-v1" | ssh-keygen -Y sign -n tpm2ssh-prfd -f <keyfile> -
```

## Registry Format

Credentials are stored in JSON format, keyed by fingerprint:

```json
{
  "credentials": {
    "SHA256:abc123...": {
      "signature_b64": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----",
      "verified": true,
      "created_at": "2026-01-15T10:30:00Z",
      "verified_at": "2026-01-15T10:35:00Z"
    }
  }
}
```

## Integration with tpm2ssh-authenticator

The `tpm2ssh-authenticator` daemon connects to this server to:
1. Register user's TPM-backed public key
2. Verify ownership with TPM-signed signature
3. Retrieve `pre_prf_seed` for WebAuthn PRF operations
4. Combine with local `user_secret` to derive `final_prf`
