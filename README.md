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

1. **VPS Side**: `pre_prf_seed = HKDF(service_secret + user_id + signature_sha + pubkey)`
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

### Get Your user_id

```bash
# Extract user_id from SSH key (SHA256 of pubkey as raw hex)
USER_ID=$(cat ~/.ssh/id_ed25519.pub | awk '{print $2}' | base64 -d | sha256sum | cut -d' ' -f1)
echo "user_id: $USER_ID"
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TPM2SSH_PRFD_SECRET` | 32-byte service secret (hex) | Generated on startup |
| `TPM2SSH_PRFD_PORT` | Server port | `2222` |
| `TPM2SSH_PRFD_REGISTRY` | Path to credentials registry | `~/.config/tpm2ssh-prfd/registry.json` |

## Response Format

All commands return standardized responses and SSH exit codes (0 for success, 1 for failure):

```
SUCCESS: <result>
FAILURE <code>: <message>
```

**Error codes:**
- `400` - Bad request (invalid input, verification failed, already registered)
- `403` - Forbidden (auth required, credential not verified)

**Note:** All hex values are raw hex strings (no `0x` prefix).

## Protocol

### Phase 1: Register (anonymous)

Register a pubkey. Use the username `anonymous` to connect without a key:

```bash
# Extract raw public key bytes as hex
PUBKEY_HEX=$(cat ~/.ssh/id_ed25519.pub | awk '{print $2}' | base64 -d | xxd -p -c0)

ssh -o PreferredAuthentications=none -o PubkeyAuthentication=no \
    anonymous@localhost -p 2222 "register $PUBKEY_HEX"
```

**Response:** `SUCCESS: <user_id>`

The `user_id` returned is `sha256(pubkey)` as hex. Client should verify this matches their derivation.

### Phase 2: Verify (auth-pubkey)

Verify ownership by signing the message `register-v1` with namespace `tpm2ssh-prfd-`. **Must connect with username equal to your `user_id` (SHA256 of pubkey) to trigger public key authentication.**

```bash
# Extract user_id (SHA256 of pubkey as hex)
USER_ID=$(cat ~/.ssh/id_ed25519.pub | awk '{print $2}' | base64 -d | sha256sum | cut -d' ' -f1)

# Create signature and hex-encode the PEM
echo -n "register-v1" | ssh-keygen -Y sign -n tpm2ssh-prfd- -f ~/.ssh/id_ed25519 - > /tmp/sig.pem
SIG_HEX=$(cat /tmp/sig.pem | xxd -p -c0)

# Connect with pubkey auth using user_id as username
ssh -i ~/.ssh/id_ed25519 -o PreferredAuthentications=publickey \
    $USER_ID@localhost -p 2222 "verify $SIG_HEX"
```

**Response:** `SUCCESS: true`

**Errors:**
- `FAILURE 403: pubkey auth required` - anonymous connection
- `FAILURE 400: signature verification failed` - invalid signature

### Phase 3: Get PRF Seed (auth-pubkey)

Once verified, retrieve the pre_prf_seed. Requires auth-pubkey with username=`user_id` and signature over `<pubkey_hex>-<user_id>`:

```bash
# Create PRF signature over message: {pubkey_hex}-{user_id}
echo -n "$PUBKEY_HEX-$USER_ID" | ssh-keygen -Y sign -n tpm2ssh-prfd- -f ~/.ssh/id_ed25519 - > /tmp/prf_sig.pem
PRF_SIG_HEX=$(cat /tmp/prf_sig.pem | xxd -p -c0)

ssh -i ~/.ssh/id_ed25519 -o PreferredAuthentications=publickey \
    $USER_ID@localhost -p 2222 "prf $PRF_SIG_HEX"
```

**Response:** `SUCCESS: <pre_prf_seed_hex>`

**Errors:**
- `FAILURE 403: pubkey auth required` - anonymous connection
- `FAILURE 403: credential not verified` - not yet verified
- `FAILURE 400: signature verification failed` - invalid PRF signature

## Commands

| Command | Auth | Username | Description |
|---------|------|----------|-------------|
| `register <pubkey_hex>` | none | `anonymous` | Register pubkey, returns `user_id` |
| `verify <sig_hex>` | pubkey | `user_id` | Verify with signature over `register-v1` |
| `prf <sig_hex>` | pubkey | `user_id` | Get pre_prf_seed (verified only, sig over `{pubkey_hex}-{user_id}`) |
| `help` | any | `any` | Show usage |

## Signature Format

Signatures must be hex-encoded [SshSig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig) PEM:

```bash
echo -n "<message>" | ssh-keygen -Y sign -n tpm2ssh-prfd- -f <keyfile> - | xxd -p -c0
```

**Namespace:** `tpm2ssh-prfd-` (trailing dash)

**Messages:**
- Verify: `register-v1`
- PRF: `<pubkey_hex>-<user_id>` (raw hex, joined by dash)

## Registry Format

Credentials are stored in JSON format, keyed by `user_id`:

```json
{
  "credentials": {
    "<sha256_of_pubkey>": {
      "pubkey_hex": "<pubkey_bytes_as_hex>",
      "signature_sha": "<sha256_of_signature_pem_bytes>",
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
