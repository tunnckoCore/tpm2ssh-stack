Final Implementation Plan
Confirmed Architecture
┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER'S MACHINE                                     │
│                                                                              │
│  Browser ──WebAuthn──► CTAP2 Stack ──USB HID──► Virtual USB Gadget          │
│                                                            │                 │
│                                                            ▼                 │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ tpm2ssh-authenticator daemon (user)                                   │   │
│  │                                                                       │   │
│  │  Commands:                                                            │   │
│  │  --setup   (root, one-time): Create USB gadget, seal user_secret     │   │
│  │  --daemon  (user): Handle CTAP2, process PRF via backend             │   │
│  │                                                                       │   │
│  │  PRF Flow:                                                            │   │
│  │  1. Receive hmac-secret request from browser                          │   │
│  │  2. SSH exec to VPS: `prf <user_pubkey>`                              │   │
│  │  3. Receive pre_prf from backend                                      │   │
│  │  4. Unseal user_secret from TPM (same PIN)                            │   │
│  │  5. Final PRF = HKDF(pre_prf + user_secret)                          │   │
│  │  6. Return to browser                                                 │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Storage: ~/.ssh/tpm2ssh/authenticator.json                                  │
│  TPM: Handle 0x81006970 (user_secret, sealed with same PIN)                  │
└──────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     │ SSH
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VPS BACKEND                                      │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ tpm2ssh-prfd (russh SSH server)                                       │   │
│  │                                                                       │   │
│  │  Registration (accountless, two-step):                                │   │
│  │  1. auth_none: receive pubkey → store {id, pubkey, reg_sig, verified=false} │
│  │  2. auth_publickey: verify → set verified=true                        │   │
│  │                                                                       │   │
│  │  PRF Request (SSH exec):                                              │   │
│  │  Command: `prf <user_pubkey_base64>`                                  │   │
│  │  Response: <pre_prf_base64>                                           │   │
│  │                                                                       │   │
│  │  Derivation: pre_prf = HKDF(service_secret + user_id + user_reg_sig) │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Storage:                                                                    │
│  - credentials.json or SQLite: {id, pubkey, reg_sig, verified, created_at}  │
│  - service_secret: TPM-sealed or env variable                               │
└──────────────────────────────────────────────────────────────────────────────┘
---
Project Structure
agent-secrets-manager/
├── tpm2ssh/                        # EXISTING
│   ├── Cargo.toml
│   └── src/main.rs
│
├── tpm2ssh-authenticator/          # NEW
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                 # CLI: --setup, --daemon
│       ├── setup.rs                # USB gadget creation (root)
│       ├── daemon.rs               # Main daemon loop
│       ├── ctap2/
│       │   ├── mod.rs
│       │   ├── commands.rs         # CTAP2 command handlers
│       │   ├── responses.rs        # CTAP2 response builders
│       │   └── extensions.rs       # hmac-secret/PRF extension
│       ├── hid.rs                  # /dev/hidrawX read/write
│       ├── tpm.rs                  # user_secret sealing/unsealing
│       └── backend.rs              # SSH client to VPS
│
├── tpm2ssh-prfd/                   # NEW
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                 # SSH server entry
│       ├── handler.rs              # russh Handler impl
│       ├── registry.rs             # User credential storage
│       ├── prf.rs                  # PRF derivation
│       └── config.rs               # Server config
│
└── shared/                         # Optional: shared types
    └── protocol.rs                 # Common protocol definitions
---
Implementation Phases
Phase 1: Backend Service (tpm2ssh-prfd)
Deliverables:
1. russh SSH server listening on configurable port
2. auth_none handler: receive pubkey, store unverified
3. auth_publickey handler: verify signature, mark verified
4. Exec command handler: prf <pubkey_b64> → return pre_prf_b64
5. File-based credential storage (JSON)
6. Service secret from environment or TPM
Dependencies:
[dependencies]
russh = "0.45"
russh-keys = "0.43"
tokio = { version = "1", features = ["full"] }
hkdf = "0.12"
sha2 = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
Testing:
# Start server
SERVICE_SECRET="test-secret" cargo run
# Register (from user machine)
ssh -o PreferredAuthentications=none -i ~/.ssh/tpm2ssh/id_user user@localhost
ssh -i ~/.ssh/tpm2ssh/id_user user@localhost  # verify
# Request PRF
ssh -i ~/.ssh/tpm2ssh/id_user user@localhost prf $(cat ~/.ssh/tpm2ssh/id_user.pub | base64 -w0)
---
Phase 2: Platform Authenticator (tpm2ssh-authenticator)
Deliverables:
2a. Setup Command (root):
1. Create USB gadget via configfs (/sys/kernel/config/usb_gadget/)
2. Configure HID function for FIDO2
3. Enable gadget
4. Create udev rule for persistence
5. Seal user_secret to TPM handle 0x81006970
6. Create systemd user service file
2b. Daemon Command (user):
1. Open /dev/hidrawX for reading
2. CTAP2 command parser/dispatcher
3. Implement commands:
   - authenticatorGetInfo (advertise hmac-secret support)
   - authenticatorMakeCredential (create credential, return attestation)
   - authenticatorGetAssertion (authenticate, handle PRF)
4. hmac-secret extension:
   - On PRF request, call VPS backend
   - Merge with user_secret from TPM
   - Return final PRF
Dependencies:
[dependencies]
tokio = { version = "1", features = ["full"] }
russh = "0.45"
russh-keys = "0.43"
hkdf = "0.12"
sha2 = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
cbor = "0.4"              # CBOR encoding for CTAP2
p256 = "0.13"             # ECDSA for credentials
rand = "0.8"
Testing:
# Setup (as root)
sudo tpm2ssh-authenticator --setup
# Start daemon (as user)
tpm2ssh-authenticator --daemon
# Browser should now detect a new authenticator
# Test at webauthn.io or similar
---
Phase 3: Browser Extension (Future)
Deliverables:
1. Popup UI showing authenticator status
2. Identity management (switch between keys)
3. PRF visualization/debug tools
---
Data Structures
Credential Registry (credentials.json)
{
  users: [
    {
      id: uuid-v4,
      pubkey: ssh-ed25519 AAAA...,
      pubkey_b64: base64-encoded,
      reg_sig: base64 signature from registration,
      verified: true,
      created_at: 2026-02-22T10:00:00Z,
      last_used: 2026-02-22T12:00:00Z
    }
  ]
}
Authenticator State (~/.ssh/tpm2ssh/authenticator.json)
{
  user_pubkey_path: ~/.ssh/tpm2ssh/id_user_ed25519.pub,
  user_secret_handle: 0x81006970,
  backend_host: prfd.example.com:22,
  credentials: [
    {
      id: base64-cred-id,
      rp_id: example.com,
      user_handle: base64-user-handle,
      created_at: 2026-02-22T10:00:00Z
    }
  ]
}
