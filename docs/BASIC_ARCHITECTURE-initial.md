## Summary of Confirmed Architecture

### Components:
1. tpm2ssh (existing) - TPM-sealed SSH keys
2. tpm2ssh-authenticator (new) - Platform authenticator daemon on user's machine
3. tpm2ssh-prfd (new) - VPS backend with SSH server

### Key Decisions:
- Linux-only first
- Option C: Hybrid seed derivation (service secret + user components)
- SSH only (russh), no HTTPS
- Accountless - pubkey is identity
- Two-step registration (`auth_none → store pubkey unverified → public-key-auth → verified`)

### PRF Derivation Flow:
Service side:
  service_secret + user_id + user_reg_signature => pre_prf_seed

### User side (tpm2ssh-authenticator):

`pre_prf_seed + user_secret (from user's TPM) => prf`
  
This is a clever design - neither side knows the full derivation material:
- Service knows: `service_secret, user_id, user_reg_signature`
- User knows: `user_secret` (TPM-sealed)
- PRF requires both, so neither can derive PRF alone

### What I Need to Research
1. libfido2 virtual authenticator - How to register as a platform authenticator on Linux
2. WebAuthn authenticator implementation - What messages does the browser send, what responses are expected
3. russh - Rust SSH server/client library capabilities
4. CTAP2 hmac-secret - The underlying protocol for PRF

Let me research these topics to form a comprehensive implementation plan.
