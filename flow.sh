#!/usr/bin/bash

# generates a keypair (Ed25519 or NIST P-256)
ssh-keygen -t ed25519 -f ./ed-testkey -N ""
# ./ed-testkey and ./ed-testkey.pub

# Extract raw public key bytes as hex
PUBKEY_HEX="$(cat ./ed-testkey.pub \
    | awk '{print $2}' \
    | base64 -d \
    | xxd -p -c0
)"

# Extract user_id (SHA256 of pubkey as hex)
USER_ID=$(cat ./ed-testkey.pub \
    | awk '{print $2}' \
    | base64 -d \
    | sha256sum \
    | cut -d' ' -f1
)

# Register with pubkey auth
ssh -p 2222 \
    -i ./ed-testkey \
    -o PreferredAuthentications=publickey \
    "$USER_ID@localhost" \
    "register"

# SUCCESS: 5c9440e8dee499a6af99d9de5a67a983cf0cb5294d71e061b2da3d41a9dd3b2c

# Create signature and hex-encode the PEM
SIG_HEX="$(echo -n "register-v1" \
    | ssh-keygen -Y sign -n tpm2ssh-prfd- -f ./ed-testkey - \
    | xxd -p -c0
)"

# Connect with pubkey auth using user_id as username
ssh -p 2222 \
    -i ./ed-testkey \
    -o PreferredAuthentications=publickey \
    "$USER_ID@localhost" \
    "verify $SIG_HEX"

# SUCCESS: true
```

#####
#####

# Create PRF signature over message: {pubkey_hex}-{user_id}
PRF_SIG_HEX=$(echo -n "$PUBKEY_HEX-$USER_ID" \
    | ssh-keygen -Y sign -n tpm2ssh-prfd- -f ./ed-testkey - \
    | xxd -p -c0
)

# Returns `pre_prf_seed` in hex
ssh -p 2222 \
    -i ./ed-testkey \
    -o PreferredAuthentications=publickey \
    "$USER_ID@localhost" \
    "prf $PRF_SIG_HEX"

# SUCCESS: 79d5a6e634e56a8a3e8a1b09d49ea114438b9914ed1c0dea1430d03a92e9efc6
