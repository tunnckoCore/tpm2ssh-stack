# tpm2-derive

Rethinking of the whole thing.

### Commands

- inspect
- setup
- 
- derive
- 
- sign
- verify
- 
- encrypt
- decrypt

misc:

- import
- export --kind public-key
- export --kind recovery-bundle
- 
- ssh-agent

### Modes

- native
- prf
- seed

### Algorithms

- p256
- ed25519
- secp256k1

---

## P-256 - Native

### Can/Cannot Use

**CAN:** `sign`, `verify`, `encrypt`, `decrypt`, `ssh-agent`, `export public-key`
**CANNOT:** `derive`, `export private-key`.

## P-256 - PRF

### Can/Cannot Use

**CAN:** everything, because uses the `derive

------


### P-256 in `native` mode -> available usage = all

**NOTE:** can also export `PublicKey`, but **NOT** the `SecretKey`.

**NOTE:** The `--use all` should be supported to enable all available (which is everything without `derive`)

```bash

# initialize
tpm2x setup \
  --profile wgw \
  --algorithm p256 \
  --mode native \
  --use sign \
  --use verify \
  --use encrypt \
  --use decrypt \
  --use ssh-agent

# signing
tpm2x sign --profile wgw --input msg.txt

# verifying
tpm2-derive verify --profile wgw --input msg.txt --signature msg-sig.der

# exporting pubKey
tpm2-derive export --profile wgw --kind public-key --output wgw-pubkey.spki.der

# encrypt & decrypt (inside the TPM)
tpm2x encrypt --profile wgw --input msg.txt --output msg-ciphertext.bin
tpm2x decrypt --profile wgw --input msg-ciphertext.bin --output msg-decrypted.txt

# TODO -- not sure if there is a way without giving the key to the agent?
# maybe we should have a `git signing helper` then takes the message, we use the `sign` and then proceed?
tpm2x ssh-agent add --profile wgw
```


### P-256 in `prf` mode

Not `getrandom`, but a secret seed which is used to derive bytes, in combination with the INPUT that is given.

**NOTE:** Support everything, including `derive`.

It **MUST** use at least one of the  `derive` flags like `--namespace`, `--purpose`, and `--context`, that's because that will be used as part of the derivation process that happens under the hood (implicitly/transparently) to generate the key that would do the action (sign/verify/encrypt/decrypt) with.

```bash

# initialize
tpm2x setup \
  --profile wgw-prf \
  --algorithm p256 \
  --mode prf \
  --use sign \
  --use verify \
  --use encrypt \
  --use decrypt \
  --use ssh-agent \
  --use derive

# signing
tpm2x sign --profile wgw-prf --input msg.txt --namespace com.example.wgw

# verifying
tpm2x verify --profile wgw-prf --input msg.txt --signature msg-sig.der --namespace com.example.wgw

# exporting publicKey
tpm2x export --profile wgw-prf --output wgw-prf-pubkey.spki.der --export-public-key  --namespace com.example.wgw

# exporting secretKey
tpm2x export --profile wgw-prf --output wgw-prf-seckey.spki.der --export-secret-key --confirm --reason "i need it temporary" --namespace com.example.wgw

# exporting keypair
tpm2x export --profile wgw-prf --output wgw-prf-keypair.json --export --confirm --reason "hardware migration" --namespace com.example.wgw

# encrypt & decrypt (inside the TPM)
tpm2x encrypt --profile wgw-prf --input msg.txt --output msg-ciphertext.bin --namespace com.example.wgw
tpm2x decrypt --profile wgw-prf --input msg-ciphertext.bin --output msg-decrypted.txt --namespace com.example.wgw

# TODO -- not sure if there is a way without giving the key to the agent?
# maybe we should have a `git signing helper` then takes the message, we use the `sign` and then proceed?
tpm2x ssh-agent add --profile wgw-prf --namespace com.example.wgw

# deriving a deterministic value from the `prf` value
tpm2x derive \
    --profile wgw-prf \
    --namespace com.example \
    --purpose session \
    --context tenant=alpha \
    --length 32
```

----



```bash
# or `--use sign,verify`
tpm2x identity wgw --algorithm p256 --mode native --use all
```
