# tpm2 tooling

okay, now, i refactored the repo we were in. it's a clean slate with just empty Cargo.toml and we are in `minimal-and-native`. there's the `pkcs11` module lib you initially did at `./pkcs11`

lets call it passgent-core, passgent-cli, passgent-pkcs11. the feature should be `pkcs11-provider` maybe.

we are targeting a local-first cli approach, assuming a safe properly secure host/machine.

we need to support just p256. the "keygen" cli should be around the non-persistent handles, but ctx files making it scalable to create many identities. we need to allow them to creatge sign-p256 ke, ecdh-p256 key, and hmac key which would be used as "prf" root if they need to derive something in software.

it should be library-first approach. so start from the library. then we build the cli from it.

make a plan for implementing all that. use the PRD/ADRs. but no, we don't need an ADR for now, just a plan.

---

example cli api:


### creating identities

```bash
tpmctl identity --sign --id org/acme/alice/main
tpmctl identity --ecdh --id org/acme/alice/comms
tpmctl identity --hmac --id org/acme/alice/kdf

# optionally pass handle to persist to
tpmctl identity --sign --id org/acme/alice/main --handle 0x81010010
```

### signing

optionally if the identity is persistent, instead of `--id` they should be able to use `--handle` i think.


```bash
# pre-hash the message
openssl dgst -sha256 -binary message.txt > message.sha256

# sign computed hash
tpmctl sign --id org/acme/alice/main --digest ./message.sha256 --output ./sig.der

# sign accept message directly with --input and compute hash
tpmctl sign --id org/acme/alice/main --input ./message.txt --output ./sig.der

# sign should support outputting the signature raw bytes as hex
tpmctl sign --id org/acme/alice/main --input ./message.txt --output ./sig.hex --hex

# or without `--output` to be pipe-able (printed to stdout)
tpmctl sign --id org/acme/alice/main --input ./message.txt --raw
```

### generating pubkeys, ecdh, hmac

optionally if the identity is persistent, instead of `--id` they should be able to use `--handle` i think.

```bash
# public key of the main TPM-persisted p256 key
tpmctl pubkey --id org/acme/alice/main > alice-main.pem

# static ECDH public key, used for e2ee comms
tpmctl pubkey --id org/acme/alice/comms > alice-comms.pem

# generate shared secret for comms with bob
tpmctl ecdh --id org/acme/alice/comms --peer-pub ./bob-comms.pem

# or output shared secret to file
tpmctl ecdh --id org/acme/alice/comms --peer-pub ./bob-comms.pem --output ./shared-secret.bin

# generate hmac secret and output hex
tpmctl hmac --id org/acme/alice/kdf --input ./ctx.bin --hex

# or, output to stdout
tpmctl hmac --id org/acme/alice/kdf --input ./ctx.bin

# or, output to file
tpmctl hmac --id org/acme/alice/kdf --input ./ctx.bin --output ./prf.bin

# or, persist the prf as sealed secret on the tpm
tpmctl hmac --id org/acme/alice/kdf --input ./ctx.bin --handle 0x81010020
```
