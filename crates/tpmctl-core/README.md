# tpmctl-core

`tpmctl-core` is the library crate for TPM-backed object management and derived
software-key operations. It owns TPM semantics, registry storage, validation,
output encoders, and secret-handling types.

## Main modules

- `api` — high-level typed operations using an `api::Context`.
- `derive` — TPM-seeded software-key derivation for P-256, secp256k1, and Ed25519, including pure derivation primitives.
- `keygen`, `pubkey`, `sign`, `hmac`, `seal`, `ecdh` — domain request/result APIs.
- `store` — registry IDs, object records, and atomic persistence.
- `tpm` — ESAPI context creation, object loading, handles, signatures, and ECDH.
- `output` — public key, signature, and byte encoders.

## Basic usage

```rust,no_run
use tpmctl_core::{
    RegistryId, StoreOptions,
    api::{self, Context, KeygenParams, PubkeyParams},
    keygen::KeygenUsage,
    output::PublicKeyFormat,
};

fn main() -> tpmctl_core::Result<()> {
    let context = Context {
        store: StoreOptions::default(),
        tcti: None,
    };

    let id = RegistryId::new("app/signing")?;
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )?;

    let public_key = api::pubkey(
        &context,
        PubkeyParams {
            material: tpmctl_core::ObjectSelector::Id(id),
            format: PublicKeyFormat::Pem,
        },
    )?;

    println!("{}", String::from_utf8_lossy(public_key.as_slice()));
    Ok(())
}
```

## Derived keys

`derive` resolves seed material from a sealed object first. If the selected ID is
not sealed, it uses the selected HMAC identity as a TPM PRF seed source. For the
same HMAC identity, algorithm, and label, `Secret`, `Pubkey`, and `Sign` derive
from the same underlying key material.

```rust,no_run
use zeroize::Zeroizing;
use tpmctl_core::{
    DeriveAlgorithm, DeriveFormat, ObjectSelector, RegistryId,
    api::Context,
    derive::{self, DeriveParams, DeriveUse, SignPayload},
};

fn sign(context: &Context) -> tpmctl_core::Result<Zeroizing<Vec<u8>>> {
    derive::derive(
        context,
        DeriveParams {
            material: ObjectSelector::Id(RegistryId::new("app/kdf")?),
            label: Some(b"login/v1".to_vec()),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Sign,
            payload: Some(SignPayload::Message(Zeroizing::new(b"message".to_vec()))),
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
}
```

## Secret handling

Secret-bearing inputs and outputs use `zeroize::Zeroizing<Vec<u8>>` where the
library owns the bytes. Debug output redacts payloads, private blobs, HMAC data,
sealed bytes, ECDH peer material, and derived secrets.

## TPM simulator tests

The integration tests spawn `swtpm` by default and isolate the registry per test:

```sh
cargo test -p tpmctl-core --test simulator_harness -- --nocapture
```

Use an external TCTI only when explicitly needed:

```sh
TPMCTL_TEST_EXTERNAL_TCTI=1 TEST_TCTI='swtpm:host=127.0.0.1,port=2321' \
  cargo test -p tpmctl-core --test simulator_harness
```

## Validation

Recommended core-only checks:

```sh
cargo fmt --all
cargo clippy -p tpmctl-core --all-targets -- -D warnings
cargo test -p tpmctl-core -- --nocapture
cargo doc -p tpmctl-core --no-deps
```
