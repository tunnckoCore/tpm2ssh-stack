mod support;

use support::*;

#[test]
fn simulator_api_derive_from_sealed_seed_emits_ed25519_pubkey_and_signature() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let seed_id = RegistryId::new("sim/api/derive/ed25519-sealed-seed").unwrap();
    let label = b"simulator sealed seed ed25519 derivation".to_vec();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(seed_id.clone()),
            input: Zeroizing::new(b"sealed ed25519 derive integration seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let public_key = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Ed25519,
            usage: derive::DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(public_key.len(), 32);
    let public_key: [u8; 32] = public_key.as_slice().try_into().unwrap();
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_key).unwrap();

    let message = Zeroizing::new(b"api derive simulator ed25519 signature payload".to_vec());
    let signature = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id),
            label: Some(label),
            algorithm: DeriveAlgorithm::Ed25519,
            usage: derive::DeriveUse::Sign,
            payload: Some(derive::SignPayload::Message(message.clone())),
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(signature.len(), 64);
    let signature = Ed25519Signature::try_from(signature.as_slice()).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();
}
