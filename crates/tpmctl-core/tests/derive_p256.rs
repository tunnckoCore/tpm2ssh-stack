mod support;

use support::*;

#[test]
fn simulator_api_derive_from_sealed_seed_emits_p256_pubkey_and_signature() {
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
    let seed_id = RegistryId::new("sim/api/derive/sealed-seed").unwrap();
    let label = b"simulator sealed seed p256 derivation".to_vec();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(seed_id.clone()),
            input: Zeroizing::new(b"sealed derive integration seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let secret = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Secret,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    let repeated_secret = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Secret,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(secret, repeated_secret);
    assert_eq!(secret.len(), 32);
    let software_secret = SecretKey::from_slice(secret.as_slice()).unwrap();

    let public_sec1 = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(public_sec1.len(), 65);
    assert_eq!(public_sec1[0], 0x04);
    let expected_public_sec1 = software_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    assert_eq!(public_sec1.as_slice(), expected_public_sec1.as_slice());
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"api derive simulator signature payload".to_vec());
    let digest = Sha256::digest(message.as_slice());
    let signature = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id),
            label: Some(label),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Sign,
            payload: Some(DeriveSignPayload::Message(message.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(signature.len(), 64);
    let software_signature: P256Signature = P256SigningKey::from(software_secret)
        .sign_prehash(&digest)
        .unwrap();
    let software_signature_bytes = software_signature.to_bytes();
    assert_eq!(signature.as_slice(), &software_signature_bytes[..]);
    let signature = P256Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();
}

#[test]
fn simulator_api_derive_uses_hmac_identity_seed_via_persistent_handle() {
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
    let hmac_id = RegistryId::new("sim/api/derive-hmac-handle/key").unwrap();
    let handle = PersistentHandle::new(0x8101_0042).unwrap();
    let label = b"simulator derive hmac persistent handle label".to_vec();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: Some(handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();

    let by_handle_secret_params = DeriveParams {
        material: ObjectSelector::Handle(handle),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Secret,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let handle_secret = derive::derive(&context, by_handle_secret_params.clone()).unwrap();
    let repeated_handle_secret = derive::derive(&context, by_handle_secret_params).unwrap();
    assert_eq!(handle_secret, repeated_handle_secret);
    assert_eq!(handle_secret.len(), 32);
    let software_secret = SecretKey::from_slice(handle_secret.as_slice()).unwrap();

    let by_handle_params = DeriveParams {
        material: ObjectSelector::Handle(handle),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let handle_pubkey = derive::derive(&context, by_handle_params.clone()).unwrap();
    let repeated_handle_pubkey = derive::derive(&context, by_handle_params).unwrap();
    assert_eq!(handle_pubkey, repeated_handle_pubkey);
    assert_eq!(handle_pubkey.len(), 65);
    assert_eq!(handle_pubkey[0], 0x04);
    let expected_public = software_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    assert_eq!(handle_pubkey.as_slice(), expected_public.as_slice());

    let by_id_pubkey = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(hmac_id),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(handle_pubkey, by_id_pubkey);

    let message = Zeroizing::new(b"derive with persistent HMAC identity handle".to_vec());
    let digest = Sha256::digest(message.as_slice());
    let public_key = VerifyingKey::from_sec1_bytes(&handle_pubkey).unwrap();
    let signature = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Handle(handle),
            label: Some(label),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Sign,
            payload: Some(DeriveSignPayload::Message(message.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(signature.len(), 64);
    let software_signature: P256Signature = P256SigningKey::from(software_secret)
        .sign_prehash(&digest)
        .unwrap();
    let software_signature_bytes = software_signature.to_bytes();
    assert_eq!(signature.as_slice(), &software_signature_bytes[..]);
    let signature = P256Signature::from_slice(&signature).unwrap();
    public_key.verify(message.as_slice(), &signature).unwrap();

    cleanup_persistent_handle(handle);
}
