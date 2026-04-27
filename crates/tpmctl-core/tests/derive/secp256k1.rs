use super::support::*;

#[test]
fn simulator_api_derive_from_sealed_seed_emits_secp256k1_pubkey_address_and_signature() {
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
    let seed_id = RegistryId::new("sim/api/derive/secp256k1-sealed-seed").unwrap();
    let label = b"simulator sealed seed secp256k1 derivation".to_vec();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(seed_id.clone()),
            input: Zeroizing::new(b"sealed secp256k1 derive integration seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let secret = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: DeriveUse::Secret,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(secret.len(), 32);
    let software_secret = k256::SecretKey::from_slice(secret.as_slice()).unwrap();

    let public_sec1 = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
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
    let verifying_key = Secp256k1VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let compressed_public = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: derive::DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: true,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(compressed_public.len(), 33);
    assert!(matches!(compressed_public[0], 0x02 | 0x03));

    let address = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: derive::DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Address,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(address.len(), 42);
    assert!(address.starts_with(b"0x"));

    let message = Zeroizing::new(b"api derive simulator secp256k1 signature payload".to_vec());
    let digest = Zeroizing::new(Sha256::digest(message.as_slice()).to_vec());
    let signature = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
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
    let software_signature: Secp256k1Signature = Secp256k1SigningKey::from(software_secret.clone())
        .sign_prehash(&digest)
        .unwrap();
    let software_signature_bytes = software_signature.to_bytes();
    assert_eq!(signature.as_slice(), &software_signature_bytes[..]);
    let signature = Secp256k1Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify_prehash(digest.as_slice(), &signature)
        .unwrap();

    let digest_signature = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id),
            label: Some(label),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: derive::DeriveUse::Sign,
            payload: Some(derive::SignPayload::Digest(digest.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(digest_signature.len(), 64);
    let digest_signature = Secp256k1Signature::from_slice(&digest_signature).unwrap();
    verifying_key
        .verify_prehash(digest.as_slice(), &digest_signature)
        .unwrap();
}
