use super::support::*;

#[test]
fn simulator_api_signs_message_and_digest_bytes_with_exported_p256_public_key() {
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
    let sign_id = RegistryId::new("sim/api/sign-message-and-digest").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(sign_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"api simulator message bytes".to_vec());
    let message_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let message_signature = P256Signature::from_slice(&message_signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &message_signature)
        .unwrap();

    let digest = Zeroizing::new(Sha256::digest(b"api simulator digest bytes").to_vec());
    let digest_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Digest(digest.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let digest_signature = P256Signature::from_slice(&digest_signature).unwrap();
    verifying_key
        .verify_prehash(digest.as_slice(), &digest_signature)
        .unwrap();

    let sha384_message = Zeroizing::new(b"api simulator sha384 message bytes".to_vec());
    let sha384_message_digest = Zeroizing::new(Sha384::digest(sha384_message.as_slice()).to_vec());
    let sha384_message_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Message(sha384_message),
            hash: HashAlgorithm::Sha384,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let sha384_message_signature = P256Signature::from_slice(&sha384_message_signature).unwrap();
    verifying_key
        .verify_prehash(sha384_message_digest.as_slice(), &sha384_message_signature)
        .unwrap();

    let sha384_digest =
        Zeroizing::new(Sha384::digest(b"api simulator sha384 digest bytes").to_vec());
    let sha384_digest_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id),
            payload: SignPayload::Digest(sha384_digest.clone()),
            hash: HashAlgorithm::Sha384,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let sha384_digest_signature = P256Signature::from_slice(&sha384_digest_signature).unwrap();
    verifying_key
        .verify_prehash(sha384_digest.as_slice(), &sha384_digest_signature)
        .unwrap();
}
#[test]
fn simulator_sign_supports_cross_context_pubkey_and_signature_formats_with_software_verification() {
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
    let sign_id = RegistryId::new("sim/api/sign/formats-and-reload").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let raw_public = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(sign_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let der_public = api::pubkey(
        &reloaded_context,
        PubkeyParams {
            material: ObjectSelector::Id(sign_id.clone()),
            output_format: PublicKeyFormat::Der,
        },
    )
    .unwrap();
    let pem_public = api::pubkey(
        &reloaded_context,
        PubkeyParams {
            material: ObjectSelector::Id(sign_id.clone()),
            output_format: PublicKeyFormat::Pem,
        },
    )
    .unwrap();

    let raw_public_key = PublicKey::from_sec1_bytes(&raw_public).unwrap();
    let der_public_key = PublicKey::from_public_key_der(&der_public).unwrap();
    let pem_public_key =
        PublicKey::from_public_key_pem(std::str::from_utf8(&pem_public).unwrap()).unwrap();
    assert_eq!(
        raw_public_key.to_encoded_point(false).as_bytes(),
        der_public_key.to_encoded_point(false).as_bytes()
    );
    assert_eq!(
        raw_public_key.to_encoded_point(false).as_bytes(),
        pem_public_key.to_encoded_point(false).as_bytes()
    );
    let verifying_key = VerifyingKey::from_sec1_bytes(&raw_public).unwrap();

    let message = Zeroizing::new(b"simulator sign output format coverage".to_vec());
    let raw_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let raw_signature = P256Signature::from_slice(&raw_signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &raw_signature)
        .unwrap();

    let hex_signature = api::sign(
        &reloaded_context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Hex,
        },
    )
    .unwrap();
    let hex_signature = hex::decode(&hex_signature).unwrap();
    assert_eq!(hex_signature.len(), 64);
    let hex_signature = P256Signature::from_slice(&hex_signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &hex_signature)
        .unwrap();

    let digest = Zeroizing::new(Sha256::digest(message.as_slice()).to_vec());
    let der_signature = api::sign(
        &reloaded_context,
        SignParams {
            material: ObjectSelector::Id(sign_id),
            payload: SignPayload::Digest(digest.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Der,
        },
    )
    .unwrap();
    let der_signature = P256Signature::from_der(&der_signature).unwrap();
    verifying_key
        .verify_prehash(digest.as_slice(), &der_signature)
        .unwrap();
}
