use super::support::*;

#[test]
fn simulator_native_sign_by_id_signs_message_and_digest_with_exported_pubkey() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let id = RegistryId::new("sim/native/sign/by-id").unwrap();
    let message = Zeroizing::new(b"native sign by id message".to_vec());
    let digest = Zeroizing::new(Sha256::digest(message.as_slice()).to_vec());

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    let public_by_id = PubkeyRequest {
        selector: ObjectSelector::Id(id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_by_id).unwrap();

    let message_signature = SignRequest {
        selector: ObjectSelector::Id(id.clone()),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let message_signature = decode_p256_signature(&message_signature, SignatureFormat::Raw);
    verifying_key
        .verify(message.as_slice(), &message_signature)
        .unwrap();

    let digest_signature = SignRequest {
        selector: ObjectSelector::Id(id),
        input: SignInput::Digest(digest.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let digest_signature = decode_p256_signature(&digest_signature, SignatureFormat::Raw);
    verifying_key
        .verify_prehash(digest.as_slice(), &digest_signature)
        .unwrap();
}

#[test]
fn simulator_native_sign_by_id_supports_reload_hashes_and_formats() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let id = RegistryId::new("sim/native/sign/by-id-reload-formats").unwrap();
    let message = Zeroizing::new(b"native sign by id reload and formats".to_vec());

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    let public_by_id = PubkeyRequest {
        selector: ObjectSelector::Id(id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_by_id).unwrap();

    let reloaded_store = Store::new(temp_store.path());

    let raw_sha256 = SignRequest {
        selector: ObjectSelector::Id(id.clone()),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute(&reloaded_store)
    .unwrap();
    let raw_sha256 = decode_p256_signature(&raw_sha256, SignatureFormat::Raw);
    verifying_key
        .verify(message.as_slice(), &raw_sha256)
        .unwrap();

    let digest_sha384 = Zeroizing::new(Sha384::digest(message.as_slice()).to_vec());
    let hex_sha384 = SignRequest {
        selector: ObjectSelector::Id(id.clone()),
        input: SignInput::Digest(digest_sha384.clone()),
        hash: HashAlgorithm::Sha384,
        output_format: SignatureFormat::Hex,
    }
    .execute(&reloaded_store)
    .unwrap();
    let hex_sha384 = decode_p256_signature(&hex_sha384, SignatureFormat::Hex);
    verifying_key
        .verify_prehash(digest_sha384.as_slice(), &hex_sha384)
        .unwrap();

    let digest_sha512 = Zeroizing::new(Sha512::digest(message.as_slice()).to_vec());
    let der_sha512 = SignRequest {
        selector: ObjectSelector::Id(id),
        input: SignInput::Digest(digest_sha512.clone()),
        hash: HashAlgorithm::Sha512,
        output_format: SignatureFormat::Der,
    }
    .execute(&reloaded_store)
    .unwrap();
    let der_sha512 = decode_p256_signature(&der_sha512, SignatureFormat::Der);
    verifying_key
        .verify_prehash(digest_sha512.as_slice(), &der_sha512)
        .unwrap();
}

#[test]
fn simulator_non_persistent_keygen_sign_reload_supports_sha512() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let id = RegistryId::new("sim/keygen/reload-sign-sha512").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    let signature = SignRequest {
        selector: ObjectSelector::Id(id),
        input: SignInput::Message(Zeroizing::new(b"parent and hash flexibility".to_vec())),
        hash: HashAlgorithm::Sha512,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();

    assert_eq!(signature.len(), 64);
}
