mod support;

use support::*;

#[test]
fn simulator_or_test_tcti_opens_esapi_context_and_gets_random() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();

    startup_and_get_random();
}

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

#[test]
fn simulator_persistent_handle_keygen_loads_by_handle_and_enforces_lifecycle() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0040).unwrap();
    let first_id = RegistryId::new("sim/keygen/persistent-first").unwrap();
    let second_id = RegistryId::new("sim/keygen/persistent-second").unwrap();

    let first = KeygenRequest {
        usage: KeygenUsage::Sign,
        id: first_id,
        persist_at: Some(handle),
        force: initial_persistent_force(),
    }
    .execute_with_store(&store)
    .unwrap();
    assert_eq!(first.persistent_handle, Some(handle));

    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"persistent simulator signing by handle".to_vec());
    let signature = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let signature = P256Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();

    let duplicate = KeygenRequest {
        usage: KeygenUsage::Sign,
        id: second_id.clone(),
        persist_at: Some(handle),
        force: false,
    }
    .execute_with_store(&store);
    assert!(
        duplicate.is_err(),
        "occupied persistent handle should reject duplicate keygen without force"
    );

    let replacement = KeygenRequest {
        usage: KeygenUsage::Sign,
        id: second_id,
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_store(&store)
    .unwrap();
    assert_eq!(replacement.persistent_handle, Some(handle));

    let replacement_signature = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let replacement_signature = P256Signature::from_slice(&replacement_signature).unwrap();
    assert!(
        verifying_key
            .verify(message.as_slice(), &replacement_signature)
            .is_err(),
        "force should evict the old persistent object before persisting replacement"
    );

    let replacement_public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_ne!(
        public_sec1, replacement_public_sec1,
        "replacement must install a distinct object at the persistent handle"
    );

    let mut tpm_context = tpmctl_core::tpm::create_context().unwrap();
    let persistent_object = tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle)
        .expect("replacement should be present at persistent handle");
    tpmctl_core::tpm::evict_persistent_object(&mut tpm_context, persistent_object, handle)
        .expect("test cleanup should evict replacement persistent object");
    assert!(
        tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle).is_err(),
        "cleanup eviction should leave the persistent handle vacant"
    );
}

#[test]
fn simulator_sign_and_hmac_reject_wrong_object_usages() {
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

    let store = Store::new(temp_store.path());
    let sign_id = RegistryId::new("sim/negative/sign-key").unwrap();
    let hmac_id = RegistryId::new("sim/negative/hmac-key").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: sign_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    let sign_with_hmac = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(hmac_id.clone()),
            payload: SignPayload::Message(Zeroizing::new(b"wrong usage sign".to_vec())),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(sign_with_hmac.contains("expected sign object, got hmac"));

    let handle = PersistentHandle::new(0x8101_004c).unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: RegistryId::new("sim/negative/hmac-handle-key").unwrap(),
            persist_at: Some(handle),
            overwrite: allow_external_tcti(),
        },
    )
    .unwrap();

    let native_sign_with_hmac_handle = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(Zeroizing::new(b"wrong handle usage sign".to_vec())),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute_with_store_and_context(&store, &simulator_command_context(temp_store.path()))
    .unwrap_err()
    .to_string();
    assert!(native_sign_with_hmac_handle.contains("expected sign object, got hmac"));

    let hmac_with_sign = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(sign_id.clone()),
            input: Zeroizing::new(b"wrong usage hmac".to_vec()),
            hash: None,
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(hmac_with_sign.contains("expected hmac object, got sign"));
}

#[test]
fn simulator_handle_and_id_resolution_reject_stale_or_mismatched_persistent_metadata() {
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
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0044).unwrap();
    let sign_id = RegistryId::new("sim/negative/handle-id/sign").unwrap();
    let ecdh_id = RegistryId::new("sim/negative/handle-id/ecdh").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id.clone(),
            persist_at: Some(handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();
    let original_entry = store.load_key(&sign_id).unwrap();

    let mut tpm_context = tpmctl_core::tpm::create_context().unwrap();
    let persistent_object = tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle)
        .expect("sign key should be present at persistent handle");
    tpmctl_core::tpm::evict_persistent_object(&mut tpm_context, persistent_object, handle)
        .expect("test should be able to evict persistent object");

    let by_handle_missing = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap_err();
    assert!(matches!(by_handle_missing, tpmctl_core::Error::Tpm { .. }));

    let by_id_missing = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Message(Zeroizing::new(b"missing persistent backing".to_vec())),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap_err();
    assert!(matches!(by_id_missing, tpmctl_core::Error::Tpm { .. }));
    assert_eq!(store.load_key(&sign_id).unwrap(), original_entry);

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: ecdh_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let replacement_pubkey = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(replacement_pubkey.len(), 65);

    let stale_by_id = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id),
            payload: SignPayload::Message(Zeroizing::new(
                b"stale metadata should reject mismatched replacement".to_vec(),
            )),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(stale_by_id.contains("registry says sign but persistent handle contains ecdh object"));

    let ecdh_by_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(ecdh_id),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(replacement_pubkey, ecdh_by_id);
}

#[test]
fn simulator_force_replacement_allows_manual_evict_of_replacement_only() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0041).unwrap();
    let first_id = RegistryId::new("sim/keygen/force-evict-first").unwrap();
    let second_id = RegistryId::new("sim/keygen/force-evict-second").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: first_id,
        persist_at: Some(handle),
        force: initial_persistent_force(),
    }
    .execute_with_store(&store)
    .unwrap();
    let first_public = api::pubkey(
        &ApiContext {
            store: StoreOptions {
                root: Some(temp_store.path().to_path_buf()),
            },
            tcti: None,
        },
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: second_id,
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_store(&store)
    .unwrap();
    let mut tpm_context = tpmctl_core::tpm::create_context().unwrap();
    let replacement_object = tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle)
        .expect("force replacement should leave replacement object persistent");
    let (replacement_public, _, _) =
        tpmctl_core::tpm::read_public(&mut tpm_context, replacement_object).unwrap();
    let replacement_descriptor = tpmctl_core::tpm::descriptor_from_tpm_public(
        ObjectSelector::Handle(handle),
        replacement_public,
    )
    .unwrap();
    assert_ne!(
        first_public,
        replacement_descriptor.public_key.unwrap().sec1(),
        "force replacement should evict old object and expose replacement public key"
    );

    tpmctl_core::tpm::evict_persistent_object(&mut tpm_context, replacement_object, handle)
        .expect("replacement object should be evictable after force replacement");
    assert!(
        tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle).is_err(),
        "evicting replacement should clean up the persistent handle"
    );
}

#[test]
fn simulator_native_sign_rejects_invalid_digest_before_handle_lookup() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_004d).unwrap();

    let error = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Digest(Zeroizing::new(vec![0x11; 31])),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute_with_store_and_context(&store, &simulator_command_context(temp_store.path()))
    .unwrap_err();

    assert!(
        matches!(
            error,
            tpmctl_core::Error::InvalidInput {
                field: "digest",
                ..
            }
        ),
        "expected digest validation error before handle lookup, got {error:?}"
    );
}

#[test]
fn simulator_native_sign_by_handle_rejects_ecdh_key_usage() {
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
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_004e).unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: RegistryId::new("sim/negative/ecdh-handle-key").unwrap(),
            persist_at: Some(handle),
            overwrite: allow_external_tcti(),
        },
    )
    .unwrap();

    let error = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(Zeroizing::new(b"ecdh handle should not sign".to_vec())),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute_with_store_and_context(&store, &simulator_command_context(temp_store.path()))
    .unwrap_err()
    .to_string();
    assert!(error.contains("expected sign object, got ecdh"));
}

#[test]
fn simulator_native_sign_by_handle_rejects_vacant_persistent_handle() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_004f).unwrap();

    let error = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(Zeroizing::new(b"vacant handle should fail".to_vec())),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute_with_store_and_context(&store, &simulator_command_context(temp_store.path()))
    .unwrap_err();
    assert!(matches!(error, tpmctl_core::Error::Tpm { .. }));
}

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
fn simulator_persistent_sign_handle_overwrite_diverges_between_pubkey_and_sign_by_id() {
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
    let handle = PersistentHandle::new(0x8101_0046).unwrap();
    let first_id = RegistryId::new("sim/api/persistent-sign-overwrite/first").unwrap();
    let second_id = RegistryId::new("sim/api/persistent-sign-overwrite/second").unwrap();
    let message = Zeroizing::new(b"persistent sign overwrite divergence".to_vec());

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: first_id.clone(),
            persist_at: Some(handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();

    let first_pubkey_by_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(first_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let first_pubkey_by_handle = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(first_pubkey_by_id, first_pubkey_by_handle);

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: second_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let stale_pubkey_by_first_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(first_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let replacement_pubkey_by_second_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(second_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let replacement_pubkey_by_handle = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();

    assert_eq!(stale_pubkey_by_first_id, first_pubkey_by_id);
    assert_ne!(replacement_pubkey_by_handle, first_pubkey_by_handle);
    assert_eq!(
        replacement_pubkey_by_second_id,
        replacement_pubkey_by_handle
    );

    let stale_verifying_key = VerifyingKey::from_sec1_bytes(&stale_pubkey_by_first_id).unwrap();
    let replacement_verifying_key =
        VerifyingKey::from_sec1_bytes(&replacement_pubkey_by_handle).unwrap();

    let signature_by_first_id = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(first_id),
            payload: SignPayload::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let signature_by_first_id = P256Signature::from_slice(&signature_by_first_id).unwrap();
    assert!(
        stale_verifying_key
            .verify(message.as_slice(), &signature_by_first_id)
            .is_err(),
        "sign by stale id should not match the stale registry pubkey after handle overwrite"
    );
    replacement_verifying_key
        .verify(message.as_slice(), &signature_by_first_id)
        .expect("sign by stale id should resolve through the overwritten persistent handle");

    let signature_by_handle = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Handle(handle),
            payload: SignPayload::Message(message),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let signature_by_handle = P256Signature::from_slice(&signature_by_handle).unwrap();
    replacement_verifying_key
        .verify(
            b"persistent sign overwrite divergence",
            &signature_by_handle,
        )
        .unwrap();

    cleanup_persistent_handle(handle);
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

#[test]
fn simulator_native_sign_request_survives_cross_context_reload_and_handle_replacement() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0050).unwrap();
    let first_id = RegistryId::new("sim/native/sign/first").unwrap();
    let second_id = RegistryId::new("sim/native/sign/second").unwrap();
    let message = Zeroizing::new(b"native sign request reload semantics".to_vec());
    let digest = Zeroizing::new(Sha256::digest(message.as_slice()).to_vec());

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: first_id.clone(),
        persist_at: Some(handle),
        force: initial_persistent_force(),
    }
    .execute_with_context(&command)
    .unwrap();

    let first_public_by_id = PubkeyRequest {
        selector: ObjectSelector::Id(first_id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&command)
    .unwrap();
    let first_public_by_handle = PubkeyRequest {
        selector: ObjectSelector::Handle(handle),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(first_public_by_id, first_public_by_handle);
    let first_verifying_key = VerifyingKey::from_sec1_bytes(&first_public_by_handle).unwrap();

    let first_raw_signature = SignRequest {
        selector: ObjectSelector::Id(first_id.clone()),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute_with_context(&command)
    .unwrap();
    let first_raw_signature = decode_p256_signature(&first_raw_signature, SignatureFormat::Raw);
    first_verifying_key
        .verify(message.as_slice(), &first_raw_signature)
        .unwrap();

    let reloaded_command = simulator_command_context(temp_store.path());
    let first_hex_signature = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Hex,
    }
    .execute_with_context(&reloaded_command)
    .unwrap();
    let first_hex_signature = decode_p256_signature(&first_hex_signature, SignatureFormat::Hex);
    first_verifying_key
        .verify(message.as_slice(), &first_hex_signature)
        .unwrap();

    let first_der_signature = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Digest(digest.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Der,
    }
    .execute_with_context(&reloaded_command)
    .unwrap();
    let first_der_signature = decode_p256_signature(&first_der_signature, SignatureFormat::Der);
    first_verifying_key
        .verify_prehash(digest.as_slice(), &first_der_signature)
        .unwrap();

    for _ in 0..3 {
        let repeated_command = simulator_command_context(temp_store.path());
        let repeated_signature = SignRequest {
            selector: ObjectSelector::Handle(handle),
            input: SignInput::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        }
        .execute_with_context(&repeated_command)
        .unwrap();
        let repeated_signature = decode_p256_signature(&repeated_signature, SignatureFormat::Raw);
        first_verifying_key
            .verify(message.as_slice(), &repeated_signature)
            .unwrap();
    }

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: second_id.clone(),
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_context(&reloaded_command)
    .unwrap();

    let post_replacement_command = simulator_command_context(temp_store.path());
    let stale_public_by_first_id = PubkeyRequest {
        selector: ObjectSelector::Id(first_id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();
    let replacement_public_by_second_id = PubkeyRequest {
        selector: ObjectSelector::Id(second_id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();
    let replacement_public_by_handle = PubkeyRequest {
        selector: ObjectSelector::Handle(handle),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();

    assert_eq!(stale_public_by_first_id, first_public_by_id);
    assert_ne!(replacement_public_by_handle, first_public_by_handle);
    assert_eq!(
        replacement_public_by_second_id,
        replacement_public_by_handle
    );

    let replacement_verifying_key =
        VerifyingKey::from_sec1_bytes(&replacement_public_by_handle).unwrap();
    let signature_by_stale_id = SignRequest {
        selector: ObjectSelector::Id(first_id),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();
    let signature_by_stale_id = decode_p256_signature(&signature_by_stale_id, SignatureFormat::Raw);
    assert!(
        first_verifying_key
            .verify(message.as_slice(), &signature_by_stale_id)
            .is_err(),
        "sign by stale id should no longer validate against the stale cached pubkey"
    );
    replacement_verifying_key
        .verify(message.as_slice(), &signature_by_stale_id)
        .unwrap();

    let signature_by_handle = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Digest(digest),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Der,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();
    let signature_by_handle = decode_p256_signature(&signature_by_handle, SignatureFormat::Der);
    let replacement_digest = Sha256::digest(message.as_slice());
    replacement_verifying_key
        .verify_prehash(replacement_digest.as_ref(), &signature_by_handle)
        .unwrap();

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_native_sign_request_hash_and_format_matrix_verifies_with_exported_public_key() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let reloaded_command = simulator_command_context(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0053).unwrap();
    let sign_id = RegistryId::new("sim/native/sign/hash-format-matrix").unwrap();
    let message = Zeroizing::new(b"native sign hash and format matrix".to_vec());

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: sign_id.clone(),
        persist_at: Some(handle),
        force: initial_persistent_force(),
    }
    .execute_with_context(&command)
    .unwrap();

    let public_by_id = PubkeyRequest {
        selector: ObjectSelector::Id(sign_id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&command)
    .unwrap();
    let public_by_handle = PubkeyRequest {
        selector: ObjectSelector::Handle(handle),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&reloaded_command)
    .unwrap();
    assert_eq!(public_by_id, public_by_handle);

    let verifying_key = VerifyingKey::from_sec1_bytes(&public_by_id).unwrap();
    let hashes = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ];
    let formats = [
        SignatureFormat::Raw,
        SignatureFormat::Hex,
        SignatureFormat::Der,
    ];

    for (hash_index, hash) in hashes.into_iter().enumerate() {
        let digest = Zeroizing::new(hash.digest(message.as_slice()));

        for (format_index, format) in formats.into_iter().enumerate() {
            let use_id_for_message = (hash_index + format_index) % 2 == 0;
            let (message_selector, message_command, digest_selector, digest_command) =
                if use_id_for_message {
                    (
                        ObjectSelector::Id(sign_id.clone()),
                        &command,
                        ObjectSelector::Handle(handle),
                        &reloaded_command,
                    )
                } else {
                    (
                        ObjectSelector::Handle(handle),
                        &reloaded_command,
                        ObjectSelector::Id(sign_id.clone()),
                        &command,
                    )
                };

            let message_signature = SignRequest {
                selector: message_selector,
                input: SignInput::Message(message.clone()),
                hash,
                output_format: format,
            }
            .execute_with_context(message_command)
            .unwrap();
            match format {
                SignatureFormat::Raw => assert_eq!(message_signature.len(), 64),
                SignatureFormat::Hex => assert_eq!(message_signature.len(), 128),
                SignatureFormat::Der => assert_eq!(message_signature.first(), Some(&0x30)),
            }
            let message_signature = decode_p256_signature(&message_signature, format);
            verifying_key
                .verify_prehash(digest.as_slice(), &message_signature)
                .unwrap();

            let digest_signature = SignRequest {
                selector: digest_selector,
                input: SignInput::Digest(digest.clone()),
                hash,
                output_format: format,
            }
            .execute_with_context(digest_command)
            .unwrap();
            match format {
                SignatureFormat::Raw => assert_eq!(digest_signature.len(), 64),
                SignatureFormat::Hex => assert_eq!(digest_signature.len(), 128),
                SignatureFormat::Der => assert_eq!(digest_signature.first(), Some(&0x30)),
            }
            let digest_signature = decode_p256_signature(&digest_signature, format);
            verifying_key
                .verify_prehash(digest.as_slice(), &digest_signature)
                .unwrap();
        }
    }

    cleanup_persistent_handle(handle);
}
