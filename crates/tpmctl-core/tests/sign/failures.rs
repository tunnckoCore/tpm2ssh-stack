use super::support::*;

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
