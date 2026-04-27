use super::support::*;

#[test]
fn simulator_api_unseal_by_id_rejects_missing_registry_entry() {
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

    let error = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(RegistryId::new("sim/api/unseal/missing").unwrap()),
        },
    )
    .unwrap_err();
    assert!(matches!(error, tpmctl_core::Error::NotFound(_)));
}

#[test]
fn simulator_api_unseal_by_handle_rejects_vacant_persistent_handle() {
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
    let handle = PersistentHandle::new(0x8101_0063).unwrap();
    cleanup_persistent_handle(handle);

    let error = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Handle(handle),
        },
    )
    .unwrap_err();
    assert!(matches!(error, tpmctl_core::Error::Tpm { .. }));
}

#[test]
fn simulator_api_unseal_rejects_hmac_handle_with_expected_usage_error() {
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
    let hmac_handle = PersistentHandle::new(0x8101_0062).unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: RegistryId::new("sim/api/unseal-wrong-usage/hmac-handle").unwrap(),
            persist_at: Some(hmac_handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();

    let error = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Handle(hmac_handle),
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("expected sealed object, got hmac"));
}

#[test]
fn simulator_api_rejects_wrong_selector_kinds_and_wrong_usages() {
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

    let sign_id = RegistryId::new("sim/negative/api-misuse/sign").unwrap();
    let hmac_id = RegistryId::new("sim/negative/api-misuse/hmac").unwrap();
    let ecdh_id = RegistryId::new("sim/negative/api-misuse/ecdh").unwrap();
    let sealed_id = RegistryId::new("sim/negative/api-misuse/sealed").unwrap();
    let hmac_handle = PersistentHandle::new(0x8101_0043).unwrap();
    let sign_handle = PersistentHandle::new(0x8101_0045).unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id.clone(),
            persist_at: Some(sign_handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: Some(hmac_handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: ecdh_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"sealed misuse secret".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();
    let sign_with_hmac = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Handle(hmac_handle),
            payload: SignPayload::Message(Zeroizing::new(b"wrong usage sign".to_vec())),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(sign_with_hmac.contains("expected sign object, got hmac"));

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

    let ecdh_with_sign = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(sign_id.clone()),
            peer_public_key: PublicKeyInput::Sec1(
                SecretKey::from_slice(&[0x24; 32])
                    .unwrap()
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            ),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(ecdh_with_sign.contains("expected ecdh object, got sign"));

    let unseal_sign_key = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Handle(sign_handle),
        },
    )
    .unwrap_err()
    .to_string();
    assert!(unseal_sign_key.contains("object is not a keyed-hash HMAC key or sealed data object"));

    let pubkey_from_hmac_handle = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(hmac_handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(pubkey_from_hmac_handle.contains("cannot export a public key for hmac objects"));

    let pubkey_from_sealed_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(sealed_id),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap_err();
    assert!(matches!(
        pubkey_from_sealed_id,
        tpmctl_core::Error::NotFound(_)
    ));

    let ecdh_pubkey = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(ecdh_id),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(ecdh_pubkey.len(), 65);
}
