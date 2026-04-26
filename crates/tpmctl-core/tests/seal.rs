mod support;

use support::*;

#[test]
fn simulator_seal_rejects_existing_registry_target_without_overwrite_and_preserves_original() {
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
    let sealed_id = RegistryId::new("sim/negative/sealed-duplicate").unwrap();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"first sealed secret".to_vec()),
            overwrite: true,
        },
    )
    .unwrap();

    let store = Store::new(temp_store.path());
    let original_entry = store.load_sealed(&sealed_id).unwrap();

    let duplicate = api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"second sealed secret".to_vec()),
            overwrite: false,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(duplicate.contains("already exists"));

    let preserved_entry = store.load_sealed(&sealed_id).unwrap();
    assert_eq!(preserved_entry, original_entry);

    let unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), b"first sealed secret");
}

#[test]
fn simulator_api_seal_then_unseal_roundtrips_exact_bytes() {
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
    let sealed_id = RegistryId::new("sim/api/seal-roundtrip/exact-bytes").unwrap();
    let expected = Zeroizing::new(vec![0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, b's', b'e', 0x00]);

    let sealed = api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: expected.clone(),
            overwrite: false,
        },
    )
    .unwrap();
    assert_eq!(sealed.selector, ObjectSelector::Id(sealed_id.clone()));
    assert_eq!(sealed.hash, None);

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let unsealed = api::unseal(
        &reloaded_context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), expected.as_slice());
}

#[test]
fn simulator_api_seal_overwrite_replaces_unsealed_value() {
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
    let sealed_id = RegistryId::new("sim/api/seal-overwrite/replaced-value").unwrap();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"first sealed bytes".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();
    let first_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id.clone()),
        },
    )
    .unwrap();
    assert_eq!(first_unsealed.as_slice(), b"first sealed bytes");

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"second sealed bytes".to_vec()),
            overwrite: true,
        },
    )
    .unwrap();
    let replaced_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(replaced_unsealed.as_slice(), b"second sealed bytes");
    assert_ne!(replaced_unsealed.as_slice(), first_unsealed.as_slice());
}

#[test]
fn simulator_api_seal_hmac_output_then_unseal_matches_exact_bytes() {
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
    let hmac_id = RegistryId::new("sim/api/seal-hmac-output/key").unwrap();
    let sealed_id = RegistryId::new("sim/api/seal-hmac-output/sealed-prf").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let expected_hmac = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(b"seal raw hmac bytes".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(expected_hmac) = expected_hmac else {
        panic!("expected raw HMAC output")
    };
    assert_eq!(expected_hmac.len(), HashAlgorithm::Sha256.digest_len());

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: expected_hmac.clone(),
            overwrite: false,
        },
    )
    .unwrap();

    let unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), expected_hmac.as_slice());
}

#[test]
fn simulator_api_unseal_by_id_is_stable_across_repeated_calls() {
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
    let sealed_id = RegistryId::new("sim/api/unseal-repeat/stable-id").unwrap();
    let expected = b"repeatable unseal bytes".to_vec();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(expected.clone()),
            overwrite: false,
        },
    )
    .unwrap();

    let first = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id.clone()),
        },
    )
    .unwrap();
    let second = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id.clone()),
        },
    )
    .unwrap();
    let third = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();

    assert_eq!(first.as_slice(), expected.as_slice());
    assert_eq!(second.as_slice(), expected.as_slice());
    assert_eq!(third.as_slice(), expected.as_slice());
    assert_eq!(first, second);
    assert_eq!(second, third);
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

#[test]
fn simulator_api_facade_keygen_pubkey_sign_hmac_seal_and_ecdh_roundtrip() {
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

    let sign_id = RegistryId::new("sim/api/sign").unwrap();
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

    let message = Zeroizing::new(b"api facade simulator signing".to_vec());
    let signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id),
            payload: SignPayload::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let signature = P256Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();

    let hmac_id = RegistryId::new("sim/api/hmac").unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();
    let hmac = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(b"context".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(mac) = hmac else {
        panic!("expected HMAC output")
    };
    assert_eq!(mac.len(), HashAlgorithm::Sha256.digest_len());

    let sealed_id = RegistryId::new("sim/api/sealed").unwrap();
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"sealed secret".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();
    let unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), b"sealed secret");

    let ecdh_id = RegistryId::new("sim/api/ecdh").unwrap();
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
    let shared_secret = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(ecdh_id),
            peer_public_key: PublicKeyInput::Sec1(public_sec1),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(shared_secret.len(), 32);
}

#[test]
fn simulator_api_seal_handle_selector_and_overwrite_preserve_then_replace_unsealed_bytes() {
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
    let handle = PersistentHandle::new(0x8101_0049).unwrap();
    cleanup_persistent_handle(handle);

    let first = Zeroizing::new(vec![
        0x00, 0x10, 0x20, 0x30, b'h', b'a', b'n', b'd', b'l', b'e',
    ]);
    let first_result = api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Handle(handle),
            input: first.clone(),
            overwrite: false,
        },
    )
    .unwrap();
    assert_eq!(first_result.selector, ObjectSelector::Handle(handle));
    assert_eq!(first_result.hash, None);
    assert!(
        !temp_store.path().join("sealed").exists(),
        "sealing to a persistent handle should not create registry-backed sealed entries"
    );

    let first_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Handle(handle),
        },
    )
    .unwrap();
    assert_eq!(first_unsealed.as_slice(), first.as_slice());

    let duplicate_error = api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Handle(handle),
            input: Zeroizing::new(b"second handle sealed bytes".to_vec()),
            overwrite: false,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(duplicate_error.contains("already exists"));

    let preserved_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Handle(handle),
        },
    )
    .unwrap();
    assert_eq!(preserved_unsealed.as_slice(), first.as_slice());

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Handle(handle),
            input: Zeroizing::new(b"replacement handle sealed bytes".to_vec()),
            overwrite: true,
        },
    )
    .unwrap();

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let replaced_unsealed = api::unseal(
        &reloaded_context,
        UnsealParams {
            material: ObjectSelector::Handle(handle),
        },
    )
    .unwrap();
    assert_eq!(
        replaced_unsealed.as_slice(),
        b"replacement handle sealed bytes"
    );
    assert_ne!(replaced_unsealed.as_slice(), first.as_slice());
    assert!(
        !temp_store.path().join("sealed").exists(),
        "overwriting a persistent sealed handle should not create registry-backed sealed entries"
    );

    cleanup_persistent_handle(handle);
}
