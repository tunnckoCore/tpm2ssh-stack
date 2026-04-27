use super::support::*;

#[test]
fn simulator_persistent_hmac_handle_survives_reload_and_force_replaces_handle_binding_only() {
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
    let handle = PersistentHandle::new(0x8101_0043).unwrap();
    let first_id = RegistryId::new("sim/api/persistent-hmac-handle/first").unwrap();
    let second_id = RegistryId::new("sim/api/persistent-hmac-handle/second").unwrap();
    let input = b"persistent hmac simulator input".to_vec();

    let first = api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: first_id.clone(),
            persist_at: Some(handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();
    assert_eq!(first.persistent_handle, Some(handle));

    let stored = store.load_key(&first_id).unwrap();
    assert_eq!(stored.record.handle.as_deref(), Some("0x81010043"));
    assert!(stored.record.persistent);

    let by_id = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(first_id.clone()),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(by_id) = by_id else {
        panic!("expected raw HMAC output by id")
    };

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let by_handle = api::hmac(
        &reloaded_context,
        HmacParams {
            material: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(by_handle) = by_handle else {
        panic!("expected raw HMAC output by handle")
    };
    assert_eq!(by_id, by_handle);

    api::keygen(
        &reloaded_context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: second_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let replaced = api::hmac(
        &reloaded_context,
        HmacParams {
            material: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(replaced) = replaced else {
        panic!("expected replacement HMAC output by handle")
    };
    assert_ne!(replaced, by_handle);

    let original_by_id = api::hmac(
        &reloaded_context,
        HmacParams {
            material: ObjectSelector::Id(first_id),
            input: Zeroizing::new(input),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(original_by_id) = original_by_id else {
        panic!("expected original HMAC output by id after handle replacement")
    };
    assert_eq!(original_by_id, by_handle);
    assert_ne!(original_by_id, replaced);

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_hmac_supports_cross_context_reload_hex_output_and_sealed_roundtrip() {
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
    let handle = PersistentHandle::new(0x8101_0048).unwrap();
    let hmac_id = RegistryId::new("sim/api/hmac/formats-and-reload").unwrap();
    let sealed_id = RegistryId::new("sim/api/hmac/formats-and-reload/sealed").unwrap();
    let input = b"simulator hmac output format coverage".to_vec();

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

    let raw_output = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id.clone()),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(raw_output) = raw_output else {
        panic!("expected raw HMAC output")
    };
    assert_eq!(raw_output.len(), HashAlgorithm::Sha256.digest_len());

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let hex_output = api::hmac(
        &reloaded_context,
        HmacParams {
            material: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Hex,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(hex_output) = hex_output else {
        panic!("expected hex HMAC output")
    };
    assert_eq!(hex_output.len(), raw_output.len() * 2);
    assert_eq!(hex::decode(&hex_output).unwrap(), raw_output.as_slice());

    let repeated_raw_output = api::hmac(
        &reloaded_context,
        HmacParams {
            material: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(repeated_raw_output) = repeated_raw_output else {
        panic!("expected repeated raw HMAC output")
    };
    assert_eq!(repeated_raw_output, raw_output);

    let sealed_output = api::hmac(
        &reloaded_context,
        HmacParams {
            material: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Hex,
            seal_target: Some(SealTarget::Id(sealed_id.clone())),
            emit_prf_when_sealing: true,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::SealedWithOutput {
        target,
        hash,
        output,
    } = sealed_output
    else {
        panic!("expected sealed HMAC output")
    };
    assert_eq!(target, SealTarget::Id(sealed_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);
    assert_eq!(hex::decode(&output).unwrap(), raw_output.as_slice());

    let unsealed = api::unseal(
        &reloaded_context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), raw_output.as_slice());

    cleanup_persistent_handle(handle);
}
