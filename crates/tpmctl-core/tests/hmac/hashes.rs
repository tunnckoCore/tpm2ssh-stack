use super::support::*;

#[test]
fn simulator_native_hmac_hash_none_defaults_to_sha256_across_id_handle_and_seal_paths() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let reloaded_command = simulator_command_context(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0054).unwrap();
    let hmac_id = RegistryId::new("sim/native/hmac/hash-matrix").unwrap();
    let sealed_id = RegistryId::new("sim/native/hmac/hash-matrix/default-sealed").unwrap();
    let input = b"native hmac hash matrix".to_vec();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: Some(handle),
        force: initial_persistent_force(),
    }
    .execute_with_context(&command)
    .unwrap();

    let default_by_id = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id.clone()),
            input: Zeroizing::new(input.clone()),
            hash: None,
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );
    assert_eq!(default_by_id.len(), HashAlgorithm::Sha256.digest_len());

    let default_by_handle_hex = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: None,
            output_format: BinaryFormat::Hex,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&reloaded_command)
        .unwrap(),
    );
    assert_eq!(
        hex::decode(&default_by_handle_hex).unwrap(),
        default_by_id.as_slice()
    );

    let sealed = HmacRequest {
        selector: ObjectSelector::Handle(handle),
        input: Zeroizing::new(input),
        hash: None,
        output_format: BinaryFormat::Hex,
        seal_target: Some(SealTarget::Id(sealed_id.clone())),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&reloaded_command)
    .unwrap();
    let HmacResult::Sealed { target, hash } = sealed else {
        panic!("expected sealed HMAC result without emitted PRF bytes")
    };
    assert_eq!(target, SealTarget::Id(sealed_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);

    let unsealed = UnsealRequest {
        selector: ObjectSelector::Id(sealed_id),
        force_binary_stdout: true,
    }
    .execute_with_context(&simulator_command_context(temp_store.path()))
    .unwrap();
    assert_eq!(unsealed.as_slice(), default_by_id.as_slice());

    let unsupported_hash_error = HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(b"sha384 should surface TPM hmac failure".to_vec()),
        hash: Some(HashAlgorithm::Sha384),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err();
    assert!(matches!(
        unsupported_hash_error,
        tpmctl_core::Error::Tpm {
            operation: "HMAC",
            ..
        }
    ));

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_native_hmac_request_survives_cross_context_reload_and_force_replacement() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0051).unwrap();
    let first_id = RegistryId::new("sim/native/hmac/first").unwrap();
    let second_id = RegistryId::new("sim/native/hmac/second").unwrap();
    let input = b"native hmac request reload semantics".to_vec();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: first_id.clone(),
        persist_at: Some(handle),
        force: initial_persistent_force(),
    }
    .execute_with_context(&command)
    .unwrap();

    let first_raw_output = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(first_id.clone()),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );

    let by_handle_after_reload = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&simulator_command_context(temp_store.path()))
        .unwrap(),
    );
    assert_eq!(by_handle_after_reload, first_raw_output);

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: second_id.clone(),
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_context(&simulator_command_context(temp_store.path()))
    .unwrap();

    let replaced_by_handle = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&simulator_command_context(temp_store.path()))
        .unwrap(),
    );
    assert_ne!(replaced_by_handle, first_raw_output);

    let original_by_first_id = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(first_id),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&simulator_command_context(temp_store.path()))
        .unwrap(),
    );
    let replacement_by_second_id = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(second_id),
            input: Zeroizing::new(input),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&simulator_command_context(temp_store.path()))
        .unwrap(),
    );

    assert_eq!(original_by_first_id, first_raw_output);
    assert_eq!(replacement_by_second_id, replaced_by_handle);
    assert_ne!(original_by_first_id, replaced_by_handle);

    cleanup_persistent_handle(handle);
}
