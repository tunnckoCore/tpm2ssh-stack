use super::support::*;

#[test]
fn simulator_native_hmac_request_hash_matrix_covers_descriptor_and_global_defaults() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let reloaded_command = simulator_command_context(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0054).unwrap();
    let hmac_id = RegistryId::new("sim/native/hmac/hash-matrix").unwrap();
    let sealed_default_id = RegistryId::new("sim/native/hmac/hash-matrix/default-sealed").unwrap();
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

    let sealed_default = HmacRequest {
        selector: ObjectSelector::Handle(handle),
        input: Zeroizing::new(input.clone()),
        hash: None,
        output_format: BinaryFormat::Hex,
        seal_target: Some(SealTarget::Id(sealed_default_id.clone())),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&reloaded_command)
    .unwrap();
    let HmacResult::Sealed { target, hash } = sealed_default else {
        panic!("expected sealed HMAC result without emitted PRF bytes")
    };
    assert_eq!(target, SealTarget::Id(sealed_default_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);

    let unsealed_default = UnsealRequest {
        selector: ObjectSelector::Id(sealed_default_id),
        force_binary_stdout: true,
    }
    .execute_with_context(&simulator_command_context(temp_store.path()))
    .unwrap();
    assert_eq!(unsealed_default.as_slice(), default_by_id.as_slice());

    for (index, hash) in [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ]
    .into_iter()
    .enumerate()
    {
        let (raw_selector, raw_command, hex_selector, hex_command) = if index % 2 == 0 {
            (
                ObjectSelector::Id(hmac_id.clone()),
                &command,
                ObjectSelector::Handle(handle),
                &reloaded_command,
            )
        } else {
            (
                ObjectSelector::Handle(handle),
                &reloaded_command,
                ObjectSelector::Id(hmac_id.clone()),
                &command,
            )
        };

        match hash {
            HashAlgorithm::Sha256 => {
                let raw_output = expect_hmac_output(
                    HmacRequest {
                        selector: raw_selector,
                        input: Zeroizing::new(input.clone()),
                        hash: Some(hash),
                        output_format: BinaryFormat::Raw,
                        seal_target: None,
                        emit_prf_when_sealing: false,
                        force: false,
                    }
                    .execute_with_context(raw_command)
                    .unwrap(),
                );
                assert_eq!(raw_output.len(), hash.digest_len());

                let hex_output = expect_hmac_output(
                    HmacRequest {
                        selector: hex_selector,
                        input: Zeroizing::new(input.clone()),
                        hash: Some(hash),
                        output_format: BinaryFormat::Hex,
                        seal_target: None,
                        emit_prf_when_sealing: false,
                        force: false,
                    }
                    .execute_with_context(hex_command)
                    .unwrap(),
                );
                assert_eq!(hex::decode(&hex_output).unwrap(), raw_output.as_slice());
                assert_eq!(raw_output.as_slice(), default_by_id.as_slice());
            }
            HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => {
                let raw_error = HmacRequest {
                    selector: raw_selector,
                    input: Zeroizing::new(input.clone()),
                    hash: Some(hash),
                    output_format: BinaryFormat::Raw,
                    seal_target: None,
                    emit_prf_when_sealing: false,
                    force: false,
                }
                .execute_with_context(raw_command)
                .unwrap_err();
                assert!(matches!(
                    raw_error,
                    tpmctl_core::Error::Tpm {
                        operation: "HMAC",
                        ..
                    }
                ));

                let hex_error = HmacRequest {
                    selector: hex_selector,
                    input: Zeroizing::new(input.clone()),
                    hash: Some(hash),
                    output_format: BinaryFormat::Hex,
                    seal_target: None,
                    emit_prf_when_sealing: false,
                    force: false,
                }
                .execute_with_context(hex_command)
                .unwrap_err();
                assert!(matches!(
                    hex_error,
                    tpmctl_core::Error::Tpm {
                        operation: "HMAC",
                        ..
                    }
                ));
            }
        }
    }

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
    let sealed_id = RegistryId::new("sim/native/hmac/sealed-output").unwrap();
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
    assert_eq!(first_raw_output.len(), HashAlgorithm::Sha256.digest_len());

    let reloaded_command = simulator_command_context(temp_store.path());
    let first_hex_output = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Hex,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&reloaded_command)
        .unwrap(),
    );
    assert_eq!(
        hex::decode(&first_hex_output).unwrap(),
        first_raw_output.as_slice()
    );

    for _ in 0..3 {
        let repeated_command = simulator_command_context(temp_store.path());
        let repeated_output = expect_hmac_output(
            HmacRequest {
                selector: ObjectSelector::Handle(handle),
                input: Zeroizing::new(input.clone()),
                hash: Some(HashAlgorithm::Sha256),
                output_format: BinaryFormat::Raw,
                seal_target: None,
                emit_prf_when_sealing: false,
                force: false,
            }
            .execute_with_context(&repeated_command)
            .unwrap(),
        );
        assert_eq!(repeated_output, first_raw_output);
    }

    let sealed_output = HmacRequest {
        selector: ObjectSelector::Handle(handle),
        input: Zeroizing::new(input.clone()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Hex,
        seal_target: Some(SealTarget::Id(sealed_id.clone())),
        emit_prf_when_sealing: true,
        force: false,
    }
    .execute_with_context(&reloaded_command)
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
    assert_eq!(hex::decode(&output).unwrap(), first_raw_output.as_slice());

    let unsealed = UnsealRequest {
        selector: ObjectSelector::Id(sealed_id),
        force_binary_stdout: true,
    }
    .execute_with_context(&simulator_command_context(temp_store.path()))
    .unwrap();
    assert_eq!(unsealed.as_slice(), first_raw_output.as_slice());

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: second_id.clone(),
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_context(&reloaded_command)
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
