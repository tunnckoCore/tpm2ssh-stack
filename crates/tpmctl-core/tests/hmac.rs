mod support;

use support::*;

#[test]
fn simulator_api_hmac_seal_target_seals_and_emits_prf() {
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
    let hmac_id = RegistryId::new("sim/api/hmac-seal-target/key").unwrap();
    let sealed_id = RegistryId::new("sim/api/hmac-seal-target/prf").unwrap();
    let input = Zeroizing::new(b"seal target integration input".to_vec());

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

    let sealed = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input,
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: Some(SealTarget::Id(sealed_id.clone())),
            emit_prf_when_sealing: true,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::SealedWithOutput {
        target,
        hash,
        output: expected_prf,
    } = sealed
    else {
        panic!("expected sealed HMAC output")
    };
    assert_eq!(target, SealTarget::Id(sealed_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);
    assert_eq!(expected_prf.len(), HashAlgorithm::Sha256.digest_len());

    let unsealed_prf = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed_prf.as_slice(), expected_prf.as_slice());
}

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

#[test]
fn simulator_hmac_rejects_input_larger_than_tpm_one_shot_limit() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let hmac_id = RegistryId::new("sim/native/hmac/oversize-input").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let oversized_input = vec![0x41; tss_esapi::structures::MaxBuffer::MAX_SIZE + 1];
    let error = HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(oversized_input),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err()
    .to_string();
    assert!(error.contains("HMAC input is too large for TPM2_HMAC one-shot"));
}

#[test]
fn simulator_hmac_handle_targets_reject_wrong_usage_and_support_sealed_handle_overwrite() {
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
    let command = simulator_command_context(temp_store.path());
    let hmac_id = RegistryId::new("sim/native/hmac/sealed-handle/key").unwrap();
    let sign_id = RegistryId::new("sim/native/hmac/wrong-sign-handle").unwrap();
    let hmac_handle = PersistentHandle::new(0x8101_0055).unwrap();
    let sign_handle = PersistentHandle::new(0x8101_0056).unwrap();
    let sealed_handle = PersistentHandle::new(0x8101_0057).unwrap();
    let first_input = b"first sealed handle hmac input".to_vec();
    let second_input = b"second sealed handle hmac input".to_vec();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: Some(hmac_handle),
            overwrite: allow_external_tcti(),
        },
    )
    .unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id,
            persist_at: Some(sign_handle),
            overwrite: allow_external_tcti(),
        },
    )
    .unwrap();

    let sign_handle_error = HmacRequest {
        selector: ObjectSelector::Handle(sign_handle),
        input: Zeroizing::new(b"sign handle should not hmac".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err()
    .to_string();
    assert!(
        sign_handle_error.contains("object is not a keyed-hash HMAC key or sealed data object")
    );

    let first_expected = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Handle(hmac_handle),
            input: Zeroizing::new(first_input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );

    let first_sealed = HmacRequest {
        selector: ObjectSelector::Id(hmac_id.clone()),
        input: Zeroizing::new(first_input.clone()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Handle(sealed_handle)),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();
    let HmacResult::Sealed { target, hash } = first_sealed else {
        panic!("expected sealed result for handle target")
    };
    assert_eq!(target, SealTarget::Handle(sealed_handle));
    assert_eq!(hash, HashAlgorithm::Sha256);

    let unsealed_first = UnsealRequest {
        selector: ObjectSelector::Handle(sealed_handle),
        force_binary_stdout: true,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(unsealed_first.as_slice(), first_expected.as_slice());

    let sealed_handle_error = HmacRequest {
        selector: ObjectSelector::Handle(sealed_handle),
        input: Zeroizing::new(b"sealed handle should not hmac".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err()
    .to_string();
    assert!(sealed_handle_error.contains("expected hmac object, got sealed"));

    let overwrite_error = HmacRequest {
        selector: ObjectSelector::Id(hmac_id.clone()),
        input: Zeroizing::new(second_input.clone()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Handle(sealed_handle)),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err()
    .to_string();
    assert!(overwrite_error.contains("already exists"));

    let still_unsealed_first = UnsealRequest {
        selector: ObjectSelector::Handle(sealed_handle),
        force_binary_stdout: true,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(still_unsealed_first.as_slice(), first_expected.as_slice());

    let second_expected = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(second_input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );

    let replaced = HmacRequest {
        selector: ObjectSelector::Handle(hmac_handle),
        input: Zeroizing::new(second_input),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Hex,
        seal_target: Some(SealTarget::Handle(sealed_handle)),
        emit_prf_when_sealing: true,
        force: true,
    }
    .execute_with_context(&command)
    .unwrap();
    let HmacResult::SealedWithOutput {
        target,
        hash,
        output,
    } = replaced
    else {
        panic!("expected sealed output for forced handle overwrite")
    };
    assert_eq!(target, SealTarget::Handle(sealed_handle));
    assert_eq!(hash, HashAlgorithm::Sha256);
    assert_eq!(hex::decode(&output).unwrap(), second_expected.as_slice());

    let unsealed_second = UnsealRequest {
        selector: ObjectSelector::Handle(sealed_handle),
        force_binary_stdout: true,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(unsealed_second.as_slice(), second_expected.as_slice());
}

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
