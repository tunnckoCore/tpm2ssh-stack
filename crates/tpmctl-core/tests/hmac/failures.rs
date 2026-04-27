use super::support::*;

fn handle_target_case() -> (
    tempfile::TempDir,
    ApiContext,
    CommandContext,
    RegistryId,
    PersistentHandle,
    PersistentHandle,
    PersistentHandle,
) {
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

    (
        temp_store,
        context,
        command,
        hmac_id,
        hmac_handle,
        sign_handle,
        sealed_handle,
    )
}

#[test]
fn simulator_hmac_by_handle_rejects_sign_key_handles() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let (_temp_store, _context, command, _hmac_id, _hmac_handle, sign_handle, _sealed_handle) =
        handle_target_case();

    let error = HmacRequest {
        selector: ObjectSelector::Handle(sign_handle),
        input: Zeroizing::new(b"sign handle should not hmac".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err();
    assert!(matches!(
        error,
        tpmctl_core::Error::InvalidInput { field: "usage", .. }
    ));
}

#[test]
fn simulator_hmac_seal_target_handle_roundtrips_output() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let (_temp_store, _context, command, hmac_id, _hmac_handle, _sign_handle, sealed_handle) =
        handle_target_case();
    let input = b"first sealed handle hmac input".to_vec();

    let expected = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id.clone()),
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

    let sealed = HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(input),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Handle(sealed_handle)),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();
    let HmacResult::Sealed { target, hash } = sealed else {
        panic!("expected sealed result for handle target")
    };
    assert_eq!(target, SealTarget::Handle(sealed_handle));
    assert_eq!(hash, HashAlgorithm::Sha256);

    let unsealed = UnsealRequest {
        selector: ObjectSelector::Handle(sealed_handle),
        force_binary_stdout: true,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(unsealed.as_slice(), expected.as_slice());
}

#[test]
fn simulator_hmac_rejects_using_sealed_handle_as_hmac_source() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let (_temp_store, _context, command, hmac_id, _hmac_handle, _sign_handle, sealed_handle) =
        handle_target_case();

    HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(b"first sealed handle hmac input".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Handle(sealed_handle)),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let error = HmacRequest {
        selector: ObjectSelector::Handle(sealed_handle),
        input: Zeroizing::new(b"sealed handle should not hmac".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err();
    assert!(matches!(
        error,
        tpmctl_core::Error::InvalidInput { field: "usage", .. }
    ));
}

#[test]
fn simulator_hmac_seal_target_handle_preserves_existing_value_without_force() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let (_temp_store, _context, command, hmac_id, _hmac_handle, _sign_handle, sealed_handle) =
        handle_target_case();
    let first_input = b"first sealed handle hmac input".to_vec();

    let first_expected = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id.clone()),
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

    HmacRequest {
        selector: ObjectSelector::Id(hmac_id.clone()),
        input: Zeroizing::new(first_input),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Handle(sealed_handle)),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let duplicate_error = HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(b"second sealed handle hmac input".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Handle(sealed_handle)),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err()
    .to_string();
    assert!(duplicate_error.contains("already exists"));

    let preserved = UnsealRequest {
        selector: ObjectSelector::Handle(sealed_handle),
        force_binary_stdout: true,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(preserved.as_slice(), first_expected.as_slice());
}

#[test]
fn simulator_hmac_seal_target_handle_force_replaces_and_emits_output() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let (_temp_store, _context, command, hmac_id, hmac_handle, _sign_handle, sealed_handle) =
        handle_target_case();
    let first_input = b"first sealed handle hmac input".to_vec();
    let second_input = b"second sealed handle hmac input".to_vec();

    HmacRequest {
        selector: ObjectSelector::Id(hmac_id.clone()),
        input: Zeroizing::new(first_input),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Handle(sealed_handle)),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

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

    let unsealed = UnsealRequest {
        selector: ObjectSelector::Handle(sealed_handle),
        force_binary_stdout: true,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(unsealed.as_slice(), second_expected.as_slice());
}

#[test]
fn simulator_hmac_rejects_invalid_tcti_override_before_object_lookup() {
    let request = HmacRequest {
        selector: ObjectSelector::Id(RegistryId::new("sim/native/hmac/invalid-tcti").unwrap()),
        input: Zeroizing::new(b"invalid tcti should fail before lookup".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    };
    let error = request
        .execute_with_context(&CommandContext {
            store: StoreOptions::default(),
            tcti: Some("not-a-valid-tcti".to_owned()),
        })
        .unwrap_err();
    assert!(matches!(error, tpmctl_core::Error::Tcti(_)));
}

#[test]
fn simulator_hmac_execute_uses_default_context_and_surfaces_default_store_failures_when_sealing() {
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
    let hmac_handle = PersistentHandle::new(0x8101_0059).unwrap();
    let hmac_id = RegistryId::new("sim/native/hmac/default-execute/key").unwrap();
    cleanup_persistent_handle(hmac_handle);

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id,
            persist_at: Some(hmac_handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();

    let previous_home = env::var("HOME").ok();
    let previous_xdg_data_home = env::var("XDG_DATA_HOME").ok();
    let previous_store = env::var("TPMCTL_STORE").ok();
    unsafe {
        env::remove_var("HOME");
        env::remove_var("XDG_DATA_HOME");
        env::remove_var("TPMCTL_STORE");
    }

    let result = HmacRequest {
        selector: ObjectSelector::Handle(hmac_handle),
        input: Zeroizing::new(
            b"default execute sealing should hit default store resolution".to_vec(),
        ),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Id(
            RegistryId::new("sim/native/hmac/default-execute/sealed").unwrap(),
        )),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute();

    unsafe {
        if let Some(value) = previous_home {
            env::set_var("HOME", value);
        } else {
            env::remove_var("HOME");
        }
        if let Some(value) = previous_xdg_data_home {
            env::set_var("XDG_DATA_HOME", value);
        } else {
            env::remove_var("XDG_DATA_HOME");
        }
        if let Some(value) = previous_store {
            env::set_var("TPMCTL_STORE", value);
        } else {
            env::remove_var("TPMCTL_STORE");
        }
    }

    cleanup_persistent_handle(hmac_handle);

    let error = result.unwrap_err();
    assert!(matches!(error, tpmctl_core::Error::Config(_)));
    assert!(
        error
            .to_string()
            .contains("HOME must be set when XDG_DATA_HOME and TPMCTL_STORE are unset")
    );
}

#[test]
fn simulator_native_hmac_by_handle_rejects_vacant_persistent_handle() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let vacant_handle = PersistentHandle::new(0x8101_0058).unwrap();
    cleanup_persistent_handle(vacant_handle);

    let error = HmacRequest {
        selector: ObjectSelector::Handle(vacant_handle),
        input: Zeroizing::new(b"vacant handle should not hmac".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err()
    .to_string();
    assert!(error.contains("TR_FromTPMPublic"));
}

#[test]
fn simulator_native_hmac_by_id_rejects_missing_registry_entry() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let missing_id = RegistryId::new("sim/native/hmac/missing-id").unwrap();
    let expected_path = temp_store
        .path()
        .join("keys")
        .join(missing_id.as_relative_path());

    let error = HmacRequest {
        selector: ObjectSelector::Id(missing_id),
        input: Zeroizing::new(b"missing id should fail".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err();
    assert!(matches!(error, tpmctl_core::Error::NotFound(path) if path == expected_path));
}

#[test]
fn simulator_native_hmac_by_id_rejects_non_hmac_registry_entries() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let sign_id = RegistryId::new("sim/native/hmac/wrong-id-kind/sign").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: sign_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let error = HmacRequest {
        selector: ObjectSelector::Id(sign_id),
        input: Zeroizing::new(b"sign id should not hmac".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err();
    assert!(matches!(
        error,
        tpmctl_core::Error::InvalidInput { field: "usage", .. }
    ));
}

#[test]
fn simulator_native_hmac_failure_does_not_create_or_replace_sealed_output() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let hmac_id = RegistryId::new("sim/native/hmac/failure-does-not-seal/key").unwrap();
    let sealed_id = RegistryId::new("sim/native/hmac/failure-does-not-seal/output").unwrap();
    let baseline_input = b"baseline sealed hmac bytes".to_vec();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let baseline = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id.clone()),
            input: Zeroizing::new(baseline_input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );

    let initial_sealed = HmacRequest {
        selector: ObjectSelector::Id(hmac_id.clone()),
        input: Zeroizing::new(baseline_input),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Hex,
        seal_target: Some(SealTarget::Id(sealed_id.clone())),
        emit_prf_when_sealing: true,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();
    let HmacResult::SealedWithOutput {
        target,
        hash,
        output,
    } = initial_sealed
    else {
        panic!("expected sealed baseline output")
    };
    assert_eq!(target, SealTarget::Id(sealed_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);
    assert_eq!(hex::decode(&output).unwrap(), baseline.as_slice());

    let failing_error = HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(b"sha384 hmac should fail before sealing".to_vec()),
        hash: Some(HashAlgorithm::Sha384),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Id(sealed_id.clone())),
        emit_prf_when_sealing: true,
        force: true,
    }
    .execute_with_context(&command)
    .unwrap_err();
    assert!(matches!(
        failing_error,
        tpmctl_core::Error::Tpm {
            operation: "HMAC",
            ..
        }
    ));

    let preserved = UnsealRequest {
        selector: ObjectSelector::Id(sealed_id),
        force_binary_stdout: true,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(preserved.as_slice(), baseline.as_slice());
}
