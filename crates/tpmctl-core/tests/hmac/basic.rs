use super::support::*;

#[test]
fn simulator_native_hmac_by_id_returns_stable_raw_and_hex_output() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let hmac_id = RegistryId::new("sim/native/hmac/basic-id-success").unwrap();
    let input = b"basic hmac id success case".to_vec();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let raw_output = expect_hmac_output(
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
    assert_eq!(raw_output.len(), HashAlgorithm::Sha256.digest_len());

    let repeated_raw_output = expect_hmac_output(
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
    assert_eq!(repeated_raw_output, raw_output);

    let hex_output = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(input),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Hex,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );
    assert_eq!(hex::decode(&hex_output).unwrap(), raw_output.as_slice());
}

#[test]
fn simulator_native_hmac_by_id_accepts_empty_input() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let hmac_id = RegistryId::new("sim/native/hmac/empty-input").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let raw_output = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id.clone()),
            input: Zeroizing::new(Vec::new()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );
    assert_eq!(raw_output.len(), HashAlgorithm::Sha256.digest_len());

    let hex_output = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(Vec::new()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Hex,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );
    assert_eq!(hex::decode(&hex_output).unwrap(), raw_output.as_slice());
}

#[test]
fn simulator_native_hmac_execute_uses_env_store_successfully() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let hmac_id = RegistryId::new("sim/native/hmac/default-execute-success").unwrap();
    let setup_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };

    api::keygen(
        &setup_context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let previous_store = env::var("TPMCTL_STORE").ok();
    unsafe {
        env::set_var("TPMCTL_STORE", temp_store.path());
    }

    let result = HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(b"default execute should find env-backed store".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute();

    unsafe {
        if let Some(value) = previous_store {
            env::set_var("TPMCTL_STORE", value);
        } else {
            env::remove_var("TPMCTL_STORE");
        }
    }

    let output = expect_hmac_output(result.unwrap());
    assert_eq!(output.len(), HashAlgorithm::Sha256.digest_len());
}
