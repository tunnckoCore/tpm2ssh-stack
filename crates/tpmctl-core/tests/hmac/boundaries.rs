use super::support::*;

#[test]
fn simulator_hmac_by_id_surfaces_corrupt_registry_metadata() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let hmac_id = RegistryId::new("sim/native/hmac/corrupt-metadata").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let metadata_path = temp_store
        .path()
        .join("keys")
        .join(hmac_id.as_relative_path())
        .join("meta.json");
    std::fs::write(&metadata_path, b"{not valid json").unwrap();

    let error = HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(b"corrupt metadata should fail before hmac".to_vec()),
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
        tpmctl_core::Error::Json { ref path, .. } if path == &metadata_path
    ));
}

#[test]
fn simulator_hmac_by_id_hash_none_uses_registry_hash_metadata_until_overridden() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let hmac_id = RegistryId::new("sim/native/hmac/metadata-hash-default").unwrap();
    let metadata_path = temp_store
        .path()
        .join("keys")
        .join(hmac_id.as_relative_path())
        .join("meta.json");

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
    metadata["hash"] = serde_json::Value::String("sha384".to_owned());
    std::fs::write(
        &metadata_path,
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();

    let default_error = HmacRequest {
        selector: ObjectSelector::Id(hmac_id.clone()),
        input: Zeroizing::new(b"metadata hash should drive default id hmac".to_vec()),
        hash: None,
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap_err();
    assert!(matches!(
        default_error,
        tpmctl_core::Error::Tpm {
            operation: "HMAC",
            ..
        }
    ));

    let output = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(b"explicit hash should override metadata default".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );
    assert_eq!(output.len(), HashAlgorithm::Sha256.digest_len());
}

#[test]
fn simulator_hmac_accepts_input_at_tpm_one_shot_limit() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let hmac_id = RegistryId::new("sim/native/hmac/max-input").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();

    let max_sized_input = vec![0x5a; tss_esapi::structures::MaxBuffer::MAX_SIZE];
    let output = expect_hmac_output(
        HmacRequest {
            selector: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(max_sized_input),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            force: false,
        }
        .execute_with_context(&command)
        .unwrap(),
    );
    assert_eq!(output.len(), HashAlgorithm::Sha256.digest_len());
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
