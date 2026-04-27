use super::support::*;

fn api_hmac_context() -> (tempfile::TempDir, ApiContext, RegistryId, RegistryId) {
    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let hmac_id = RegistryId::new("sim/api/hmac-seal-target/key").unwrap();
    let sealed_id = RegistryId::new("sim/api/hmac-seal-target/prf").unwrap();

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

    (temp_store, context, hmac_id, sealed_id)
}

#[test]
fn simulator_api_hmac_seal_target_emits_and_roundtrips_output() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let (_temp_store, context, hmac_id, sealed_id) = api_hmac_context();

    let sealed = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(b"api seal target integration input".to_vec()),
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
        output,
    } = sealed
    else {
        panic!("expected sealed HMAC output")
    };
    assert_eq!(target, SealTarget::Id(sealed_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);

    let unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), output.as_slice());
}

#[test]
fn simulator_api_hmac_seal_target_preserves_existing_value_without_overwrite() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let (_temp_store, context, hmac_id, sealed_id) = api_hmac_context();

    let first = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id.clone()),
            input: Zeroizing::new(b"first api sealed hmac input".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: Some(SealTarget::Id(sealed_id.clone())),
            emit_prf_when_sealing: true,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::SealedWithOutput {
        output: first_output,
        ..
    } = first
    else {
        panic!("expected sealed HMAC output")
    };

    let duplicate_error = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(b"second api sealed hmac input".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: Some(SealTarget::Id(sealed_id.clone())),
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap_err();
    assert!(matches!(
        duplicate_error,
        tpmctl_core::Error::AlreadyExists(_)
    ));

    let preserved = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(preserved.as_slice(), first_output.as_slice());
}

#[test]
fn simulator_api_hmac_seal_target_overwrite_replaces_value() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let (_temp_store, context, hmac_id, sealed_id) = api_hmac_context();

    api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id.clone()),
            input: Zeroizing::new(b"first api sealed hmac input".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: Some(SealTarget::Id(sealed_id.clone())),
            emit_prf_when_sealing: false,
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

    let second_expected = expect_hmac_output(
        api::hmac(
            &context,
            HmacParams {
                material: ObjectSelector::Id(hmac_id.clone()),
                input: Zeroizing::new(b"second api sealed hmac input".to_vec()),
                hash: Some(HashAlgorithm::Sha256),
                output_format: BinaryFormat::Raw,
                seal_target: None,
                emit_prf_when_sealing: false,
                overwrite: false,
            },
        )
        .unwrap(),
    );

    let replaced = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(b"second api sealed hmac input".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: Some(SealTarget::Id(sealed_id.clone())),
            emit_prf_when_sealing: false,
            overwrite: true,
        },
    )
    .unwrap();
    let HmacResult::Sealed { target, hash } = replaced else {
        panic!("expected replaced sealed HMAC result")
    };
    assert_eq!(target, SealTarget::Id(sealed_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);

    let unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), second_expected.as_slice());
    assert_ne!(unsealed.as_slice(), first.as_slice());
}
