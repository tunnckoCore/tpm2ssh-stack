use super::support::*;

#[test]
fn simulator_api_hmac_seal_target_roundtrips_and_overwrite_controls_replacement() {
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
    let first_input = b"first api sealed hmac input".to_vec();
    let second_input = b"second api sealed hmac input".to_vec();

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

    let first = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id.clone()),
            input: Zeroizing::new(first_input.clone()),
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
        output: first_output,
    } = first
    else {
        panic!("expected sealed HMAC output")
    };
    assert_eq!(target, SealTarget::Id(sealed_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);

    let first_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id.clone()),
        },
    )
    .unwrap();
    assert_eq!(first_unsealed.as_slice(), first_output.as_slice());

    let duplicate_error = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id.clone()),
            input: Zeroizing::new(second_input.clone()),
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

    let preserved_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id.clone()),
        },
    )
    .unwrap();
    assert_eq!(preserved_unsealed.as_slice(), first_output.as_slice());

    let second_expected = expect_hmac_output(
        api::hmac(
            &context,
            HmacParams {
                material: ObjectSelector::Id(hmac_id),
                input: Zeroizing::new(second_input),
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
            material: ObjectSelector::Id(RegistryId::new("sim/api/hmac-seal-target/key").unwrap()),
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

    let replaced_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(replaced_unsealed.as_slice(), second_expected.as_slice());
    assert_ne!(replaced_unsealed.as_slice(), first_output.as_slice());
}
