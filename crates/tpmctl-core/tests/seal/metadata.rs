use super::support::*;

#[test]
fn simulator_hmac_seal_target_records_hash_metadata_in_store() {
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
    let hmac_id = RegistryId::new("sim/seal/hash-metadata/hmac-key").unwrap();
    let sealed_id = RegistryId::new("sim/seal/hash-metadata/sealed-output").unwrap();

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

    let result = HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(b"seal metadata hash bytes".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: Some(SealTarget::Id(sealed_id.clone())),
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&simulator_command_context(temp_store.path()))
    .unwrap();
    assert!(matches!(
        result,
        HmacResult::Sealed {
            target: SealTarget::Id(_),
            hash: HashAlgorithm::Sha256,
        }
    ));

    let store = Store::new(temp_store.path());
    let entry = store.load_sealed(&sealed_id).unwrap();
    assert_eq!(entry.record.hash.as_deref(), Some("sha256"));
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
