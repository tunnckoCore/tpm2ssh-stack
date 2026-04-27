use super::support::*;

#[test]
fn simulator_api_derive_uses_hmac_identity_seed_fallback_deterministically() {
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
    let hmac_id = RegistryId::new("sim/api/derive-hmac-seed/key").unwrap();
    let label = b"simulator derive hmac fallback label".to_vec();

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

    let address_params = DeriveParams {
        material: ObjectSelector::Id(hmac_id.clone()),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Secp256k1,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Address,
        compressed: false,
        entropy: None,
    };
    let first_address = derive::derive(&context, address_params.clone()).unwrap();
    let second_address = derive::derive(&context, address_params).unwrap();
    assert_eq!(first_address, second_address);
    assert_eq!(first_address.len(), 42);
    assert!(first_address.starts_with(b"0x"));

    let pubkey_params = DeriveParams {
        material: ObjectSelector::Id(hmac_id.clone()),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Secp256k1,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let first_pubkey = derive::derive(&context, pubkey_params.clone()).unwrap();
    let second_pubkey = derive::derive(&context, pubkey_params).unwrap();
    assert_eq!(first_pubkey, second_pubkey);
    assert_eq!(first_pubkey.len(), 65);
    assert_eq!(first_pubkey[0], 0x04);

    let signature_params = DeriveParams {
        material: ObjectSelector::Id(hmac_id),
        label: Some(label),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Sign,
        payload: Some(DeriveSignPayload::Message(Zeroizing::new(
            b"derive with hmac identity seed fallback".to_vec(),
        ))),
        hash: Some(HashAlgorithm::Sha256),
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let first_signature = derive::derive(&context, signature_params.clone()).unwrap();
    let second_signature = derive::derive(&context, signature_params).unwrap();
    assert_eq!(first_signature, second_signature);
    assert_eq!(first_signature.len(), 64);
}

#[test]
fn simulator_api_derive_outputs_are_consistent_for_sealed_seed_material() {
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

    let p256_seed_id = RegistryId::new("sim/api/derive/consistency/sealed-seed/p256").unwrap();
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(p256_seed_id.clone()),
            input: Zeroizing::new(
                b"sealed consistency integration seed material for p256".to_vec(),
            ),
            overwrite: false,
        },
    )
    .unwrap();
    derive_p256_workflow_and_assert_consistency(
        &context,
        ObjectSelector::Id(p256_seed_id),
        b"simulator sealed seed consistency label p256".to_vec(),
        b"simulator sealed seed consistency message p256",
    );

    let secp256k1_seed_id =
        RegistryId::new("sim/api/derive/consistency/sealed-seed/secp256k1").unwrap();
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(secp256k1_seed_id.clone()),
            input: Zeroizing::new(
                b"sealed consistency integration seed material for secp256k1".to_vec(),
            ),
            overwrite: false,
        },
    )
    .unwrap();
    derive_secp256k1_workflow_and_assert_consistency(
        &context,
        ObjectSelector::Id(secp256k1_seed_id),
        b"simulator sealed seed consistency label secp256k1".to_vec(),
        b"simulator sealed seed consistency message secp256k1",
    );

    let ed25519_seed_id =
        RegistryId::new("sim/api/derive/consistency/sealed-seed/ed25519").unwrap();
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(ed25519_seed_id.clone()),
            input: Zeroizing::new(
                b"sealed consistency integration seed material for ed25519".to_vec(),
            ),
            overwrite: false,
        },
    )
    .unwrap();
    derive_ed25519_workflow_and_assert_consistency(
        &context,
        ObjectSelector::Id(ed25519_seed_id),
        b"simulator sealed seed consistency label ed25519".to_vec(),
        b"simulator sealed seed consistency message ed25519",
    );
}

#[test]
fn simulator_api_derive_outputs_are_consistent_for_hmac_persistent_handle_material() {
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
    let hmac_id = RegistryId::new("sim/api/derive/consistency/hmac-handle/key").unwrap();
    let handle = PersistentHandle::new(0x8101_0044).unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id,
            persist_at: Some(handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();

    derive_p256_workflow_and_assert_consistency(
        &context,
        ObjectSelector::Handle(handle),
        b"simulator hmac handle consistency label p256".to_vec(),
        b"simulator hmac handle consistency message p256",
    );
    derive_secp256k1_workflow_and_assert_consistency(
        &context,
        ObjectSelector::Handle(handle),
        b"simulator hmac handle consistency label secp256k1".to_vec(),
        b"simulator hmac handle consistency message secp256k1",
    );
    derive_ed25519_workflow_and_assert_consistency(
        &context,
        ObjectSelector::Handle(handle),
        b"simulator hmac handle consistency label ed25519".to_vec(),
        b"simulator hmac handle consistency message ed25519",
    );

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_api_derive_outputs_are_stable_across_context_reloads_for_sealed_seed_material() {
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

    let p256_seed_id = RegistryId::new("sim/api/derive/reload/sealed-seed/p256").unwrap();
    let secp256k1_seed_id = RegistryId::new("sim/api/derive/reload/sealed-seed/secp256k1").unwrap();
    let ed25519_seed_id = RegistryId::new("sim/api/derive/reload/sealed-seed/ed25519").unwrap();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(p256_seed_id.clone()),
            input: Zeroizing::new(b"sealed reload consistency seed material for p256".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(secp256k1_seed_id.clone()),
            input: Zeroizing::new(
                b"sealed reload consistency seed material for secp256k1".to_vec(),
            ),
            overwrite: false,
        },
    )
    .unwrap();
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(ed25519_seed_id.clone()),
            input: Zeroizing::new(b"sealed reload consistency seed material for ed25519".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let first_p256 = derive_p256_snapshot(
        &context,
        ObjectSelector::Id(p256_seed_id.clone()),
        b"simulator sealed seed reload label p256".to_vec(),
        b"simulator sealed seed reload message p256",
    );
    let first_secp256k1 = derive_secp256k1_snapshot(
        &context,
        ObjectSelector::Id(secp256k1_seed_id.clone()),
        b"simulator sealed seed reload label secp256k1".to_vec(),
        b"simulator sealed seed reload message secp256k1",
    );
    let first_ed25519 = derive_ed25519_snapshot(
        &context,
        ObjectSelector::Id(ed25519_seed_id.clone()),
        b"simulator sealed seed reload label ed25519".to_vec(),
        b"simulator sealed seed reload message ed25519",
    );

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };

    let second_p256 = derive_p256_snapshot(
        &reloaded_context,
        ObjectSelector::Id(p256_seed_id),
        b"simulator sealed seed reload label p256".to_vec(),
        b"simulator sealed seed reload message p256",
    );
    let second_secp256k1 = derive_secp256k1_snapshot(
        &reloaded_context,
        ObjectSelector::Id(secp256k1_seed_id),
        b"simulator sealed seed reload label secp256k1".to_vec(),
        b"simulator sealed seed reload message secp256k1",
    );
    let second_ed25519 = derive_ed25519_snapshot(
        &reloaded_context,
        ObjectSelector::Id(ed25519_seed_id),
        b"simulator sealed seed reload label ed25519".to_vec(),
        b"simulator sealed seed reload message ed25519",
    );

    assert_eq!(first_p256, second_p256);
    assert_eq!(first_secp256k1, second_secp256k1);
    assert_eq!(first_ed25519, second_ed25519);
}

#[test]
fn simulator_api_derive_outputs_match_by_id_and_handle_across_context_reloads_for_persistent_hmac_material()
 {
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
    let hmac_id = RegistryId::new("sim/api/derive/reload/hmac-handle/key").unwrap();
    let handle = PersistentHandle::new(0x8101_0046).unwrap();

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

    let by_handle_p256 = derive_p256_snapshot(
        &context,
        ObjectSelector::Handle(handle),
        b"simulator hmac handle reload label p256".to_vec(),
        b"simulator hmac handle reload message p256",
    );
    let by_id_p256 = derive_p256_snapshot(
        &context,
        ObjectSelector::Id(hmac_id.clone()),
        b"simulator hmac handle reload label p256".to_vec(),
        b"simulator hmac handle reload message p256",
    );
    assert_eq!(by_handle_p256, by_id_p256);

    let by_handle_secp256k1 = derive_secp256k1_snapshot(
        &context,
        ObjectSelector::Handle(handle),
        b"simulator hmac handle reload label secp256k1".to_vec(),
        b"simulator hmac handle reload message secp256k1",
    );
    let by_id_secp256k1 = derive_secp256k1_snapshot(
        &context,
        ObjectSelector::Id(hmac_id.clone()),
        b"simulator hmac handle reload label secp256k1".to_vec(),
        b"simulator hmac handle reload message secp256k1",
    );
    assert_eq!(by_handle_secp256k1, by_id_secp256k1);

    let by_handle_ed25519 = derive_ed25519_snapshot(
        &context,
        ObjectSelector::Handle(handle),
        b"simulator hmac handle reload label ed25519".to_vec(),
        b"simulator hmac handle reload message ed25519",
    );
    let by_id_ed25519 = derive_ed25519_snapshot(
        &context,
        ObjectSelector::Id(hmac_id.clone()),
        b"simulator hmac handle reload label ed25519".to_vec(),
        b"simulator hmac handle reload message ed25519",
    );
    assert_eq!(by_handle_ed25519, by_id_ed25519);

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };

    assert_eq!(
        by_handle_p256,
        derive_p256_snapshot(
            &reloaded_context,
            ObjectSelector::Handle(handle),
            b"simulator hmac handle reload label p256".to_vec(),
            b"simulator hmac handle reload message p256",
        )
    );
    assert_eq!(
        by_handle_p256,
        derive_p256_snapshot(
            &reloaded_context,
            ObjectSelector::Id(hmac_id.clone()),
            b"simulator hmac handle reload label p256".to_vec(),
            b"simulator hmac handle reload message p256",
        )
    );
    assert_eq!(
        by_handle_secp256k1,
        derive_secp256k1_snapshot(
            &reloaded_context,
            ObjectSelector::Handle(handle),
            b"simulator hmac handle reload label secp256k1".to_vec(),
            b"simulator hmac handle reload message secp256k1",
        )
    );
    assert_eq!(
        by_handle_secp256k1,
        derive_secp256k1_snapshot(
            &reloaded_context,
            ObjectSelector::Id(hmac_id.clone()),
            b"simulator hmac handle reload label secp256k1".to_vec(),
            b"simulator hmac handle reload message secp256k1",
        )
    );
    assert_eq!(
        by_handle_ed25519,
        derive_ed25519_snapshot(
            &reloaded_context,
            ObjectSelector::Handle(handle),
            b"simulator hmac handle reload label ed25519".to_vec(),
            b"simulator hmac handle reload message ed25519",
        )
    );
    assert_eq!(
        by_handle_ed25519,
        derive_ed25519_snapshot(
            &reloaded_context,
            ObjectSelector::Id(hmac_id),
            b"simulator hmac handle reload label ed25519".to_vec(),
            b"simulator hmac handle reload message ed25519",
        )
    );

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_api_derive_persistent_hmac_handle_rebinding_changes_handle_outputs_but_preserves_stale_id_across_algorithms()
 {
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
    let handle = PersistentHandle::new(0x8101_004a).unwrap();
    let first_id = RegistryId::new("sim/api/derive/rebind/first").unwrap();
    let second_id = RegistryId::new("sim/api/derive/rebind/second").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: first_id.clone(),
            persist_at: Some(handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();

    let first_by_handle = derive_workflow_snapshots(
        &context,
        ObjectSelector::Handle(handle),
        "simulator-derive-rebind-first",
    );
    let first_by_id = derive_workflow_snapshots(
        &context,
        ObjectSelector::Id(first_id.clone()),
        "simulator-derive-rebind-first",
    );
    assert_eq!(first_by_handle, first_by_id);

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    assert_eq!(
        first_by_handle,
        derive_workflow_snapshots(
            &reloaded_context,
            ObjectSelector::Handle(handle),
            "simulator-derive-rebind-first",
        )
    );
    assert_eq!(
        first_by_id,
        derive_workflow_snapshots(
            &reloaded_context,
            ObjectSelector::Id(first_id.clone()),
            "simulator-derive-rebind-first",
        )
    );

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

    let rebound_by_handle = derive_workflow_snapshots(
        &reloaded_context,
        ObjectSelector::Handle(handle),
        "simulator-derive-rebind-second",
    );
    let rebound_by_second_id = derive_workflow_snapshots(
        &reloaded_context,
        ObjectSelector::Id(second_id.clone()),
        "simulator-derive-rebind-second",
    );
    let stale_by_first_id = derive_workflow_snapshots(
        &reloaded_context,
        ObjectSelector::Id(first_id.clone()),
        "simulator-derive-rebind-first",
    );

    assert_eq!(rebound_by_handle, rebound_by_second_id);
    assert_eq!(stale_by_first_id, first_by_id);
    assert_ne!(rebound_by_handle, first_by_handle);
    assert_ne!(rebound_by_handle.p256, first_by_handle.p256);
    assert_ne!(rebound_by_handle.secp256k1, first_by_handle.secp256k1);
    assert_ne!(rebound_by_handle.ed25519, first_by_handle.ed25519);

    let reloaded_again_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    assert_eq!(
        rebound_by_handle,
        derive_workflow_snapshots(
            &reloaded_again_context,
            ObjectSelector::Handle(handle),
            "simulator-derive-rebind-second",
        )
    );
    assert_eq!(
        rebound_by_second_id,
        derive_workflow_snapshots(
            &reloaded_again_context,
            ObjectSelector::Id(second_id),
            "simulator-derive-rebind-second",
        )
    );
    assert_eq!(
        stale_by_first_id,
        derive_workflow_snapshots(
            &reloaded_again_context,
            ObjectSelector::Id(first_id),
            "simulator-derive-rebind-first",
        )
    );

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_api_derive_overwriting_sealed_seed_changes_outputs_and_remains_stable_across_reloads()
{
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
    let seed_id = RegistryId::new("sim/api/derive/overwrite/sealed-seed").unwrap();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(seed_id.clone()),
            input: Zeroizing::new(b"first sealed derive overwrite seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let first = derive_workflow_snapshots(
        &context,
        ObjectSelector::Id(seed_id.clone()),
        "simulator-derive-overwrite-sealed-seed",
    );

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    assert_eq!(
        first,
        derive_workflow_snapshots(
            &reloaded_context,
            ObjectSelector::Id(seed_id.clone()),
            "simulator-derive-overwrite-sealed-seed",
        )
    );

    api::seal(
        &reloaded_context,
        SealParams {
            target: ObjectSelector::Id(seed_id.clone()),
            input: Zeroizing::new(b"second sealed derive overwrite seed material".to_vec()),
            overwrite: true,
        },
    )
    .unwrap();

    let second = derive_workflow_snapshots(
        &reloaded_context,
        ObjectSelector::Id(seed_id.clone()),
        "simulator-derive-overwrite-sealed-seed",
    );
    assert_ne!(second, first);
    assert_ne!(second.p256, first.p256);
    assert_ne!(second.secp256k1, first.secp256k1);
    assert_ne!(second.ed25519, first.ed25519);

    let reloaded_again_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    assert_eq!(
        second,
        derive_workflow_snapshots(
            &reloaded_again_context,
            ObjectSelector::Id(seed_id),
            "simulator-derive-overwrite-sealed-seed",
        )
    );
}

#[test]
fn simulator_api_derive_supports_output_format_matrix_for_sealed_seed_material() {
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
    let seed_id = RegistryId::new("sim/api/derive/formats/sealed-seed").unwrap();
    let material = ObjectSelector::Id(seed_id.clone());

    api::seal(
        &context,
        SealParams {
            target: material.clone(),
            input: Zeroizing::new(b"sealed derive output format matrix seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let p256_label = b"simulator derive format matrix p256".to_vec();
    let p256_secret_raw = derive_output(
        &context,
        material.clone(),
        Some(p256_label.clone()),
        DeriveAlgorithm::P256,
        DeriveUse::Secret,
        None,
        None,
        DeriveFormat::Raw,
        false,
    );
    let p256_secret_hex = derive_output(
        &context,
        material.clone(),
        Some(p256_label.clone()),
        DeriveAlgorithm::P256,
        DeriveUse::Secret,
        None,
        None,
        DeriveFormat::Hex,
        false,
    );
    assert_eq!(
        hex::decode(p256_secret_hex.as_slice()).unwrap(),
        p256_secret_raw.as_slice()
    );
    let p256_software_secret = SecretKey::from_slice(p256_secret_raw.as_slice()).unwrap();

    let p256_public_raw = derive_output(
        &context,
        material.clone(),
        Some(p256_label.clone()),
        DeriveAlgorithm::P256,
        DeriveUse::Pubkey,
        None,
        None,
        DeriveFormat::Raw,
        false,
    );
    let p256_public_hex = derive_output(
        &context,
        material.clone(),
        Some(p256_label.clone()),
        DeriveAlgorithm::P256,
        DeriveUse::Pubkey,
        None,
        None,
        DeriveFormat::Hex,
        false,
    );
    assert_eq!(
        hex::decode(p256_public_hex.as_slice()).unwrap(),
        p256_public_raw.as_slice()
    );
    assert_eq!(
        p256_public_raw.as_slice(),
        p256_software_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
    );

    let p256_message = b"derive output format matrix p256 message";
    let p256_signature_raw = derive_output(
        &context,
        material.clone(),
        Some(p256_label.clone()),
        DeriveAlgorithm::P256,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Message(Zeroizing::new(
            p256_message.to_vec(),
        ))),
        Some(HashAlgorithm::Sha256),
        DeriveFormat::Raw,
        false,
    );
    let p256_signature_hex = derive_output(
        &context,
        material.clone(),
        Some(p256_label.clone()),
        DeriveAlgorithm::P256,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Message(Zeroizing::new(
            p256_message.to_vec(),
        ))),
        Some(HashAlgorithm::Sha256),
        DeriveFormat::Hex,
        false,
    );
    assert_eq!(
        hex::decode(p256_signature_hex.as_slice()).unwrap(),
        p256_signature_raw.as_slice()
    );
    VerifyingKey::from_sec1_bytes(p256_public_raw.as_slice())
        .unwrap()
        .verify_prehash(
            HashAlgorithm::Sha256.digest(p256_message).as_slice(),
            &P256Signature::from_slice(p256_signature_raw.as_slice()).unwrap(),
        )
        .unwrap();

    let secp256k1_label = b"simulator derive format matrix secp256k1".to_vec();
    let secp256k1_secret_raw = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Secret,
        None,
        None,
        DeriveFormat::Raw,
        false,
    );
    let secp256k1_secret_hex = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Secret,
        None,
        None,
        DeriveFormat::Hex,
        false,
    );
    assert_eq!(
        hex::decode(secp256k1_secret_hex.as_slice()).unwrap(),
        secp256k1_secret_raw.as_slice()
    );
    let secp256k1_software_secret =
        k256::SecretKey::from_slice(secp256k1_secret_raw.as_slice()).unwrap();

    let secp256k1_public_raw = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Pubkey,
        None,
        None,
        DeriveFormat::Raw,
        false,
    );
    let secp256k1_public_hex = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Pubkey,
        None,
        None,
        DeriveFormat::Hex,
        false,
    );
    assert_eq!(
        hex::decode(secp256k1_public_hex.as_slice()).unwrap(),
        secp256k1_public_raw.as_slice()
    );
    assert_eq!(
        secp256k1_public_raw.as_slice(),
        secp256k1_software_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
    );

    let secp256k1_compressed_raw = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Pubkey,
        None,
        None,
        DeriveFormat::Raw,
        true,
    );
    let secp256k1_compressed_hex = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Pubkey,
        None,
        None,
        DeriveFormat::Hex,
        true,
    );
    assert_eq!(
        hex::decode(secp256k1_compressed_hex.as_slice()).unwrap(),
        secp256k1_compressed_raw.as_slice()
    );
    assert_eq!(
        k256::PublicKey::from_sec1_bytes(secp256k1_compressed_raw.as_slice())
            .unwrap()
            .to_encoded_point(false)
            .as_bytes(),
        secp256k1_public_raw.as_slice()
    );

    let secp256k1_address = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Pubkey,
        None,
        None,
        DeriveFormat::Address,
        false,
    );
    assert_eq!(
        std::str::from_utf8(secp256k1_address.as_slice()).unwrap(),
        checksum_address_from_uncompressed_secp256k1(secp256k1_public_raw.as_slice())
    );

    let secp256k1_message = b"derive output format matrix secp256k1 message";
    let secp256k1_signature_raw = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Message(Zeroizing::new(
            secp256k1_message.to_vec(),
        ))),
        Some(HashAlgorithm::Sha256),
        DeriveFormat::Raw,
        false,
    );
    let secp256k1_signature_hex = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Message(Zeroizing::new(
            secp256k1_message.to_vec(),
        ))),
        Some(HashAlgorithm::Sha256),
        DeriveFormat::Hex,
        false,
    );
    assert_eq!(
        hex::decode(secp256k1_signature_hex.as_slice()).unwrap(),
        secp256k1_signature_raw.as_slice()
    );
    Secp256k1VerifyingKey::from_sec1_bytes(secp256k1_public_raw.as_slice())
        .unwrap()
        .verify_prehash(
            HashAlgorithm::Sha256.digest(secp256k1_message).as_slice(),
            &Secp256k1Signature::from_slice(secp256k1_signature_raw.as_slice()).unwrap(),
        )
        .unwrap();

    let ed25519_label = b"simulator derive format matrix ed25519".to_vec();
    let ed25519_secret_raw = derive_output(
        &context,
        material.clone(),
        Some(ed25519_label.clone()),
        DeriveAlgorithm::Ed25519,
        DeriveUse::Secret,
        None,
        None,
        DeriveFormat::Raw,
        false,
    );
    let ed25519_secret_hex = derive_output(
        &context,
        material.clone(),
        Some(ed25519_label.clone()),
        DeriveAlgorithm::Ed25519,
        DeriveUse::Secret,
        None,
        None,
        DeriveFormat::Hex,
        false,
    );
    assert_eq!(
        hex::decode(ed25519_secret_hex.as_slice()).unwrap(),
        ed25519_secret_raw.as_slice()
    );
    let ed25519_secret_bytes: [u8; 32] = ed25519_secret_raw.as_slice().try_into().unwrap();
    let ed25519_signing_key = Ed25519SigningKey::from_bytes(&ed25519_secret_bytes);

    let ed25519_public_raw = derive_output(
        &context,
        material.clone(),
        Some(ed25519_label.clone()),
        DeriveAlgorithm::Ed25519,
        DeriveUse::Pubkey,
        None,
        None,
        DeriveFormat::Raw,
        false,
    );
    let ed25519_public_hex = derive_output(
        &context,
        material.clone(),
        Some(ed25519_label.clone()),
        DeriveAlgorithm::Ed25519,
        DeriveUse::Pubkey,
        None,
        None,
        DeriveFormat::Hex,
        false,
    );
    assert_eq!(
        hex::decode(ed25519_public_hex.as_slice()).unwrap(),
        ed25519_public_raw.as_slice()
    );
    assert_eq!(
        ed25519_public_raw.as_slice(),
        &ed25519_signing_key.verifying_key().to_bytes()
    );

    let ed25519_message = b"derive output format matrix ed25519 message";
    let ed25519_signature_raw = derive_output(
        &context,
        material.clone(),
        Some(ed25519_label.clone()),
        DeriveAlgorithm::Ed25519,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Message(Zeroizing::new(
            ed25519_message.to_vec(),
        ))),
        None,
        DeriveFormat::Raw,
        false,
    );
    let ed25519_signature_hex = derive_output(
        &context,
        material,
        Some(ed25519_label),
        DeriveAlgorithm::Ed25519,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Message(Zeroizing::new(
            ed25519_message.to_vec(),
        ))),
        None,
        DeriveFormat::Hex,
        false,
    );
    assert_eq!(
        hex::decode(ed25519_signature_hex.as_slice()).unwrap(),
        ed25519_signature_raw.as_slice()
    );
    Ed25519VerifyingKey::from_bytes(&ed25519_signing_key.verifying_key().to_bytes())
        .unwrap()
        .verify(
            ed25519_message,
            &Ed25519Signature::try_from(ed25519_signature_raw.as_slice()).unwrap(),
        )
        .unwrap();
}

#[test]
fn simulator_api_derive_supports_ecdsa_hash_and_signature_format_matrix() {
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
    let seed_id = RegistryId::new("sim/api/derive/hash-matrix/sealed-seed").unwrap();
    let material = ObjectSelector::Id(seed_id.clone());

    api::seal(
        &context,
        SealParams {
            target: material.clone(),
            input: Zeroizing::new(b"sealed derive hash matrix seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let p256_label = b"simulator derive hash matrix p256".to_vec();
    let p256_secret = derive_output(
        &context,
        material.clone(),
        Some(p256_label.clone()),
        DeriveAlgorithm::P256,
        DeriveUse::Secret,
        None,
        None,
        DeriveFormat::Raw,
        false,
    );
    let p256_software_secret = SecretKey::from_slice(p256_secret.as_slice()).unwrap();
    let p256_verifying_key = VerifyingKey::from_sec1_bytes(
        derive_output(
            &context,
            material.clone(),
            Some(p256_label.clone()),
            DeriveAlgorithm::P256,
            DeriveUse::Pubkey,
            None,
            None,
            DeriveFormat::Raw,
            false,
        )
        .as_slice(),
    )
    .unwrap();

    for (hash, output_format, message) in [
        (
            None,
            DeriveFormat::Raw,
            b"derive hash matrix p256 default-sha256".as_slice(),
        ),
        (
            Some(HashAlgorithm::Sha384),
            DeriveFormat::Hex,
            b"derive hash matrix p256 sha384".as_slice(),
        ),
        (
            Some(HashAlgorithm::Sha512),
            DeriveFormat::Der,
            b"derive hash matrix p256 sha512".as_slice(),
        ),
    ] {
        assert_p256_derive_sign_case(
            &context,
            material.clone(),
            &p256_label,
            &p256_software_secret,
            &p256_verifying_key,
            message,
            hash,
            output_format,
        );
    }

    let secp256k1_label = b"simulator derive hash matrix secp256k1".to_vec();
    let secp256k1_secret = derive_output(
        &context,
        material.clone(),
        Some(secp256k1_label.clone()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Secret,
        None,
        None,
        DeriveFormat::Raw,
        false,
    );
    let secp256k1_software_secret =
        k256::SecretKey::from_slice(secp256k1_secret.as_slice()).unwrap();
    let secp256k1_verifying_key = Secp256k1VerifyingKey::from_sec1_bytes(
        derive_output(
            &context,
            material,
            Some(secp256k1_label.clone()),
            DeriveAlgorithm::Secp256k1,
            DeriveUse::Pubkey,
            None,
            None,
            DeriveFormat::Raw,
            false,
        )
        .as_slice(),
    )
    .unwrap();

    for (hash, output_format, message) in [
        (
            None,
            DeriveFormat::Raw,
            b"derive hash matrix secp256k1 default-sha256".as_slice(),
        ),
        (
            Some(HashAlgorithm::Sha384),
            DeriveFormat::Hex,
            b"derive hash matrix secp256k1 sha384".as_slice(),
        ),
        (
            Some(HashAlgorithm::Sha512),
            DeriveFormat::Der,
            b"derive hash matrix secp256k1 sha512".as_slice(),
        ),
    ] {
        assert_secp256k1_derive_sign_case(
            &context,
            ObjectSelector::Id(seed_id.clone()),
            &secp256k1_label,
            &secp256k1_software_secret,
            &secp256k1_verifying_key,
            message,
            hash,
            output_format,
        );
    }
}
