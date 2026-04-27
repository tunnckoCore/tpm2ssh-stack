use super::support::*;

#[test]
fn simulator_persistent_ecdh_handle_reload_and_force_replacement_changes_shared_secret() {
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
    let handle = PersistentHandle::new(0x8101_0045).unwrap();
    let first_id = RegistryId::new("sim/api/persistent-ecdh-handle/first").unwrap();
    let second_id = RegistryId::new("sim/api/persistent-ecdh-handle/second").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: first_id.clone(),
            persist_at: Some(handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();

    let software_secret = SecretKey::from_slice(&[0x24; 32]).unwrap();
    let peer_public_key = PublicKeyInput::Sec1(
        software_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    );

    let by_id = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(first_id.clone()),
            peer_public_key: peer_public_key.clone(),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let handle_public_sec1 = api::pubkey(
        &reloaded_context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let handle_public = PublicKey::from_sec1_bytes(&handle_public_sec1).unwrap();

    let by_handle = api::ecdh(
        &reloaded_context,
        EcdhParams {
            material: ObjectSelector::Handle(handle),
            peer_public_key: peer_public_key.clone(),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(by_id, by_handle);

    let expected = diffie_hellman(
        software_secret.to_nonzero_scalar(),
        handle_public.as_affine(),
    );
    let expected_bytes: &[u8; 32] = expected.raw_secret_bytes().as_ref();
    assert_eq!(by_handle.as_slice(), expected_bytes.as_slice());

    api::keygen(
        &reloaded_context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: second_id,
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let replaced_public_sec1 = api::pubkey(
        &reloaded_context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_ne!(handle_public_sec1, replaced_public_sec1);

    let replaced_by_handle = api::ecdh(
        &reloaded_context,
        EcdhParams {
            material: ObjectSelector::Handle(handle),
            peer_public_key,
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_ne!(by_handle, replaced_by_handle);

    let original_by_id = api::ecdh(
        &reloaded_context,
        EcdhParams {
            material: ObjectSelector::Id(first_id),
            peer_public_key: PublicKeyInput::Sec1(
                software_secret
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            ),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(original_by_id, replaced_by_handle);
    assert_ne!(original_by_id, by_handle);

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_persistent_ecdh_handle_overwrite_diverges_between_pubkey_and_ecdh_by_id() {
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
    let handle = PersistentHandle::new(0x8101_0047).unwrap();
    let first_id = RegistryId::new("sim/api/persistent-ecdh-overwrite/first").unwrap();
    let second_id = RegistryId::new("sim/api/persistent-ecdh-overwrite/second").unwrap();
    let peer_secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let peer_public_key = PublicKeyInput::Sec1(
        peer_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    );

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: first_id.clone(),
            persist_at: Some(handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();

    let first_pubkey_by_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(first_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let first_secret_by_id = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(first_id.clone()),
            peer_public_key: peer_public_key.clone(),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: second_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let stale_pubkey_by_first_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(first_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let replacement_pubkey_by_second_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(second_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let replacement_pubkey_by_handle = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let replacement_secret_by_handle = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Handle(handle),
            peer_public_key: peer_public_key.clone(),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    let replacement_secret_by_first_id = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(first_id),
            peer_public_key: peer_public_key.clone(),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    let replacement_secret_by_second_id = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(second_id),
            peer_public_key,
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();

    assert_eq!(stale_pubkey_by_first_id, first_pubkey_by_id);
    assert_ne!(replacement_pubkey_by_handle, first_pubkey_by_id);
    assert_eq!(
        replacement_pubkey_by_second_id,
        replacement_pubkey_by_handle
    );
    assert_ne!(replacement_secret_by_handle, first_secret_by_id);
    assert_eq!(replacement_secret_by_handle, replacement_secret_by_first_id);
    assert_eq!(
        replacement_secret_by_handle,
        replacement_secret_by_second_id
    );

    cleanup_persistent_handle(handle);
}
