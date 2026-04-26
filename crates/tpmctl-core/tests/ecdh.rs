mod support;

use support::*;

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

#[test]
fn simulator_ecdh_shared_secret_matches_software_p256_agreement() {
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
    let ecdh_id = RegistryId::new("sim/api/ecdh-software-p256").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: ecdh_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let tpm_public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(ecdh_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let tpm_public = PublicKey::from_sec1_bytes(&tpm_public_sec1).unwrap();

    let software_secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let software_public_sec1 = software_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let tpm_shared_secret = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(ecdh_id),
            peer_public_key: PublicKeyInput::Sec1(software_public_sec1),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();

    let software_shared_secret =
        diffie_hellman(software_secret.to_nonzero_scalar(), tpm_public.as_affine());
    let expected_shared_secret: &[u8] = software_shared_secret.raw_secret_bytes().as_ref();
    assert_eq!(tpm_shared_secret.as_slice(), expected_shared_secret);
}

#[test]
fn simulator_ecdh_rejects_invalid_peer_public_key_before_zgen() {
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
    let ecdh_id = RegistryId::new("sim/api/ecdh-invalid-peer").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: ecdh_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let mut invalid_uncompressed_point = vec![0x04];
    invalid_uncompressed_point.extend_from_slice(&[0xff; 64]);
    let error = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(ecdh_id),
            peer_public_key: PublicKeyInput::Sec1(invalid_uncompressed_point),
            output_format: BinaryFormat::Raw,
        },
    )
    .expect_err("invalid SEC1 peer public key should be rejected");
    assert!(
        matches!(
            error,
            tpmctl_core::Error::InvalidInput {
                field: "public_key",
                ..
            }
        ),
        "expected invalid public_key error, got {error:?}"
    );
}

#[test]
fn simulator_ecdh_supports_cross_context_peer_formats_hex_output_and_software_verification() {
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
    let handle = PersistentHandle::new(0x8101_0049).unwrap();
    let ecdh_id = RegistryId::new("sim/api/ecdh/formats-and-reload").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: ecdh_id.clone(),
            persist_at: Some(handle),
            overwrite: initial_persistent_overwrite(),
        },
    )
    .unwrap();

    let tpm_public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let tpm_public = PublicKey::from_sec1_bytes(&tpm_public_sec1).unwrap();

    let peer_secret = SecretKey::from_slice(&[0x37; 32]).unwrap();
    let peer_public = peer_secret.public_key();
    let peer_sec1 = peer_public.to_encoded_point(false).as_bytes().to_vec();
    let peer_der = peer_public.to_public_key_der().unwrap().as_bytes().to_vec();
    let peer_pem = peer_public.to_public_key_pem(LineEnding::LF).unwrap();

    let raw_secret_by_id = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(ecdh_id.clone()),
            peer_public_key: PublicKeyInput::Sec1(peer_sec1),
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
    let hex_secret_by_handle = api::ecdh(
        &reloaded_context,
        EcdhParams {
            material: ObjectSelector::Handle(handle),
            peer_public_key: PublicKeyInput::Der(peer_der),
            output_format: BinaryFormat::Hex,
        },
    )
    .unwrap();
    assert_eq!(hex_secret_by_handle.len(), raw_secret_by_id.len() * 2);
    assert_eq!(
        hex::decode(&hex_secret_by_handle).unwrap(),
        raw_secret_by_id.as_slice()
    );

    let repeated_raw_secret = api::ecdh(
        &reloaded_context,
        EcdhParams {
            material: ObjectSelector::Handle(handle),
            peer_public_key: PublicKeyInput::Pem(peer_pem),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(repeated_raw_secret, raw_secret_by_id);

    let expected_secret = diffie_hellman(peer_secret.to_nonzero_scalar(), tpm_public.as_affine());
    let expected_secret: &[u8; 32] = expected_secret.raw_secret_bytes().as_ref();
    assert_eq!(raw_secret_by_id.as_slice(), expected_secret.as_slice());

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_native_ecdh_request_survives_cross_context_reload_and_handle_replacement() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0052).unwrap();
    let first_id = RegistryId::new("sim/native/ecdh/first").unwrap();
    let second_id = RegistryId::new("sim/native/ecdh/second").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Ecdh,
        id: first_id.clone(),
        persist_at: Some(handle),
        force: initial_persistent_force(),
    }
    .execute_with_context(&command)
    .unwrap();

    let peer_secret = SecretKey::from_slice(&[0x53; 32]).unwrap();
    let peer_public = peer_secret.public_key();
    let peer_sec1 = peer_public.to_encoded_point(false).as_bytes().to_vec();
    let peer_der = peer_public.to_public_key_der().unwrap().as_bytes().to_vec();
    let peer_pem = peer_public.to_public_key_pem(LineEnding::LF).unwrap();

    let first_public_by_id = PubkeyRequest {
        selector: ObjectSelector::Id(first_id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&command)
    .unwrap();
    let first_public_by_handle = PubkeyRequest {
        selector: ObjectSelector::Handle(handle),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(first_public_by_id, first_public_by_handle);

    let first_tpm_public = PublicKey::from_sec1_bytes(&first_public_by_handle).unwrap();
    let first_raw_secret = EcdhRequest {
        selector: ObjectSelector::Id(first_id.clone()),
        peer_public_key: PublicKeyInput::Sec1(peer_sec1.clone()),
        output_format: BinaryFormat::Raw,
    }
    .execute_with_context(&command)
    .unwrap();
    let first_expected = diffie_hellman(
        peer_secret.to_nonzero_scalar(),
        first_tpm_public.as_affine(),
    );
    let first_expected: &[u8; 32] = first_expected.raw_secret_bytes().as_ref();
    assert_eq!(first_raw_secret.as_slice(), first_expected.as_slice());

    let reloaded_command = simulator_command_context(temp_store.path());
    let first_hex_secret = EcdhRequest {
        selector: ObjectSelector::Handle(handle),
        peer_public_key: PublicKeyInput::Der(peer_der),
        output_format: BinaryFormat::Hex,
    }
    .execute_with_context(&reloaded_command)
    .unwrap();
    assert_eq!(
        hex::decode(&first_hex_secret).unwrap(),
        first_raw_secret.as_slice()
    );

    for _ in 0..3 {
        let repeated_command = simulator_command_context(temp_store.path());
        let repeated_secret = EcdhRequest {
            selector: ObjectSelector::Handle(handle),
            peer_public_key: PublicKeyInput::Pem(peer_pem.clone()),
            output_format: BinaryFormat::Raw,
        }
        .execute_with_context(&repeated_command)
        .unwrap();
        assert_eq!(repeated_secret, first_raw_secret);
    }

    KeygenRequest {
        usage: KeygenUsage::Ecdh,
        id: second_id.clone(),
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_context(&reloaded_command)
    .unwrap();

    let post_replacement_command = simulator_command_context(temp_store.path());
    let stale_public_by_first_id = PubkeyRequest {
        selector: ObjectSelector::Id(first_id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();
    let replacement_public_by_second_id = PubkeyRequest {
        selector: ObjectSelector::Id(second_id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();
    let replacement_public_by_handle = PubkeyRequest {
        selector: ObjectSelector::Handle(handle),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();

    assert_eq!(stale_public_by_first_id, first_public_by_id);
    assert_ne!(replacement_public_by_handle, first_public_by_handle);
    assert_eq!(
        replacement_public_by_second_id,
        replacement_public_by_handle
    );

    let replacement_tpm_public = PublicKey::from_sec1_bytes(&replacement_public_by_handle).unwrap();
    let replacement_expected = diffie_hellman(
        peer_secret.to_nonzero_scalar(),
        replacement_tpm_public.as_affine(),
    );
    let replacement_expected: &[u8; 32] = replacement_expected.raw_secret_bytes().as_ref();

    let replacement_secret_by_handle = EcdhRequest {
        selector: ObjectSelector::Handle(handle),
        peer_public_key: PublicKeyInput::Sec1(peer_sec1.clone()),
        output_format: BinaryFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();
    let replacement_secret_by_first_id = EcdhRequest {
        selector: ObjectSelector::Id(first_id),
        peer_public_key: PublicKeyInput::Pem(peer_pem.clone()),
        output_format: BinaryFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();
    let replacement_secret_by_second_id = EcdhRequest {
        selector: ObjectSelector::Id(second_id),
        peer_public_key: PublicKeyInput::Sec1(peer_sec1),
        output_format: BinaryFormat::Raw,
    }
    .execute_with_context(&post_replacement_command)
    .unwrap();

    assert_eq!(
        replacement_secret_by_handle.as_slice(),
        replacement_expected.as_slice()
    );
    assert_eq!(replacement_secret_by_handle, replacement_secret_by_first_id);
    assert_eq!(
        replacement_secret_by_handle,
        replacement_secret_by_second_id
    );
    assert_ne!(replacement_secret_by_handle, first_raw_secret);

    cleanup_persistent_handle(handle);
}
