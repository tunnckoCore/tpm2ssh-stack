use super::support::*;

#[test]
fn simulator_native_ecdh_execute_uses_explicit_store_and_accepts_compressed_sec1_peer_keys() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let id = RegistryId::new("sim/native/ecdh/execute-store-compressed-peer").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Ecdh,
        id: id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    let tpm_public_sec1 = PubkeyRequest {
        selector: ObjectSelector::Id(id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let tpm_public = PublicKey::from_sec1_bytes(&tpm_public_sec1).unwrap();

    let peer_secret = SecretKey::from_slice(&[0x39; 32]).unwrap();
    let peer_public = peer_secret.public_key();
    let compressed_sec1 = peer_public.to_encoded_point(true).as_bytes().to_vec();

    let shared_secret = EcdhRequest {
        selector: ObjectSelector::Id(id),
        peer_public_key: PublicKeyInput::Sec1(compressed_sec1),
        output_format: BinaryFormat::Raw,
    }
    .execute(&store)
    .unwrap();

    let expected = diffie_hellman(peer_secret.to_nonzero_scalar(), tpm_public.as_affine());
    let expected: &[u8; 32] = expected.raw_secret_bytes().as_ref();
    assert_eq!(shared_secret.as_slice(), expected.as_slice());
}

#[test]
fn simulator_native_ecdh_rejects_invalid_der_and_pem_before_context_or_lookup() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let command = CommandContext {
        store: StoreOptions::default(),
        tcti: Some("not-a-valid-tcti".to_string()),
    };
    let handle = PersistentHandle::new(0x8101_0060).unwrap();

    for peer_public_key in [
        PublicKeyInput::Der(vec![0x30, 0x03, 0x01, 0x01]),
        PublicKeyInput::Pem("not a valid pem public key".to_string()),
    ] {
        let error = EcdhRequest {
            selector: ObjectSelector::Handle(handle),
            peer_public_key,
            output_format: BinaryFormat::Raw,
        }
        .execute_with_store_and_context(&store, &command)
        .expect_err("invalid peer key should fail before TCTI parsing or handle lookup");
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
}

#[test]
fn simulator_native_ecdh_by_handle_rejects_sign_key_usage() {
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
    let handle = PersistentHandle::new(0x8101_0061).unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: RegistryId::new("sim/native/ecdh/wrong-usage-sign-handle").unwrap(),
            persist_at: Some(handle),
            overwrite: allow_external_tcti(),
        },
    )
    .unwrap();

    let peer_secret = SecretKey::from_slice(&[0x61; 32]).unwrap();
    let error = EcdhRequest {
        selector: ObjectSelector::Handle(handle),
        peer_public_key: PublicKeyInput::Sec1(
            peer_secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        ),
        output_format: BinaryFormat::Raw,
    }
    .execute_with_store_and_context(&store, &simulator_command_context(temp_store.path()))
    .unwrap_err()
    .to_string();
    assert!(error.contains("expected ecdh object, got sign"));
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
