use super::support::*;

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
