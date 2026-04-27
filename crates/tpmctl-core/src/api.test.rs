use super::*;
use crate::{Error, KeyUsage, PersistentHandle};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};

#[test]
fn keygen_params_reserve_handle_literal_namespace() {
    let params = KeygenParams {
        usage: KeygenUsage::Sign,
        id: RegistryId::new("0x81010010").unwrap(),
        persist_at: None,
        overwrite: false,
    };
    assert!(params.validate().is_err());
}

#[test]
fn sign_payload_keeps_digest_in_zeroizing_storage() {
    let payload = SignPayload::Digest(Zeroizing::new(vec![0_u8; 32]));
    let SignPayload::Digest(digest) = payload else {
        panic!("expected digest payload");
    };
    assert_eq!(digest.len(), HashAlgorithm::Sha256.digest_len());
}

#[test]
fn sign_params_debug_redacts_message_and_digest_bytes() {
    for payload in [
        SignPayload::Message(Zeroizing::new(b"super secret message".to_vec())),
        SignPayload::Digest(Zeroizing::new(vec![0x7a; 32])),
    ] {
        let params = SignParams {
            material: ObjectSelector::Id(RegistryId::new("sign-key").unwrap()),
            payload,
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Der,
        };
        let debug = format!("{params:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("super secret"));
        assert!(!debug.contains("122"));
    }
}

#[test]
fn ecdh_params_debug_redacts_peer_public_key() {
    let params = EcdhParams {
        material: ObjectSelector::Id(RegistryId::new("ecdh-key").unwrap()),
        peer_public_key: PublicKeyInput::Sec1(vec![0x04, 0xaa, 0xbb]),
        output_format: BinaryFormat::Hex,
    };
    let debug = format!("{params:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("170"));
    assert!(!debug.contains("187"));
}

#[test]
fn context_builds_command_and_store_without_tcti_side_effects() {
    let dir = tempfile::tempdir().unwrap();
    let context = Context {
        store: StoreOptions {
            root: Some(dir.path().to_path_buf()),
        },
        tcti: Some("swtpm:host=127.0.0.1,port=2321".to_string()),
    };
    let command = context.command();
    assert_eq!(command.store.root.as_deref(), Some(dir.path()));
    assert_eq!(
        command.tcti.as_deref(),
        Some("swtpm:host=127.0.0.1,port=2321")
    );
    let store = context.store().unwrap();
    assert_eq!(store.root(), dir.path());
}

#[test]
fn hmac_params_debug_redacts_input() {
    let params = HmacParams {
        material: ObjectSelector::Id(RegistryId::new("hmac-key").unwrap()),
        input: Zeroizing::new(b"very secret hmac input".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Hex,
        seal_target: Some(SealTarget::Id(RegistryId::new("sealed-out").unwrap())),
        emit_prf_when_sealing: true,
        overwrite: true,
    };
    let debug = format!("{params:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("very secret hmac input"));
}

#[test]
fn seal_params_debug_redacts_input() {
    let params = SealParams {
        target: ObjectSelector::Id(RegistryId::new("sealed-target").unwrap()),
        input: Zeroizing::new(b"very secret seal input".to_vec()),
        overwrite: true,
    };
    let debug = format!("{params:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("very secret seal input"));
}

#[test]
fn api_keygen_rejects_reserved_handle_literal_before_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let context = Context {
        store: StoreOptions {
            root: Some(dir.path().to_path_buf()),
        },
        tcti: Some("not-a-valid-tcti".to_string()),
    };
    let error = keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: RegistryId::new("0x81010011").unwrap(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap_err();
    assert!(matches!(error, Error::InvalidInput { field: "id", .. }));
}

#[test]
fn api_wrappers_propagate_invalid_tcti_errors() {
    let dir = tempfile::tempdir().unwrap();
    let context = Context {
        store: StoreOptions {
            root: Some(dir.path().to_path_buf()),
        },
        tcti: Some("not-a-valid-tcti".to_string()),
    };
    let handle = PersistentHandle::new(0x8101_0060).unwrap();

    let pubkey_error = pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Pem,
        },
    )
    .unwrap_err();
    assert!(matches!(pubkey_error, Error::Tcti(_)));

    let peer_public_key = SecretKey::from_slice(&[7_u8; 32])
        .unwrap()
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let ecdh_error = ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Handle(handle),
            peer_public_key: PublicKeyInput::Sec1(peer_public_key),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap_err();
    assert!(matches!(ecdh_error, Error::Tcti(_)));

    let sign_error = sign(
        &context,
        SignParams {
            material: ObjectSelector::Handle(handle),
            payload: SignPayload::Message(Zeroizing::new(b"sign me".to_vec())),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Der,
        },
    )
    .unwrap_err();
    assert!(matches!(sign_error, Error::Tcti(_)));

    let hmac_error = hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Handle(handle),
            input: Zeroizing::new(b"hmac me".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap_err();
    assert!(matches!(hmac_error, Error::Tcti(_)));

    let seal_error = seal(
        &context,
        SealParams {
            target: ObjectSelector::Handle(handle),
            input: Zeroizing::new(b"seal me".to_vec()),
            overwrite: false,
        },
    )
    .unwrap_err();
    assert!(matches!(seal_error, Error::Tcti(_)));

    let unseal_error = unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Handle(handle),
        },
    )
    .unwrap_err();
    assert!(matches!(unseal_error, Error::Tcti(_)));
}

#[test]
fn object_selector_usage_stays_explicit() {
    let descriptor = crate::ObjectDescriptor {
        selector: ObjectSelector::Id(RegistryId::new("id").unwrap()),
        usage: KeyUsage::Sign,
        curve: None,
        hash: None,
        public_key: None,
    };
    descriptor.require_usage(KeyUsage::Sign).unwrap();
    assert!(descriptor.require_usage(KeyUsage::Hmac).is_err());
}
