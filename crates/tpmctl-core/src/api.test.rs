use super::*;
use crate::KeyUsage;

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
