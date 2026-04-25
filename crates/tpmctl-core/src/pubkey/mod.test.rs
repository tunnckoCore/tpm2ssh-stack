use super::*;
use crate::{CoreError, PersistentHandle, RegistryId, output::PublicKeyFormat};

fn sec1() -> Vec<u8> {
    hex::decode(concat!(
        "04",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    ))
    .unwrap()
}

fn descriptor(usage: KeyUsage) -> ObjectDescriptor {
    ObjectDescriptor {
        selector: ObjectSelector::Id(RegistryId::new("org/acme/alice/main").unwrap()),
        usage,
        curve: Some(crate::EccCurve::P256),
        hash: None,
        public_key: Some(EccPublicKey::p256_sec1(sec1()).unwrap()),
    }
}

#[test]
fn pubkey_rejects_hmac_and_sealed_objects() {
    let request = PubkeyRequest {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
        output_format: PublicKeyFormat::Pem,
    };

    for usage in [KeyUsage::Hmac, KeyUsage::Sealed] {
        let error = request
            .validate_descriptor(&descriptor(usage))
            .expect_err("unsupported usage should be rejected");
        match error {
            CoreError::InvalidInput { field, reason } => {
                assert_eq!(field, "usage");
                assert!(reason.contains(&usage.to_string()));
                assert!(reason.contains("cannot export a public key"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
fn pubkey_supports_raw_hex_pem_der_and_ssh_output() {
    for output_format in [
        PublicKeyFormat::Raw,
        PublicKeyFormat::Hex,
        PublicKeyFormat::Pem,
        PublicKeyFormat::Der,
        PublicKeyFormat::Ssh,
    ] {
        let request = PubkeyRequest {
            selector: ObjectSelector::Id(RegistryId::new("org/acme/alice/main").unwrap()),
            output_format,
        };
        assert!(
            !request
                .encode_descriptor_public_key(&descriptor(KeyUsage::Sign))
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn pubkey_ssh_comment_uses_sanitized_id() {
    let request = PubkeyRequest {
        selector: ObjectSelector::Id(RegistryId::new("org/acme/alice/main").unwrap()),
        output_format: PublicKeyFormat::Ssh,
    };
    let output = String::from_utf8(
        request
            .encode_descriptor_public_key(&descriptor(KeyUsage::Sign))
            .unwrap(),
    )
    .unwrap();
    assert!(output.ends_with(" org_acme_alice_main"));
}

#[test]
fn pubkey_rejects_descriptor_without_cached_public_key() {
    let request = PubkeyRequest {
        selector: ObjectSelector::Id(RegistryId::new("org/acme/alice/main").unwrap()),
        output_format: PublicKeyFormat::Pem,
    };
    let mut descriptor = descriptor(KeyUsage::Sign);
    descriptor.public_key = None;

    let error = request
        .encode_descriptor_public_key(&descriptor)
        .expect_err("missing cached public key should be rejected");
    match error {
        CoreError::InvalidInput { field, reason } => {
            assert_eq!(field, "public_key");
            assert_eq!(reason, "descriptor has no cached public key");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn public_key_input_parse_bytes_classifies_pem_sec1_and_der() {
    let pem = b"-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n".to_vec();
    assert!(matches!(
        PublicKeyInput::parse_bytes(pem).unwrap(),
        PublicKeyInput::Pem(_)
    ));
    assert!(matches!(
        PublicKeyInput::parse_bytes(sec1()).unwrap(),
        PublicKeyInput::Sec1(_)
    ));
    assert!(matches!(
        PublicKeyInput::parse_bytes(vec![0x30, 0x59, 0x30]).unwrap(),
        PublicKeyInput::Der(_)
    ));
}

#[test]
fn public_key_input_rejects_invalid_pem_utf8() {
    let error = PublicKeyInput::parse_bytes(vec![
        b'-', b'-', b'-', b'-', b'-', b'B', b'E', b'G', b'I', b'N', 0xff,
    ])
    .expect_err("invalid PEM utf-8 should be rejected");

    match error {
        CoreError::InvalidInput { field, reason } => {
            assert_eq!(field, "public_key");
            assert!(reason.contains("utf-8") || reason.contains("UTF-8"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn public_key_input_into_p256_rejects_invalid_sec1_der_and_pem() {
    for input in [
        PublicKeyInput::Sec1(vec![0x04, 0x01, 0x02, 0x03]),
        PublicKeyInput::Der(vec![0x30, 0x03, 0x02, 0x01, 0x00]),
        PublicKeyInput::Pem(
            "-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n".to_owned(),
        ),
    ] {
        let error = input
            .into_p256()
            .expect_err("invalid public key encoding should be rejected");
        match error {
            CoreError::InvalidInput { field, reason } => {
                assert_eq!(field, "public_key");
                assert!(!reason.is_empty());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
