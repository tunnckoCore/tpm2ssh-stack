use super::*;
use crate::{PersistentHandle, RegistryId, output::PublicKeyFormat};

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
    assert!(
        request
            .validate_descriptor(&descriptor(KeyUsage::Hmac))
            .is_err()
    );
    assert!(
        request
            .validate_descriptor(&descriptor(KeyUsage::Sealed))
            .is_err()
    );
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
