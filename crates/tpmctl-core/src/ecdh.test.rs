
use super::*;
use crate::{KeyUsage, PersistentHandle};

fn sec1() -> Vec<u8> {
    hex::decode(concat!(
        "04",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    ))
    .unwrap()
}

fn request() -> EcdhRequest {
    EcdhRequest {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
        peer_public_key: PublicKeyInput::Sec1(sec1()),
        output_format: BinaryFormat::Raw,
    }
}

#[test]
fn ecdh_validates_expected_key_usage() {
    let descriptor = ObjectDescriptor {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
        usage: KeyUsage::Ecdh,
        curve: Some(crate::EccCurve::P256),
        hash: None,
        public_key: None,
    };
    assert!(request().validate_descriptor(&descriptor).is_ok());
}

#[test]
fn ecdh_rejects_non_ecdh_usage() {
    let descriptor = ObjectDescriptor {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
        usage: KeyUsage::Sign,
        curve: Some(crate::EccCurve::P256),
        hash: None,
        public_key: None,
    };
    assert!(request().validate_descriptor(&descriptor).is_err());
}

#[test]
fn ecdh_rejects_missing_curve_descriptor() {
    let descriptor = ObjectDescriptor {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
        usage: KeyUsage::Ecdh,
        curve: None,
        hash: None,
        public_key: None,
    };
    let error = request().validate_descriptor(&descriptor).unwrap_err();
    assert!(error.to_string().contains("expected P-256"));
}

#[test]
fn ecdh_encodes_raw_and_hex_shared_secret() {
    assert_eq!(
        encode_shared_secret(&[1, 2], BinaryFormat::Raw).as_slice(),
        &[1, 2]
    );
    assert_eq!(
        encode_shared_secret(&[1, 2], BinaryFormat::Hex).as_slice(),
        b"0102"
    );
}
