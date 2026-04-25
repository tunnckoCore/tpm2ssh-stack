use super::{
    DeriveFormat, DeriveParams, ObjectSelector, SignPayload, encode_raw_or_hex, signature_format,
};
use crate::RegistryId;
use crate::derive::primitives::{DeriveUse, DerivedAlgorithm};
use zeroize::Zeroizing;

fn params(
    algorithm: DerivedAlgorithm,
    usage: DeriveUse,
    output_format: DeriveFormat,
) -> DeriveParams {
    DeriveParams {
        material: ObjectSelector::Id(RegistryId::new("material").unwrap()),
        label: Some(b"label".to_vec()),
        algorithm,
        usage,
        payload: None,
        hash: None,
        output_format,
        compressed: false,
        entropy: None,
    }
}

#[test]
fn validate_rejects_ed25519_digest_payload() {
    let mut params = params(
        DerivedAlgorithm::Ed25519,
        DeriveUse::Sign,
        DeriveFormat::Raw,
    );
    params.payload = Some(SignPayload::Digest(Zeroizing::new(vec![0_u8; 32])));
    assert!(params.validate().is_err());
}

#[test]
fn validate_rejects_entropy_when_label_present() {
    let mut params = params(DerivedAlgorithm::P256, DeriveUse::Secret, DeriveFormat::Raw);
    params.entropy = Some(Zeroizing::new(vec![1_u8; 32]));
    assert!(params.validate().is_err());
}

#[test]
fn validate_rejects_pubkey_formats_matching_root_rules() {
    let mut p256 = params(DerivedAlgorithm::P256, DeriveUse::Pubkey, DeriveFormat::Der);
    assert!(p256.validate().is_err());
    p256.algorithm = DerivedAlgorithm::Ed25519;
    assert!(p256.validate().is_err());
    let secp_der = params(
        DerivedAlgorithm::Secp256k1,
        DeriveUse::Pubkey,
        DeriveFormat::Der,
    );
    assert!(secp_der.validate().is_err());
}

#[test]
fn validate_rejects_sign_formats_matching_root_rules() {
    let mut ed = params(
        DerivedAlgorithm::Ed25519,
        DeriveUse::Sign,
        DeriveFormat::Der,
    );
    ed.payload = Some(SignPayload::Message(Zeroizing::new(b"message".to_vec())));
    assert!(ed.validate().is_err());
    let mut p256 = params(
        DerivedAlgorithm::P256,
        DeriveUse::Sign,
        DeriveFormat::Address,
    );
    p256.payload = Some(SignPayload::Message(Zeroizing::new(b"message".to_vec())));
    assert!(p256.validate().is_err());
}

#[test]
fn debug_redacts_secret_bearing_derive_fields() {
    let mut params = params(DerivedAlgorithm::P256, DeriveUse::Sign, DeriveFormat::Raw);
    params.label = Some(b"label-secret".to_vec());
    params.payload = Some(SignPayload::Message(Zeroizing::new(
        b"message-secret".to_vec(),
    )));
    params.entropy = Some(Zeroizing::new(b"entropy-secret".to_vec()));

    let debug = format!("{params:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("label-secret"));
    assert!(!debug.contains("message-secret"));
    assert!(!debug.contains("entropy-secret"));
}

#[test]
fn encode_raw_or_hex_rejects_non_binary_formats() {
    for format in [DeriveFormat::Der, DeriveFormat::Address] {
        assert_eq!(
            encode_raw_or_hex(b"derived-bytes", format)
                .unwrap_err()
                .to_string(),
            "invalid output_format: derive output format is not valid for this operation"
        );
    }
}

#[test]
fn signature_format_rejects_address_output() {
    assert_eq!(
        signature_format(DeriveFormat::Address)
            .unwrap_err()
            .to_string(),
        "invalid output_format: derive sign does not support address output"
    );
}
