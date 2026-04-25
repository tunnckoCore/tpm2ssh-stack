use super::*;
use crate::{DeriveFormat, Error, ObjectSelector, RegistryId};
use zeroize::Zeroizing;

fn params(
    algorithm: crate::DeriveAlgorithm,
    usage: crate::DeriveUse,
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
fn validate_rejects_payload_for_non_sign_usage() {
    let mut params = params(
        crate::DeriveAlgorithm::P256,
        crate::DeriveUse::Pubkey,
        DeriveFormat::Raw,
    );
    params.payload = Some(SignPayload::Message(Zeroizing::new(b"message".to_vec())));

    let error = validate_params(&params).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidInput { field: "derive", ref reason }
        if reason == "payload is valid only for derive sign"
    ));
}

#[test]
fn validate_output_format_rejects_address_for_non_matching_operations() {
    for (algorithm, usage, expected_field, expected_reason) in [
        (
            crate::DeriveAlgorithm::P256,
            crate::DeriveUse::Pubkey,
            "derive",
            "pubkey output for p256 or ed25519 supports only raw or hex",
        ),
        (
            crate::DeriveAlgorithm::Ed25519,
            crate::DeriveUse::Pubkey,
            "derive",
            "pubkey output for p256 or ed25519 supports only raw or hex",
        ),
        (
            crate::DeriveAlgorithm::Secp256k1,
            crate::DeriveUse::Sign,
            "derive",
            "p256 or secp256k1 sign output supports only der, raw, or hex",
        ),
    ] {
        let error = validate_output_format(algorithm, usage, DeriveFormat::Address).unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidInput { field, ref reason }
            if field == expected_field && reason == expected_reason
        ));
    }
}

#[test]
fn validate_rejects_compressed_output_outside_secp256k1_pubkey_raw_or_hex() {
    for (algorithm, usage, output_format) in [
        (
            crate::DeriveAlgorithm::P256,
            crate::DeriveUse::Pubkey,
            DeriveFormat::Raw,
        ),
        (
            crate::DeriveAlgorithm::Secp256k1,
            crate::DeriveUse::Pubkey,
            DeriveFormat::Address,
        ),
        (
            crate::DeriveAlgorithm::Secp256k1,
            crate::DeriveUse::Sign,
            DeriveFormat::Raw,
        ),
    ] {
        let mut params = params(algorithm, usage, output_format);
        params.compressed = true;
        if usage == crate::DeriveUse::Sign {
            params.payload = Some(SignPayload::Message(Zeroizing::new(b"message".to_vec())));
        }

        let error = validate_params(&params).unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidInput { field: "compressed", ref reason }
            if reason == "compressed output is valid only for secp256k1 pubkey raw/hex derivation"
        ));
    }
}

#[test]
fn sign_message_bytes_rejects_invalid_digest_length() {
    let mut params = params(
        crate::DeriveAlgorithm::P256,
        crate::DeriveUse::Sign,
        DeriveFormat::Raw,
    );
    params.payload = Some(SignPayload::Digest(Zeroizing::new(vec![0xA5; 31])));

    let error = sign_message_bytes(&params).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidInput { field: "digest", ref reason }
        if reason == "sha256 digest must be 32 bytes, got 31 bytes"
    ));
}
