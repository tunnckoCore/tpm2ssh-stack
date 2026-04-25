use super::*;
use crate::CoreError;

fn base_point_sec1() -> Vec<u8> {
    hex::decode(concat!(
        "04",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    ))
    .unwrap()
}

#[test]
fn output_hex_encoding_is_lowercase_without_newline() {
    assert_eq!(encode_binary(&[0xab, 0xcd], BinaryFormat::Hex), b"abcd");
}

#[test]
fn secret_hex_encoding_is_exact_lowercase_bytes_without_newline() {
    let encoded = encode_secret_binary(&[0x00, 0x0f, 0x10, 0xab, 0xcd, 0xef], BinaryFormat::Hex);

    assert_eq!(encoded.as_slice(), b"000f10abcdef");
    assert!(!encoded.as_slice().contains(&b'\n'));
    assert!(!encoded.as_slice().iter().any(u8::is_ascii_uppercase));
}

#[test]
fn secret_raw_encoding_is_exact_input_bytes() {
    let bytes = [0x00, b'\n', 0xff, b'A'];

    assert_eq!(
        encode_secret_binary(&bytes, BinaryFormat::Raw).as_slice(),
        bytes
    );
}

#[test]
fn output_signature_formats_raw_hex_and_der() {
    let mut p1363 = vec![0_u8; 64];
    p1363[31] = 1;
    p1363[63] = 2;

    assert_eq!(
        encode_p256_signature(&p1363, SignatureFormat::Raw).unwrap(),
        p1363
    );
    assert_eq!(
        encode_p256_signature(&p1363, SignatureFormat::Hex).unwrap(),
        hex::encode(&p1363).into_bytes()
    );
    assert_eq!(
        encode_p256_signature(&p1363, SignatureFormat::Der).unwrap(),
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
    );
}

#[test]
fn output_rejects_wrong_signature_length() {
    let error = encode_p256_signature(&[1, 2, 3], SignatureFormat::Der)
        .expect_err("short P-256 signature should be rejected");
    match error {
        CoreError::InvalidInput { field, reason } => {
            assert_eq!(field, "signature");
            assert!(reason.contains("64-byte P1363"));
            assert!(reason.contains("3 bytes"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn output_rejects_invalid_p256_signature_values_for_der() {
    let mut p1363 = hex::decode(concat!(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "0000000000000000000000000000000000000000000000000000000000000001"
    ))
    .unwrap();

    let error = encode_p256_signature(&p1363, SignatureFormat::Der)
        .expect_err("P-256 scalars at curve order should be rejected");
    match error {
        CoreError::InvalidInput { field, reason } => {
            assert_eq!(field, "signature");
            assert!(!reason.is_empty());
        }
        other => panic!("unexpected error: {other:?}"),
    }

    p1363.fill(0);
    let zero_error = encode_p256_signature(&p1363, SignatureFormat::Der)
        .expect_err("zero P-256 signature should be rejected");
    assert!(matches!(
        zero_error,
        CoreError::InvalidInput {
            field: "signature",
            ..
        }
    ));
}

#[test]
fn output_formats_and_validates_secp256k1_signatures() {
    let mut p1363 = vec![0_u8; 64];
    p1363[31] = 1;
    p1363[63] = 2;

    assert_eq!(
        encode_secp256k1_signature(&p1363, SignatureFormat::Raw).unwrap(),
        p1363
    );
    assert_eq!(
        encode_secp256k1_signature(&p1363, SignatureFormat::Hex).unwrap(),
        hex::encode(&p1363).into_bytes()
    );
    assert_eq!(
        encode_secp256k1_signature(&p1363, SignatureFormat::Der).unwrap(),
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
    );
}

#[test]
fn output_rejects_invalid_secp256k1_signature_lengths_and_values() {
    let short_error = encode_secp256k1_signature(&[1, 2, 3], SignatureFormat::Der)
        .expect_err("short secp256k1 signature should be rejected");
    match short_error {
        CoreError::InvalidInput { field, reason } => {
            assert_eq!(field, "signature");
            assert!(reason.contains("64-byte P1363"));
            assert!(reason.contains("3 bytes"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let mut p1363 = hex::decode(concat!(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        "0000000000000000000000000000000000000000000000000000000000000001"
    ))
    .unwrap();
    let value_error = encode_secp256k1_signature(&p1363, SignatureFormat::Der)
        .expect_err("secp256k1 scalars at curve order should be rejected");
    match value_error {
        CoreError::InvalidInput { field, reason } => {
            assert_eq!(field, "signature");
            assert!(!reason.is_empty());
        }
        other => panic!("unexpected error: {other:?}"),
    }

    p1363.fill(0);
    let zero_error = encode_secp256k1_signature(&p1363, SignatureFormat::Der)
        .expect_err("zero secp256k1 signature should be rejected");
    assert!(matches!(
        zero_error,
        CoreError::InvalidInput {
            field: "signature",
            ..
        }
    ));
}

#[test]
fn output_public_key_formats() {
    let sec1 = base_point_sec1();
    let public_key = EccPublicKey::p256_sec1(sec1.clone()).unwrap();

    assert_eq!(
        encode_public_key(&public_key, PublicKeyFormat::Raw, None).unwrap(),
        sec1
    );
    assert_eq!(
        encode_public_key(&public_key, PublicKeyFormat::Hex, None).unwrap(),
        hex::encode(&sec1).into_bytes()
    );
    assert!(
        String::from_utf8(encode_public_key(&public_key, PublicKeyFormat::Pem, None).unwrap())
            .unwrap()
            .contains("BEGIN PUBLIC KEY")
    );
    assert!(
        encode_public_key(&public_key, PublicKeyFormat::Der, None)
            .unwrap()
            .starts_with(&[0x30])
    );
    let ssh = String::from_utf8(
        encode_public_key(&public_key, PublicKeyFormat::Ssh, Some("org_acme_alice")).unwrap(),
    )
    .unwrap();
    assert!(ssh.starts_with("ecdsa-sha2-nistp256 "));
    assert!(ssh.ends_with(" org_acme_alice"));
}

#[test]
fn output_rejects_invalid_public_key_encodings() {
    for format in [
        PublicKeyFormat::Raw,
        PublicKeyFormat::Hex,
        PublicKeyFormat::Pem,
        PublicKeyFormat::Der,
        PublicKeyFormat::Ssh,
    ] {
        let error = encode_p256_public_key(&[0x04, 0x01, 0x02, 0x03], format, Some("comment"))
            .expect_err("invalid SEC1 public key should be rejected");
        match error {
            CoreError::InvalidInput { field, reason } => {
                assert_eq!(field, "public_key");
                assert!(!reason.is_empty());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
