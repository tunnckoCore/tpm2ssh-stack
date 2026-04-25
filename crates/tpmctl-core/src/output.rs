use std::str::FromStr;

/// Output encodings shared by core operations and callers.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum OutputFormat {
    Raw,
    Hex,
    Pem,
    Der,
    Ssh,
    Json,
    Address,
}

/// Bytes plus their semantic format.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EncodedOutput {
    pub format: OutputFormat,
    pub bytes: Vec<u8>,
}

impl EncodedOutput {
    pub fn new(format: OutputFormat, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            format,
            bytes: bytes.into(),
        }
    }
}

use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::pkcs8::{EncodePublicKey as _, LineEnding};

use zeroize::Zeroizing;

use crate::{EccCurve, EccPublicKey, Error, Result};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BinaryFormat {
    Raw,
    Hex,
}

impl FromStr for BinaryFormat {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "raw" => Ok(Self::Raw),
            "hex" => Ok(Self::Hex),
            other => Err(Error::invalid(
                "format",
                format!("expected raw or hex; got {other:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SignatureFormat {
    Der,
    Raw,
    Hex,
}

impl FromStr for SignatureFormat {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "der" => Ok(Self::Der),
            "raw" => Ok(Self::Raw),
            "hex" => Ok(Self::Hex),
            other => Err(Error::invalid(
                "format",
                format!("expected der, raw, or hex; got {other:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PublicKeyFormat {
    Raw,
    Hex,
    Pem,
    Der,
    Ssh,
}

impl FromStr for PublicKeyFormat {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "raw" => Ok(Self::Raw),
            "hex" => Ok(Self::Hex),
            "pem" => Ok(Self::Pem),
            "der" => Ok(Self::Der),
            "ssh" => Ok(Self::Ssh),
            other => Err(Error::invalid(
                "format",
                format!("expected raw, hex, pem, der, or ssh; got {other:?}"),
            )),
        }
    }
}

pub fn encode_binary(bytes: &[u8], format: BinaryFormat) -> Vec<u8> {
    match format {
        BinaryFormat::Raw => bytes.to_vec(),
        BinaryFormat::Hex => hex::encode(bytes).into_bytes(),
    }
}

pub fn encode_secret_binary(bytes: &[u8], format: BinaryFormat) -> Zeroizing<Vec<u8>> {
    match format {
        BinaryFormat::Raw => Zeroizing::new(bytes.to_vec()),
        BinaryFormat::Hex => {
            let mut encoded = Zeroizing::new(vec![0_u8; bytes.len() * 2]);
            hex::encode_to_slice(bytes, encoded.as_mut_slice())
                .expect("hex output buffer length is exactly twice the input length");
            encoded
        }
    }
}

pub fn encode_p256_signature(p1363: &[u8], format: SignatureFormat) -> Result<Vec<u8>> {
    if p1363.len() != 64 {
        return Err(Error::invalid(
            "signature",
            format!(
                "P-256 ECDSA signatures must be 64-byte P1363 r||s values, got {} bytes",
                p1363.len()
            ),
        ));
    }

    match format {
        SignatureFormat::Raw => Ok(p1363.to_vec()),
        SignatureFormat::Hex => Ok(hex::encode(p1363).into_bytes()),
        SignatureFormat::Der => {
            let signature = p256::ecdsa::Signature::from_slice(p1363)
                .map_err(|error| Error::invalid("signature", error.to_string()))?;
            Ok(signature.to_der().as_bytes().to_vec())
        }
    }
}

pub fn encode_secp256k1_signature(p1363: &[u8], format: SignatureFormat) -> Result<Vec<u8>> {
    if p1363.len() != 64 {
        return Err(Error::invalid(
            "signature",
            format!(
                "secp256k1 ECDSA signatures must be 64-byte P1363 r||s values, got {} bytes",
                p1363.len()
            ),
        ));
    }

    match format {
        SignatureFormat::Raw => Ok(p1363.to_vec()),
        SignatureFormat::Hex => Ok(hex::encode(p1363).into_bytes()),
        SignatureFormat::Der => {
            let signature = k256::ecdsa::Signature::from_slice(p1363)
                .map_err(|error| Error::invalid("signature", error.to_string()))?;
            Ok(signature.to_der().as_bytes().to_vec())
        }
    }
}

pub fn encode_public_key(
    public_key: &EccPublicKey,
    format: PublicKeyFormat,
    ssh_comment: Option<&str>,
) -> Result<Vec<u8>> {
    match public_key.curve() {
        EccCurve::P256 => encode_p256_public_key(public_key.sec1(), format, ssh_comment),
    }
}

pub fn encode_p256_public_key(
    sec1: &[u8],
    format: PublicKeyFormat,
    ssh_comment: Option<&str>,
) -> Result<Vec<u8>> {
    let key = p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|error| Error::invalid("public_key", error.to_string()))?;

    match format {
        PublicKeyFormat::Raw => Ok(sec1.to_vec()),
        PublicKeyFormat::Hex => Ok(hex::encode(sec1).into_bytes()),
        PublicKeyFormat::Der => key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|error| Error::invalid("public_key", error.to_string())),
        PublicKeyFormat::Pem => key
            .to_public_key_pem(LineEnding::LF)
            .map(|pem| pem.into_bytes())
            .map_err(|error| Error::invalid("public_key", error.to_string())),
        PublicKeyFormat::Ssh => {
            let comment = ssh_comment.unwrap_or("tpmctl-key");
            Ok(format!(
                "ecdsa-sha2-nistp256 {} {comment}",
                STANDARD.encode(ssh_p256_blob(sec1)?)
            )
            .into_bytes())
        }
    }
}

fn ssh_p256_blob(sec1: &[u8]) -> Result<Vec<u8>> {
    p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|error| Error::invalid("public_key", error.to_string()))?;

    let mut blob = Vec::new();
    push_ssh_string(&mut blob, b"ecdsa-sha2-nistp256")?;
    push_ssh_string(&mut blob, b"nistp256")?;
    push_ssh_string(&mut blob, sec1)?;
    Ok(blob)
}

fn push_ssh_string(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| {
        Error::invalid(
            "ssh",
            format!("SSH string too large: {} bytes", value.len()),
        )
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod output_tests {
    use super::*;

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
        let encoded =
            encode_secret_binary(&[0x00, 0x0f, 0x10, 0xab, 0xcd, 0xef], BinaryFormat::Hex);

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
        assert!(encode_p256_signature(&[1, 2, 3], SignatureFormat::Der).is_err());
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
}
