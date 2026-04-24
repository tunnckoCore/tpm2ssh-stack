use crate::{Error, OutputFormat, Result};
use base64::Engine;
use p256::ecdsa::Signature;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{EncodePublicKey, LineEnding};

/// Encodes arbitrary bytes as raw or lowercase hex.
pub fn encode_bytes(
    bytes: &[u8],
    format: OutputFormat,
    operation: &'static str,
) -> Result<Vec<u8>> {
    match format {
        OutputFormat::Raw => Ok(bytes.to_vec()),
        OutputFormat::Hex => Ok(hex::encode(bytes).into_bytes()),
        _ => Err(Error::UnsupportedFormat { operation, format }),
    }
}

/// Encodes a fixed-width ECDSA signature represented as `r || s`.
pub fn encode_ecdsa_p1363(raw: &[u8], format: OutputFormat) -> Result<Vec<u8>> {
    if raw.len() != 64 {
        return Err(Error::InvalidKeyMaterial(format!(
            "expected 64-byte P-256 ECDSA signature, got {} bytes",
            raw.len()
        )));
    }

    match format {
        OutputFormat::Raw => Ok(raw.to_vec()),
        OutputFormat::Hex => Ok(hex::encode(raw).into_bytes()),
        OutputFormat::Der => {
            let signature = Signature::from_slice(raw).map_err(|err| {
                Error::InvalidKeyMaterial(format!("invalid ECDSA signature: {err}"))
            })?;
            Ok(signature.to_der().as_bytes().to_vec())
        }
        _ => Err(Error::UnsupportedFormat {
            operation: "sign",
            format,
        }),
    }
}

/// Encodes a P-256 public key from raw SEC1 bytes.
pub fn encode_p256_public_key(sec1: &[u8], format: OutputFormat, comment: &str) -> Result<Vec<u8>> {
    let public_key = p256::PublicKey::from_sec1_bytes(sec1).map_err(|err| {
        Error::InvalidKeyMaterial(format!("invalid P-256 SEC1 public key: {err}"))
    })?;
    let point = public_key.to_encoded_point(false);
    let raw = point.as_bytes();

    match format {
        OutputFormat::Raw => Ok(raw.to_vec()),
        OutputFormat::Hex => Ok(hex::encode(raw).into_bytes()),
        OutputFormat::Der => Ok(public_key
            .to_public_key_der()
            .map_err(|err| Error::InvalidKeyMaterial(format!("SPKI DER encode failed: {err}")))?
            .as_bytes()
            .to_vec()),
        OutputFormat::Pem => Ok(public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|err| Error::InvalidKeyMaterial(format!("SPKI PEM encode failed: {err}")))?
            .into_bytes()),
        OutputFormat::Ssh => encode_p256_ssh_public_key(raw, comment),
    }
}

fn encode_p256_ssh_public_key(uncompressed_sec1: &[u8], comment: &str) -> Result<Vec<u8>> {
    if uncompressed_sec1.len() != 65 || uncompressed_sec1[0] != 0x04 {
        return Err(Error::InvalidKeyMaterial(
            "OpenSSH P-256 export requires uncompressed 65-byte SEC1 point".into(),
        ));
    }

    let mut blob = Vec::new();
    put_ssh_string(&mut blob, b"ecdsa-sha2-nistp256");
    put_ssh_string(&mut blob, b"nistp256");
    put_ssh_string(&mut blob, uncompressed_sec1);

    let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
    Ok(format!("ecdsa-sha2-nistp256 {b64} {comment}\n").into_bytes())
}

fn put_ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_raw_to_hex_and_der() {
        let mut raw = [0u8; 64];
        raw[31] = 1;
        raw[63] = 2;
        assert_eq!(
            encode_ecdsa_p1363(&raw, OutputFormat::Hex).unwrap(),
            hex::encode(raw).into_bytes()
        );
        assert!(
            encode_ecdsa_p1363(&raw, OutputFormat::Der)
                .unwrap()
                .starts_with(&[0x30])
        );
    }

    #[test]
    fn p256_public_key_formats() {
        let secret = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let public = secret.public_key();
        let raw = public.to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(
            encode_p256_public_key(&raw, OutputFormat::Raw, "id").unwrap(),
            raw
        );
        assert!(
            String::from_utf8(encode_p256_public_key(&raw, OutputFormat::Pem, "id").unwrap())
                .unwrap()
                .contains("BEGIN PUBLIC KEY")
        );
        assert!(
            String::from_utf8(encode_p256_public_key(&raw, OutputFormat::Ssh, "id").unwrap())
                .unwrap()
                .starts_with("ecdsa-sha2-nistp256 ")
        );
    }
}
