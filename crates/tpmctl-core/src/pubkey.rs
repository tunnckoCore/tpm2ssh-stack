use crate::output::encode_p256_public_key;
use crate::{Error, ObjectSelector, OutputFormat, Result, ensure_selector, tpm_todo};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubkeyRequest {
    pub selector: ObjectSelector,
    pub format: OutputFormat,
    /// Optional cached raw SEC1 public key supplied by a caller that already
    /// loaded registry metadata. If absent, TPM/read-public integration is used.
    pub cached_sec1_public_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubkeyResponse {
    pub public_key: Vec<u8>,
    pub format: OutputFormat,
}

impl PubkeyRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_selector(&self.selector)?;
        if !matches!(
            self.format,
            OutputFormat::Raw
                | OutputFormat::Hex
                | OutputFormat::Pem
                | OutputFormat::Der
                | OutputFormat::Ssh
        ) {
            return Err(Error::UnsupportedFormat {
                operation: "pubkey",
                format: self.format,
            });
        }
        Ok(())
    }
}

/// Export a TPM asymmetric public key.
///
/// TODO(tss-esapi): for handles, call ReadPublic; for IDs, load registry
/// metadata/cache or TPM public blob; reject HMAC/sealed objects before encode.
pub fn pubkey(request: PubkeyRequest) -> Result<PubkeyResponse> {
    request.validate()?;
    if let Some(sec1) = &request.cached_sec1_public_key {
        let public_key = encode_p256_public_key(sec1, request.format, &request.selector.comment())?;
        return Ok(PubkeyResponse {
            public_key,
            format: request.format,
        });
    }
    tpm_todo("pubkey: registry cache/read-public integration")
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn pubkey_uses_id_comment_for_ssh() {
        let secret = p256::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let raw = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let res = pubkey(PubkeyRequest {
            selector: ObjectSelector::Id("org/acme/alice/main".into()),
            format: OutputFormat::Ssh,
            cached_sec1_public_key: Some(raw),
        })
        .unwrap();
        assert!(
            String::from_utf8(res.public_key)
                .unwrap()
                .ends_with("org_acme_alice_main\n")
        );
    }
}
