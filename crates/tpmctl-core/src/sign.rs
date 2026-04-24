use crate::output::encode_ecdsa_p1363;
use crate::{
    Error, HashAlgorithm, InputMaterial, ObjectSelector, OutputFormat, Result, ensure_selector,
    tpm_todo,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignInput {
    Message(InputMaterial),
    Digest(Vec<u8>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub selector: ObjectSelector,
    pub input: SignInput,
    pub hash: HashAlgorithm,
    pub format: OutputFormat,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature: Vec<u8>,
    pub format: OutputFormat,
}

impl SignRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_selector(&self.selector)?;
        if !matches!(
            self.format,
            OutputFormat::Der | OutputFormat::Raw | OutputFormat::Hex
        ) {
            return Err(Error::UnsupportedFormat {
                operation: "sign",
                format: self.format,
            });
        }
        if let SignInput::Digest(digest) = &self.input {
            let expected = self.hash.digest_len();
            if digest.len() != expected {
                return Err(Error::Validation(format!(
                    "digest length {} does not match {:?} length {expected}",
                    digest.len(),
                    self.hash
                )));
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Vec<u8>> {
        match &self.input {
            SignInput::Digest(digest) => Ok(digest.clone()),
            SignInput::Message(input) => Ok(self.hash.digest(&input.read_all()?)),
        }
    }
}

/// Sign a digest/message using a TPM-backed signing key.
///
/// TODO(tss-esapi): load the sign key by registry ID or persistent handle,
/// validate metadata/key attributes, invoke `Context::sign`, and pass the TPM
/// ECDSA `(r, s)` values to `encode_tpm_ecdsa_signature`.
pub fn sign(request: SignRequest) -> Result<SignResponse> {
    request.validate()?;
    let _digest = request.digest()?;
    tpm_todo("sign: TPM Sign call and TPMT_SIGNATURE to P1363 conversion")
}

pub fn encode_tpm_ecdsa_signature(raw_p1363: &[u8], format: OutputFormat) -> Result<Vec<u8>> {
    encode_ecdsa_p1363(raw_p1363, format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_validates_digest_length() {
        let req = SignRequest {
            selector: ObjectSelector::Id("a/b".into()),
            input: SignInput::Digest(vec![0; 31]),
            hash: HashAlgorithm::Sha256,
            format: OutputFormat::Der,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn sign_hashes_message_input() {
        let req = SignRequest {
            selector: ObjectSelector::Id("a/b".into()),
            input: SignInput::Message(InputMaterial::Bytes(b"abc".to_vec())),
            hash: HashAlgorithm::Sha256,
            format: OutputFormat::Raw,
        };
        assert_eq!(req.digest().unwrap().len(), 32);
    }
}
