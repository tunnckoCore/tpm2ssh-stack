use crate::output::encode_bytes;
use crate::{
    Error, InputMaterial, ObjectSelector, OutputFormat, Result, ensure_selector, tpm_todo,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcdhRequest {
    pub selector: ObjectSelector,
    pub peer_public_key: InputMaterial,
    pub format: OutputFormat,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcdhResponse {
    pub shared_secret: Vec<u8>,
    pub format: OutputFormat,
}

impl EcdhRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_selector(&self.selector)?;
        if !matches!(self.format, OutputFormat::Raw | OutputFormat::Hex) {
            return Err(Error::UnsupportedFormat {
                operation: "ecdh",
                format: self.format,
            });
        }
        Ok(())
    }
}

/// Generate a shared secret with a TPM ECDH key.
///
/// TODO(tss-esapi): parse peer PEM/DER/SEC1 into TPM2B_ECC_POINT, load ECDH key,
/// verify usage/attributes, call ECDH_ZGen, and encode the returned X coordinate.
pub fn ecdh(request: EcdhRequest) -> Result<EcdhResponse> {
    request.validate()?;
    let _peer = request.peer_public_key.read_all()?;
    tpm_todo("ecdh: TPM ECDH_ZGen integration")
}

pub fn encode_shared_secret(raw: &[u8], format: OutputFormat) -> Result<Vec<u8>> {
    encode_bytes(raw, format, "ecdh")
}
