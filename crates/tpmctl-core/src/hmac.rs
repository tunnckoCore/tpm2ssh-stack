use crate::output::encode_bytes;
use crate::{
    Error, HashAlgorithm, InputMaterial, ObjectSelector, OutputFormat, PersistentHandle, Result,
    ensure_selector, tpm_todo,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HmacSealTarget {
    Id(String),
    Handle(PersistentHandle),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HmacRequest {
    pub selector: ObjectSelector,
    pub input: InputMaterial,
    pub hash: HashAlgorithm,
    pub format: OutputFormat,
    pub seal_target: Option<HmacSealTarget>,
    pub emit_when_sealing: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HmacResponse {
    pub output: Option<Vec<u8>>,
    pub sealed: Option<HmacSealTarget>,
    pub hash: HashAlgorithm,
    pub format: OutputFormat,
}

impl HmacRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_selector(&self.selector)?;
        if !matches!(self.format, OutputFormat::Raw | OutputFormat::Hex) {
            return Err(Error::UnsupportedFormat {
                operation: "hmac",
                format: self.format,
            });
        }
        if let Some(HmacSealTarget::Id(id)) = &self.seal_target {
            ensure_selector(&ObjectSelector::Id(id.clone()))?;
        }
        Ok(())
    }
}

/// Compute a TPM HMAC/PRF output, optionally sealing it.
///
/// TODO(tss-esapi): load keyed-hash object, call HMAC or sequence APIs; if a
/// seal target is present, create a sealed data object from the HMAC result and
/// persist/store it without emitting bytes unless requested.
pub fn hmac(request: HmacRequest) -> Result<HmacResponse> {
    request.validate()?;
    let _input = request.input.read_all()?;
    tpm_todo("hmac: TPM HMAC/HMAC sequence and optional seal integration")
}

pub fn encode_hmac_output(raw: &[u8], format: OutputFormat) -> Result<Vec<u8>> {
    encode_bytes(raw, format, "hmac")
}

pub fn zeroize_after_use(bytes: &mut Vec<u8>) {
    bytes.zeroize();
}
