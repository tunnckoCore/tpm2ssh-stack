use crate::{InputMaterial, ObjectSelector, Result, ensure_selector, tpm_todo};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealRequest {
    pub target: ObjectSelector,
    pub input: InputMaterial,
    pub force: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealResponse {
    pub target: ObjectSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsealRequest {
    pub selector: ObjectSelector,
    pub force_stdout: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsealResponse {
    pub secret: Vec<u8>,
}

impl SealRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_selector(&self.target)
    }
}

impl UnsealRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_selector(&self.selector)
    }
}

/// Seal arbitrary bytes to a TPM object, storing by ID or persistent handle.
///
/// TODO(tss-esapi): create sealed data object under the owner primary, persist
/// with EvictControl for handles or save public/private blobs and metadata for IDs.
pub fn seal(request: SealRequest) -> Result<SealResponse> {
    request.validate()?;
    let mut bytes = request.input.read_all()?;
    bytes.zeroize();
    tpm_todo("seal: TPM sealed-data object create/store integration")
}

/// Unseal arbitrary bytes from a TPM sealed object.
///
/// TODO(tss-esapi): load sealed object by ID/handle, call Unseal, return bytes;
/// caller owns output destination and TTY policy.
pub fn unseal(request: UnsealRequest) -> Result<UnsealResponse> {
    request.validate()?;
    tpm_todo("unseal: TPM Unseal integration")
}

pub fn zeroize_unsealed(response: &mut UnsealResponse) {
    response.secret.zeroize();
}
