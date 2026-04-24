use crate::{KeyUsage, ObjectSelector, PersistentHandle, Result, ensure_selector, tpm_todo};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeygenRequest {
    pub id: String,
    pub usage: KeyUsage,
    pub persist_handle: Option<PersistentHandle>,
    pub force: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeygenResponse {
    pub id: String,
    pub usage: KeyUsage,
    pub persistent_handle: Option<PersistentHandle>,
    pub public_key: Option<Vec<u8>>,
}

impl KeygenRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_selector(&ObjectSelector::Id(self.id.clone()))
    }
}

/// Create a TPM-backed key object for signing, ECDH, or HMAC.
///
/// TODO(tss-esapi): create/load primary parent; create child using the selected
/// template; optionally EvictControl to `persist_handle`; store public/private
/// blobs and metadata via the registry helpers.
pub fn keygen(request: KeygenRequest) -> Result<KeygenResponse> {
    request.validate()?;
    tpm_todo(match request.usage {
        KeyUsage::Sign => {
            "keygen sign: create P-256 restricted/decrypt=false signing key via tss-esapi"
        }
        KeyUsage::Ecdh => "keygen ecdh: create P-256 decrypt/ECDH key via tss-esapi",
        KeyUsage::Hmac => "keygen hmac: create keyed-hash HMAC key via tss-esapi",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_rejects_bad_id() {
        let req = KeygenRequest {
            id: "../bad".into(),
            usage: KeyUsage::Sign,
            persist_handle: None,
            force: false,
        };
        assert!(req.validate().is_err());
    }
}
