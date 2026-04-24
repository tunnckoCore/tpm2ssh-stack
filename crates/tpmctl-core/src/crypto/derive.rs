use crate::{KeyId, Result, crypto::DerivedKeyCurve, store::StoreConfig, tpm::TctiConfig};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DeriveRequest {
    pub id: KeyId,
    pub curve: DerivedKeyCurve,
    pub context: Vec<u8>,
    pub store: StoreConfig,
    pub tcti: TctiConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DeriveResponse {
    pub public_key: Vec<u8>,
}

pub fn derive_key(_request: DeriveRequest) -> Result<DeriveResponse> {
    Err(crate::TpmctlError::NotImplemented(
        "crypto::derive::derive_key",
    ))
}
