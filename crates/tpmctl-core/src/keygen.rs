use crate::{KeyAlgorithm, KeyId, Result, store::StoreConfig, tpm::TctiConfig};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct KeygenRequest {
    pub id: KeyId,
    pub algorithm: KeyAlgorithm,
    pub store: StoreConfig,
    pub tcti: TctiConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct KeygenResponse {
    pub id: KeyId,
    pub public_key: Vec<u8>,
}

pub fn keygen(_request: KeygenRequest) -> Result<KeygenResponse> {
    Err(crate::TpmctlError::NotImplemented("keygen::keygen"))
}
