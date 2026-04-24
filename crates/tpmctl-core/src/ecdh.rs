use crate::{KeyId, Result, store::StoreConfig, tpm::TctiConfig};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EcdhRequest {
    pub id: KeyId,
    pub peer_public_key: Vec<u8>,
    pub store: StoreConfig,
    pub tcti: TctiConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EcdhResponse {
    pub shared_secret: Vec<u8>,
}

pub fn ecdh(_request: EcdhRequest) -> Result<EcdhResponse> {
    Err(crate::TpmctlError::NotImplemented("ecdh::ecdh"))
}
