use crate::{KeyId, OutputFormat, Result, store::StoreConfig, tpm::TctiConfig};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PubkeyRequest {
    pub id: KeyId,
    pub format: OutputFormat,
    pub store: StoreConfig,
    pub tcti: TctiConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PubkeyResponse {
    pub public_key: Vec<u8>,
}

pub fn pubkey(_request: PubkeyRequest) -> Result<PubkeyResponse> {
    Err(crate::TpmctlError::NotImplemented("pubkey::pubkey"))
}
