use crate::{KeyId, Result, store::StoreConfig, tpm::TctiConfig};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SealRequest {
    pub id: KeyId,
    pub plaintext: Vec<u8>,
    pub store: StoreConfig,
    pub tcti: TctiConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SealResponse {
    pub id: KeyId,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct UnsealRequest {
    pub id: KeyId,
    pub store: StoreConfig,
    pub tcti: TctiConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct UnsealResponse {
    pub plaintext: Vec<u8>,
}

pub fn seal(_request: SealRequest) -> Result<SealResponse> {
    Err(crate::TpmctlError::NotImplemented("seal::seal"))
}

pub fn unseal(_request: UnsealRequest) -> Result<UnsealResponse> {
    Err(crate::TpmctlError::NotImplemented("seal::unseal"))
}
