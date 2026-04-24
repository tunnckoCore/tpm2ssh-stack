use crate::{KeyId, Result, store::StoreConfig, tpm::TctiConfig};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SignRequest {
    pub id: KeyId,
    pub message: Vec<u8>,
    pub store: StoreConfig,
    pub tcti: TctiConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SignResponse {
    pub signature: Vec<u8>,
}

pub fn sign(_request: SignRequest) -> Result<SignResponse> {
    Err(crate::TpmctlError::NotImplemented("sign::sign"))
}
