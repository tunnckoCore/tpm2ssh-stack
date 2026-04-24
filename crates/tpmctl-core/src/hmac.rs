use crate::{KeyId, Result, store::StoreConfig, tpm::TctiConfig};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HmacRequest {
    pub id: KeyId,
    pub data: Vec<u8>,
    pub store: StoreConfig,
    pub tcti: TctiConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HmacResponse {
    pub mac: Vec<u8>,
}

pub fn hmac(_request: HmacRequest) -> Result<HmacResponse> {
    Err(crate::TpmctlError::NotImplemented("hmac::hmac"))
}
