use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct TctiConfig {
    pub spec: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PersistentHandle(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AuthValue(pub Vec<u8>);

#[derive(Debug, Default)]
pub struct TpmContext;

pub fn open_context(_config: &TctiConfig) -> Result<TpmContext> {
    Err(crate::TpmctlError::NotImplemented("tpm::open_context"))
}
