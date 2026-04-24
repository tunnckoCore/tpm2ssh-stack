use crate::{OutputFormat, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedOutput {
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
}

pub fn encode_bytes(_bytes: &[u8], _format: OutputFormat) -> Result<EncodedOutput> {
    Err(crate::TpmctlError::NotImplemented("output::encode_bytes"))
}
