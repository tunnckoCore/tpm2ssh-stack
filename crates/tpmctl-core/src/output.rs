/// Output encodings shared by core operations and frontends.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum OutputFormat {
    Raw,
    Hex,
    Pem,
    Der,
    Ssh,
    Json,
    Address,
}

/// Bytes plus their semantic format.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EncodedOutput {
    pub format: OutputFormat,
    pub bytes: Vec<u8>,
}

impl EncodedOutput {
    pub fn new(format: OutputFormat, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            format,
            bytes: bytes.into(),
        }
    }
}

/// Encode bytes for a requested output format.
pub fn encode(_bytes: &[u8], _format: OutputFormat) -> crate::Result<EncodedOutput> {
    Err(crate::Error::unsupported("output::encode"))
}
