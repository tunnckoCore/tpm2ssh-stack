/// Request to compute an HMAC using TPM-backed material.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HmacRequest {
    pub key: crate::IdentityRef,
    pub input: Vec<u8>,
    pub format: crate::OutputFormat,
    pub seal_target: Option<SealTarget>,
}

/// Optional sealing target for an HMAC result.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SealTarget {
    Id(String),
    Path(std::path::PathBuf),
}

/// HMAC output.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HmacResponse {
    pub digest: crate::EncodedOutput,
    pub sealed: Option<String>,
}

pub fn hmac(
    _context: &crate::CommandContext,
    _request: HmacRequest,
) -> crate::Result<HmacResponse> {
    Err(crate::Error::unsupported("hmac::hmac"))
}
