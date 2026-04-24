/// Request to compute ECDH with a TPM-backed identity.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EcdhRequest {
    pub key: crate::IdentityRef,
    pub peer_public_key: Vec<u8>,
    pub format: crate::OutputFormat,
}

/// ECDH shared secret output.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EcdhResponse {
    pub shared_secret: crate::EncodedOutput,
}

pub fn ecdh(
    _context: &crate::CommandContext,
    _request: EcdhRequest,
) -> crate::Result<EcdhResponse> {
    Err(crate::Error::unsupported("ecdh::ecdh"))
}
