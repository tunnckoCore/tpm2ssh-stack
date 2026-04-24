/// Request to export a public key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PubkeyRequest {
    pub key: crate::IdentityRef,
    pub format: crate::OutputFormat,
}

/// Public key output.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PubkeyResponse {
    pub public_key: crate::EncodedOutput,
}

pub fn pubkey(
    _context: &crate::CommandContext,
    _request: PubkeyRequest,
) -> crate::Result<PubkeyResponse> {
    Err(crate::Error::unsupported("pubkey::pubkey"))
}
