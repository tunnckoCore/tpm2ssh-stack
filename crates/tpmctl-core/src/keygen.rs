/// Request to create a TPM-backed identity.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenRequest {
    pub id: String,
    pub usage: crate::KeyUsage,
    pub handle: Option<crate::PersistentHandle>,
    pub force: bool,
}

/// Result of creating a TPM-backed identity.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenResponse {
    pub id: String,
    pub usage: crate::KeyUsage,
    pub handle: Option<crate::PersistentHandle>,
    pub public_key: Option<crate::EncodedOutput>,
}

pub fn keygen(
    _context: &crate::CommandContext,
    _request: KeygenRequest,
) -> crate::Result<KeygenResponse> {
    Err(crate::Error::unsupported("keygen::keygen"))
}
