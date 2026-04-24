/// Request to create a sealed TPM object.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SealRequest {
    pub id: Option<String>,
    pub handle: Option<crate::PersistentHandle>,
    pub input: Vec<u8>,
    pub force: bool,
}

/// Result of creating a sealed TPM object.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SealResponse {
    pub id: Option<String>,
    pub handle: Option<crate::PersistentHandle>,
}

/// Request to unseal a TPM object.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnsealRequest {
    pub object: crate::IdentityRef,
    pub format: crate::OutputFormat,
}

/// Unsealed output.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnsealResponse {
    pub secret: crate::EncodedOutput,
}

pub fn seal(
    _context: &crate::CommandContext,
    _request: SealRequest,
) -> crate::Result<SealResponse> {
    Err(crate::Error::unsupported("seal::seal"))
}

pub fn unseal(
    _context: &crate::CommandContext,
    _request: UnsealRequest,
) -> crate::Result<UnsealResponse> {
    Err(crate::Error::unsupported("seal::unseal"))
}
