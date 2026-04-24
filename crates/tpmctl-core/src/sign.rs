/// Request to sign a digest or message using TPM-backed material.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignRequest {
    pub key: crate::IdentityRef,
    pub input: SignInput,
    pub format: crate::OutputFormat,
}

/// Input form for signing operations.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SignInput {
    Message(Vec<u8>),
    Digest(Vec<u8>),
}

/// Signature output.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignResponse {
    pub signature: crate::EncodedOutput,
}

pub fn sign(
    _context: &crate::CommandContext,
    _request: SignRequest,
) -> crate::Result<SignResponse> {
    Err(crate::Error::unsupported("sign::sign"))
}
