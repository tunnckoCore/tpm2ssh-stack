pub fn derive(
    _context: &crate::CommandContext,
    _request: super::DeriveRequest,
) -> crate::Result<super::DeriveResponse> {
    Err(crate::Error::unsupported("crypto::derive::derive"))
}
