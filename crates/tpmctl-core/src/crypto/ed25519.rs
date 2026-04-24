pub fn public_key(
    _seed: &[u8],
    _format: crate::OutputFormat,
) -> crate::Result<crate::EncodedOutput> {
    Err(crate::Error::unsupported("crypto::ed25519::public_key"))
}
