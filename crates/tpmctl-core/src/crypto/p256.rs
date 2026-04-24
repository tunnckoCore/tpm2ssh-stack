pub fn public_key(
    _seed: &[u8],
    _format: crate::OutputFormat,
) -> crate::Result<crate::EncodedOutput> {
    Err(crate::Error::unsupported("crypto::p256::public_key"))
}
