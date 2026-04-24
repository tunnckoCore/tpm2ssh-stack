pub fn public_key(
    _seed: &[u8],
    _format: crate::OutputFormat,
) -> crate::Result<crate::EncodedOutput> {
    Err(crate::Error::unsupported("crypto::secp256k1::public_key"))
}
