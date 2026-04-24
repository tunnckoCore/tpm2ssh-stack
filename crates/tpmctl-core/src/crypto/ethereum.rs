pub fn checksum_address(_public_key: &[u8]) -> crate::Result<String> {
    Err(crate::Error::unsupported(
        "crypto::ethereum::checksum_address",
    ))
}
