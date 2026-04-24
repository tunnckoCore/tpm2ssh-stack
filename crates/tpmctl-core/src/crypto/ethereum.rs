use crate::Result;

pub fn checksummed_address(_public_key: &[u8]) -> Result<String> {
    Err(crate::TpmctlError::NotImplemented(
        "crypto::ethereum::checksummed_address",
    ))
}
