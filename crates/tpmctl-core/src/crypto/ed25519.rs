use crate::Result;

pub fn public_key_from_seed(_seed: &[u8]) -> Result<Vec<u8>> {
    Err(crate::TpmctlError::NotImplemented(
        "crypto::ed25519::public_key_from_seed",
    ))
}
