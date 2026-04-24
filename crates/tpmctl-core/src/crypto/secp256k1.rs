use crate::Result;

pub fn public_key_from_seed(_seed: &[u8]) -> Result<Vec<u8>> {
    Err(crate::TpmctlError::NotImplemented(
        "crypto::secp256k1::public_key_from_seed",
    ))
}
