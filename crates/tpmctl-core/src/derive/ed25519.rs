use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use super::primitives::{DeriveError, DeriveMode, DerivedAlgorithm, SecretSeed, derive_bytes};

pub(super) fn derive_signing_key(
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<SigningKey, DeriveError> {
    let seed = derive_bytes(seed, mode, DerivedAlgorithm::Ed25519, b"seed", 0)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn derive_verifying_key(seed: &SecretSeed, mode: &DeriveMode) -> Result<VerifyingKey, DeriveError> {
    Ok(derive_signing_key(seed, mode)?.verifying_key())
}

pub(super) fn derive_public_key_bytes(
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<[u8; 32], DeriveError> {
    Ok(derive_verifying_key(seed, mode)?.to_bytes())
}

/// Signs message bytes with pure Ed25519. Ed25519ph/hash selection is
/// intentionally not implemented for v1; request validation rejects it.
pub(super) fn sign_message(
    seed: &SecretSeed,
    mode: &DeriveMode,
    message: &[u8],
) -> Result<Vec<u8>, DeriveError> {
    let signing_key = derive_signing_key(seed, mode)?;
    let signature = Zeroizing::new(signing_key.sign(message).to_bytes());
    Ok(signature.as_slice().to_vec())
}

#[cfg(test)]
#[path = "ed25519.test.rs"]
mod tests;
