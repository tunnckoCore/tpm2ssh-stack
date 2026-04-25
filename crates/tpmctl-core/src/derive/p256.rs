use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint};
#[cfg(test)]
use signature::Signer;
use signature::hazmat::PrehashSigner;
use zeroize::Zeroize;

use super::primitives::{
    DeriveError, DeriveMode, DerivedAlgorithm, SecretSeed, derive_valid_secret_key,
};

/// Derives a valid non-zero P-256 scalar, retrying HKDF output until accepted by
/// the curve implementation.
pub(crate) fn derive_secret_key(
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<SecretKey, DeriveError> {
    derive_valid_secret_key(seed, mode, DerivedAlgorithm::P256, b"scalar", |candidate| {
        SecretKey::from_slice(candidate).ok()
    })
}

pub(crate) fn derive_public_key_sec1(
    seed: &SecretSeed,
    mode: &DeriveMode,
    compressed: bool,
) -> Result<Vec<u8>, DeriveError> {
    let secret = derive_secret_key(seed, mode)?;
    let public = secret.public_key();
    Ok(public.to_encoded_point(compressed).as_bytes().to_vec())
}

#[cfg(test)]
/// Signs message bytes using ECDSA/P-256. The `p256` ECDSA implementation hashes
/// the message internally according to its signature crate semantics.
pub(crate) fn sign_message(
    seed: &SecretSeed,
    mode: &DeriveMode,
    message: &[u8],
) -> Result<Vec<u8>, DeriveError> {
    let secret = derive_secret_key(seed, mode)?;
    let signing_key = SigningKey::from(secret);
    let signature: p256::ecdsa::Signature = signing_key.sign(message);
    signature_to_vec(signature)
}

/// Signs a caller-supplied digest using ECDSA/P-256 prehash semantics.
pub(crate) fn sign_prehash(
    seed: &SecretSeed,
    mode: &DeriveMode,
    digest: &[u8],
) -> Result<Vec<u8>, DeriveError> {
    let secret = derive_secret_key(seed, mode)?;
    let signing_key = SigningKey::from(secret);
    let signature: p256::ecdsa::Signature = signing_key
        .sign_prehash(digest)
        .map_err(|_| DeriveError::InvalidPrehash)?;
    signature_to_vec(signature)
}

fn signature_to_vec(signature: p256::ecdsa::Signature) -> Result<Vec<u8>, DeriveError> {
    let mut bytes = signature.to_bytes();
    let out = bytes.to_vec();
    bytes.zeroize();
    Ok(out)
}

#[cfg(test)]
#[path = "p256.test.rs"]
mod tests;
