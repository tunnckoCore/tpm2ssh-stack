use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint};
use signature::{Signer, hazmat::PrehashSigner};
use zeroize::Zeroize;

use super::derive::{
    DeriveError, DeriveMode, DerivedAlgorithm, SecretSeed, derive_valid_secret_key,
};

/// Derives a valid non-zero P-256 scalar, retrying HKDF output until accepted by
/// the curve implementation.
pub fn derive_secret_key(seed: &SecretSeed, mode: &DeriveMode) -> Result<SecretKey, DeriveError> {
    derive_valid_secret_key(seed, mode, DerivedAlgorithm::P256, b"scalar", |candidate| {
        SecretKey::from_slice(candidate).ok()
    })
}

pub fn derive_public_key_sec1(
    seed: &SecretSeed,
    mode: &DeriveMode,
    compressed: bool,
) -> Result<Vec<u8>, DeriveError> {
    let secret = derive_secret_key(seed, mode)?;
    let public = secret.public_key();
    Ok(public.to_encoded_point(compressed).as_bytes().to_vec())
}

pub fn public_key_sec1(secret: &SecretKey, compressed: bool) -> Vec<u8> {
    secret
        .public_key()
        .to_encoded_point(compressed)
        .as_bytes()
        .to_vec()
}

/// Signs message bytes using ECDSA/P-256. The `p256` ECDSA implementation hashes
/// the message internally according to its signature crate semantics.
pub fn sign_message(
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
pub fn sign_prehash(
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
mod tests {
    use super::*;
    use crate::crypto::derive::retry_valid_candidate_for_test;

    #[test]
    fn scalar_retry_skips_zero_and_accepts_non_zero() {
        let secret =
            retry_valid_candidate_for_test(|candidate| SecretKey::from_slice(candidate).ok())
                .unwrap();
        let raw: [u8; 32] = secret.to_bytes().into();
        assert_ne!(raw, [0_u8; 32]);
    }

    #[test]
    fn derived_public_key_is_uncompressed_sec1() {
        let seed = SecretSeed::new(b"p256 seed").unwrap();
        let mode = DeriveMode::deterministic(b"p256 label".to_vec());
        let public = derive_public_key_sec1(&seed, &mode, false).unwrap();
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04);
    }

    #[test]
    fn derived_signature_is_p1363_width() {
        let seed = SecretSeed::new(b"p256 seed").unwrap();
        let mode = DeriveMode::deterministic(b"p256 sign".to_vec());
        let signature = sign_message(&seed, &mode, b"message").unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn prehash_matches_internal_sha256_message_signing() {
        let seed = SecretSeed::new(b"p256 seed").unwrap();
        let mode = DeriveMode::deterministic(b"p256 prehash".to_vec());
        let digest = crate::HashAlgorithm::Sha256.digest(b"message");
        assert_eq!(
            sign_message(&seed, &mode, b"message").unwrap(),
            sign_prehash(&seed, &mode, &digest).unwrap()
        );
    }
}
