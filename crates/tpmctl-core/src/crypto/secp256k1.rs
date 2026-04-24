use k256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint};
use signature::{Signer, hazmat::PrehashSigner};
use zeroize::Zeroize;

use super::{
    derive::{DeriveError, DeriveMode, DerivedAlgorithm, SecretSeed, derive_valid_secret_key},
    ethereum::{EthereumError, checksum_address_from_public_key},
};

/// Derives a valid non-zero secp256k1 scalar, retrying HKDF output until accepted
/// by the curve implementation.
pub fn derive_secret_key(seed: &SecretSeed, mode: &DeriveMode) -> Result<SecretKey, DeriveError> {
    derive_valid_secret_key(
        seed,
        mode,
        DerivedAlgorithm::Secp256k1,
        b"scalar",
        |candidate| SecretKey::from_slice(candidate).ok(),
    )
}

pub fn derive_public_key_sec1(
    seed: &SecretSeed,
    mode: &DeriveMode,
    compressed: bool,
) -> Result<Vec<u8>, DeriveError> {
    let secret = derive_secret_key(seed, mode)?;
    Ok(public_key_sec1(&secret, compressed))
}

pub fn public_key_sec1(secret: &SecretKey, compressed: bool) -> Vec<u8> {
    secret
        .public_key()
        .to_encoded_point(compressed)
        .as_bytes()
        .to_vec()
}

/// Returns an EIP-55 checksummed Ethereum address for the derived secp256k1 key.
pub fn derive_ethereum_address(
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<String, Secp256k1AddressError> {
    let public = derive_public_key_sec1(seed, mode, false)?;
    checksum_address_from_public_key(&public).map_err(Secp256k1AddressError::Ethereum)
}

/// Signs message bytes using ECDSA/secp256k1. The `k256` ECDSA implementation
/// hashes the message internally according to its signature crate semantics.
pub fn sign_message(
    seed: &SecretSeed,
    mode: &DeriveMode,
    message: &[u8],
) -> Result<Vec<u8>, DeriveError> {
    let secret = derive_secret_key(seed, mode)?;
    let signing_key = SigningKey::from(secret);
    let signature: k256::ecdsa::Signature = signing_key.sign(message);
    signature_to_vec(signature)
}

/// Signs a caller-supplied digest using ECDSA/secp256k1 prehash semantics.
pub fn sign_prehash(
    seed: &SecretSeed,
    mode: &DeriveMode,
    digest: &[u8],
) -> Result<Vec<u8>, DeriveError> {
    let secret = derive_secret_key(seed, mode)?;
    let signing_key = SigningKey::from(secret);
    let signature: k256::ecdsa::Signature = signing_key
        .sign_prehash(digest)
        .map_err(|_| DeriveError::InvalidPrehash)?;
    signature_to_vec(signature)
}

fn signature_to_vec(signature: k256::ecdsa::Signature) -> Result<Vec<u8>, DeriveError> {
    let mut bytes = signature.to_bytes();
    let out = bytes.to_vec();
    bytes.zeroize();
    Ok(out)
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum Secp256k1AddressError {
    #[error(transparent)]
    Derive(#[from] DeriveError),
    #[error(transparent)]
    Ethereum(#[from] EthereumError),
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
        let seed = SecretSeed::new(b"secp seed").unwrap();
        let mode = DeriveMode::deterministic(b"secp label".to_vec());
        let public = derive_public_key_sec1(&seed, &mode, false).unwrap();
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04);
    }

    #[test]
    fn address_format_is_eip55_hex() {
        let seed = SecretSeed::new(b"secp seed").unwrap();
        let mode = DeriveMode::deterministic(b"address".to_vec());
        let address = derive_ethereum_address(&seed, &mode).unwrap();
        assert_eq!(address.len(), 42);
        assert!(address.starts_with("0x"));
    }

    #[test]
    fn derived_signature_is_p1363_width() {
        let seed = SecretSeed::new(b"secp seed").unwrap();
        let mode = DeriveMode::deterministic(b"secp sign".to_vec());
        let signature = sign_message(&seed, &mode, b"message").unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn prehash_matches_internal_sha256_message_signing() {
        let seed = SecretSeed::new(b"secp seed").unwrap();
        let mode = DeriveMode::deterministic(b"secp prehash".to_vec());
        let digest = crate::HashAlgorithm::Sha256.digest(b"message");
        assert_eq!(
            sign_message(&seed, &mode, b"message").unwrap(),
            sign_prehash(&seed, &mode, &digest).unwrap()
        );
    }
}
