use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use super::derive::{DeriveError, DeriveMode, DerivedAlgorithm, SecretSeed, derive_bytes};

pub fn derive_signing_key(seed: &SecretSeed, mode: &DeriveMode) -> Result<SigningKey, DeriveError> {
    let seed = derive_bytes(seed, mode, DerivedAlgorithm::Ed25519, b"seed", 0)?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn derive_verifying_key(
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<VerifyingKey, DeriveError> {
    Ok(derive_signing_key(seed, mode)?.verifying_key())
}

pub fn derive_public_key_bytes(
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<[u8; 32], DeriveError> {
    Ok(derive_verifying_key(seed, mode)?.to_bytes())
}

/// Signs message bytes with pure Ed25519. Ed25519ph/hash selection is
/// intentionally not implemented for v1; request validation rejects it.
pub fn sign_message(
    seed: &SecretSeed,
    mode: &DeriveMode,
    message: &[u8],
) -> Result<Vec<u8>, DeriveError> {
    let signing_key = derive_signing_key(seed, mode)?;
    let signature = Zeroizing::new(signing_key.sign(message).to_bytes());
    Ok(signature.as_slice().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive::{DeriveRequest, DeriveUse, HashSelection};

    #[test]
    fn public_key_is_32_bytes() {
        let seed = SecretSeed::new(b"ed seed").unwrap();
        let mode = DeriveMode::deterministic(b"ed label".to_vec());
        let public = derive_public_key_bytes(&seed, &mode).unwrap();
        assert_eq!(public.len(), 32);
    }

    #[test]
    fn signature_is_64_bytes() {
        let seed = SecretSeed::new(b"ed seed").unwrap();
        let mode = DeriveMode::deterministic(b"ed sign".to_vec());
        let signature = sign_message(&seed, &mode, b"message").unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn request_validation_rejects_hash_for_ed25519_sign() {
        assert!(
            DeriveRequest::new(
                DerivedAlgorithm::Ed25519,
                DeriveUse::Sign,
                Some(HashSelection::Sha512),
            )
            .is_err()
        );
    }
}
