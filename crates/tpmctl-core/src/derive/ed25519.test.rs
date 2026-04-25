use super::*;
use crate::derive::primitives::{DeriveRequest, DeriveUse, HashSelection};

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
fn derived_signature_verifies_with_corresponding_public_key() {
    use ed25519_dalek::{Signature, Verifier as _};

    let seed = SecretSeed::new(b"ed seed").unwrap();
    let mode = DeriveMode::deterministic(b"ed verify".to_vec());
    let message = b"message";
    let verifying_key = derive_verifying_key(&seed, &mode).unwrap();
    let signature = Signature::from_slice(&sign_message(&seed, &mode, message).unwrap()).unwrap();

    verifying_key.verify(message, &signature).unwrap();
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
