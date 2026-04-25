use super::{derive_public_key_sec1, sign_message, sign_prehash};
use crate::derive::primitives::{DeriveMode, SecretSeed, retry_valid_candidate_for_test};
use p256::SecretKey;

#[test]
fn scalar_retry_skips_zero_and_accepts_non_zero() {
    let secret =
        retry_valid_candidate_for_test(|candidate| SecretKey::from_slice(candidate).ok()).unwrap();
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
fn derived_signature_verifies_with_corresponding_public_key() {
    use p256::ecdsa::{Signature, VerifyingKey};
    use signature::Verifier;

    let seed = SecretSeed::new(b"p256 seed").unwrap();
    let mode = DeriveMode::deterministic(b"p256 verify".to_vec());
    let message = b"message";
    let public = derive_public_key_sec1(&seed, &mode, false).unwrap();
    let signature = Signature::from_slice(&sign_message(&seed, &mode, message).unwrap()).unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public).unwrap();

    verifying_key.verify(message, &signature).unwrap();
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
