use super::*;

#[test]
fn seed_rejects_empty_input() {
    assert!(matches!(SecretSeed::new([]), Err(DeriveError::EmptySeed)));
}

#[test]
fn ed25519_sign_rejects_hash_selection() {
    assert_eq!(
        DeriveRequest::new(
            DerivedAlgorithm::Ed25519,
            DeriveUse::Sign,
            Some(HashSelection::Sha256),
        ),
        Err(DeriveError::HashNotAllowedForEd25519Sign),
    );
}

#[test]
fn deterministic_derivation_is_reproducible() {
    let seed = SecretSeed::new(b"seed").unwrap();
    let mode = DeriveMode::deterministic(b"label".to_vec());
    let first = derive_bytes(&seed, &mode, DerivedAlgorithm::P256, b"secret", 0).unwrap();
    let second = derive_bytes(&seed, &mode, DerivedAlgorithm::P256, b"secret", 0).unwrap();
    assert_eq!(*first, *second);
}

#[test]
fn ephemeral_entropy_changes_derivation() {
    let seed = SecretSeed::new(b"seed").unwrap();
    let first_mode = DeriveMode::ephemeral(b"label".to_vec(), b"entropy-1".to_vec());
    let second_mode = DeriveMode::ephemeral(b"label".to_vec(), b"entropy-2".to_vec());
    let first = derive_bytes(&seed, &first_mode, DerivedAlgorithm::P256, b"secret", 0).unwrap();
    let second = derive_bytes(&seed, &second_mode, DerivedAlgorithm::P256, b"secret", 0).unwrap();
    assert_ne!(*first, *second);
}
