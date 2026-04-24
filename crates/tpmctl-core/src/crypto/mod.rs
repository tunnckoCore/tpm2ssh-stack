pub mod derive;
pub mod ed25519;
pub mod ethereum;
pub mod p256;
pub mod secp256k1;

/// Software key families derived from TPM-protected PRF material.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum DerivedKeyKind {
    P256,
    Ed25519,
    Secp256k1,
}

/// Shared derived-key request contract.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeriveRequest {
    pub source: crate::IdentityRef,
    pub kind: DerivedKeyKind,
    pub label: Vec<u8>,
}

/// Derived bytes returned by helper workflows.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeriveResponse {
    pub output: crate::EncodedOutput,
}
