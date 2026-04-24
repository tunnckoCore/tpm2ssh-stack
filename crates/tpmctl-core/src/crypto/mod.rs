//! Software derived-key helpers.
//!
//! The functions in this module derive ephemeral or deterministic software keys
//! from TPM-protected PRF material. They are deliberately separate from TPM-native
//! signing and zeroize temporary seed/scalar buffers where practical.

pub mod derive;
pub mod ed25519;
pub mod ethereum;
pub mod p256;
pub mod secp256k1;

pub use derive::{
    DeriveError, DeriveMode, DeriveRequest, DeriveUse, DerivedAlgorithm, HashSelection, SecretSeed,
};
