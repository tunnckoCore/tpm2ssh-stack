//! Reusable TPMCTL domain library.
//!
//! This crate intentionally contains no command-line parser and no PKCS#11
//! entrypoints. Frontends should call the typed request/response APIs exposed by
//! these modules.

pub mod crypto;
pub mod ecdh;
pub mod error;
pub mod hmac;
pub mod keygen;
pub mod output;
pub mod pubkey;
pub mod seal;
pub mod sign;
pub mod store;
pub mod tpm;

pub use error::{Result, TpmctlError};

/// Key algorithm families understood by TPMCTL commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum KeyAlgorithm {
    P256,
    Ed25519,
    Secp256k1,
    Rsa2048,
}

/// Output encoding requested by a frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum OutputFormat {
    Text,
    Json,
    Pem,
    Ssh,
    Hex,
}

/// Stable registry identifier used by the local key store.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.contains('/') || value.contains('\\') || value.contains("..") {
            return Err(TpmctlError::InvalidKeyId(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
