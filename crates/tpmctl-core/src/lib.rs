//! Reusable TPM and local-registry core for `tpmctl`.
//!
//! This crate intentionally contains no command-line parser and no PKCS#11
//! entrypoints. Frontends should call the typed request/response APIs exposed by
//! these modules.

pub mod config;
pub mod crypto;
pub mod ecdh;
pub mod error;
pub mod handle;
pub mod hmac;
pub mod keygen;
pub mod output;
pub mod pubkey;
pub mod seal;
pub mod sign;
pub mod store;
pub mod tcti;
pub mod tpm;

pub use config::{StoreConfig, StoreRoot};
pub use error::{Error, Result, TpmctlError};
pub use handle::PersistentHandle;
pub use store::{Id, ObjectKind, ObjectMetadata, Store, Usage};
pub use tcti::{TctiConfig, TctiSource};

/// Stable registry identifier used by the local key store.
pub type KeyId = Id;

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
