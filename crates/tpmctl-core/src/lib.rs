//! Shared public contracts for the `tpmctl` workspace.
//!
//! This crate is intentionally library-first: TPM semantics, registry access,
//! output encoders, and derived-key helpers live here. Frontends such as the CLI
//! and PKCS#11 provider should depend on these typed contracts rather than
//! shelling out to another binary.

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

pub use error::{CoreError, Error, Result};
pub use output::{EncodedOutput, OutputFormat};
pub use store::{IdentityRef, ObjectKind, RegistryId, Store, StoreOptions};
pub use tpm::{CommandContext, KeyUsage, PersistentHandle};
