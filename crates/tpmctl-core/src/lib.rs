//! Reusable TPM and local-registry core for `tpmctl`.
//!
//! This crate intentionally contains no CLI parsing and no PKCS#11 entrypoints.

pub mod config;
pub mod error;
pub mod handle;
pub mod store;
pub mod tcti;
pub mod tpm;

pub use config::{StoreConfig, StoreRoot};
pub use error::{Error, Result};
pub use handle::PersistentHandle;
pub use store::{Id, ObjectKind, ObjectMetadata, Store, Usage};
pub use tcti::{TctiConfig, TctiSource};
