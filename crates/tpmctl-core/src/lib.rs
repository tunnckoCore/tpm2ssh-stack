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

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use config::{StoreConfig, StoreRoot};
pub use error::{Error, Result, TpmctlError};
pub use handle::PersistentHandle;
pub use store::{Id, ObjectKind, ObjectMetadata, Store, Usage};
pub use tcti::{TctiConfig, TctiSource};

/// Stable registry identifier used by the local key store.
pub type KeyId = Id;

/// Target selector for operations over existing TPM/local-registry material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectSelector {
    Id(String),
    Handle(PersistentHandle),
}

impl ObjectSelector {
    pub fn comment(&self) -> String {
        match self {
            Self::Id(id) => id.replace('/', "_"),
            Self::Handle(handle) => handle.to_string(),
        }
    }
}

/// Backwards-compatible selector name used by CLI parser code.
pub type Target = ObjectSelector;

/// Key algorithm families understood by TPMCTL commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    P256,
    Ed25519,
    Secp256k1,
    Rsa2048,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyUsage {
    Sign,
    Ecdh,
    Hmac,
}

/// Hash algorithms accepted by signing/HMAC frontends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digest(self, bytes: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256, Sha384, Sha512};
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }
}

/// Output encoding requested by a frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Raw,
    Hex,
    Der,
    Pem,
    Ssh,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum InputMaterial {
    Bytes(Vec<u8>),
    Path(PathBuf),
    Stdin,
}

impl InputMaterial {
    pub fn read_all(&self) -> Result<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Ok(bytes.clone()),
            Self::Path(path) => std::fs::read(path).map_err(|error| TpmctlError::Io {
                path: path.clone(),
                source: error,
            }),
            Self::Stdin => {
                use std::io::Read;
                let mut bytes = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut bytes)
                    .map_err(|error| TpmctlError::InvalidInput(error.to_string()))?;
                Ok(bytes)
            }
        }
    }
}

pub(crate) fn ensure_selector(selector: &ObjectSelector) -> Result<()> {
    match selector {
        ObjectSelector::Id(id) if id.trim().is_empty() => {
            Err(TpmctlError::Validation("id must not be empty".into()))
        }
        ObjectSelector::Id(id)
            if id.starts_with('/') || id.split('/').any(|p| p.is_empty() || p == "..") =>
        {
            Err(TpmctlError::Validation(
                "id must be relative and must not contain empty or '..' components".into(),
            ))
        }
        ObjectSelector::Id(_) | ObjectSelector::Handle(_) => Ok(()),
    }
}

pub(crate) fn tpm_todo<T>(what: &'static str) -> Result<T> {
    Err(TpmctlError::TpmTodo(what))
}
