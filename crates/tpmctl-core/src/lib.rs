//! Core request/response types and command-domain logic for `tpmctl`.
//!
//! This crate intentionally owns TPM command semantics, validation, and output
//! encoders, but not CLI parsing.  The TPM integration points are currently
//! narrow skeletons so the crate remains buildable before the final tss-esapi
//! context/load helpers land.

pub mod ecdh;
pub mod hmac;
pub mod keygen;
pub mod output;
pub mod pubkey;
pub mod seal;
pub mod sign;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("unsupported format {format:?} for {operation}")]
    UnsupportedFormat {
        operation: &'static str,
        format: OutputFormat,
    },
    #[error("TPM integration not yet wired: {0}")]
    TpmTodo(&'static str),
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistentHandle(pub u32);

impl std::fmt::Display for PersistentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyUsage {
    Sign,
    Ecdh,
    Hmac,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn digest_len(self) -> usize {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
            Self::Path(path) => Ok(std::fs::read(path)?),
            Self::Stdin => {
                use std::io::Read;
                let mut bytes = Vec::new();
                std::io::stdin().read_to_end(&mut bytes)?;
                Ok(bytes)
            }
        }
    }
}

pub(crate) fn ensure_selector(selector: &ObjectSelector) -> Result<()> {
    match selector {
        ObjectSelector::Id(id) if id.trim().is_empty() => {
            Err(Error::Validation("id must not be empty".into()))
        }
        ObjectSelector::Id(id)
            if id.starts_with('/') || id.split('/').any(|p| p.is_empty() || p == "..") =>
        {
            Err(Error::Validation(
                "id must be relative and must not contain empty or '..' components".into(),
            ))
        }
        ObjectSelector::Id(_) | ObjectSelector::Handle(_) => Ok(()),
    }
}

pub(crate) fn tpm_todo<T>(what: &'static str) -> Result<T> {
    Err(Error::TpmTodo(what))
}
