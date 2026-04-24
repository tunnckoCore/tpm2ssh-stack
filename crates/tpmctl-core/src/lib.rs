//! Minimal tpmctl core API contracts used by the CLI crate.
//!
//! TPM behavior intentionally lives outside the CLI. These request/response
//! shapes are stubs for the domain implementation branches to fill in.

use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Id(String),
    Handle(PersistentHandle),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistentHandle(pub u32);

impl std::fmt::Display for PersistentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("core operation is not implemented yet: {0}")]
    NotImplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Clone)]
pub struct GlobalOptions {
    pub store: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
}

#[derive(Debug, Serialize)]
pub struct CommandResult {
    pub status: &'static str,
    pub operation: &'static str,
}

macro_rules! stub_operation {
    ($name:ident, $request:ident) => {
        pub mod $name {
            use super::*;
            #[derive(Debug, Clone)]
            pub struct $request;
            pub fn run(_globals: &GlobalOptions, _request: $request) -> Result<CommandResult> {
                Err(CoreError::NotImplemented(stringify!($name)))
            }
        }
    };
}

stub_operation!(keygen, Request);
stub_operation!(sign, Request);
stub_operation!(pubkey, Request);
stub_operation!(ecdh, Request);
stub_operation!(hmac, Request);
stub_operation!(seal, Request);
stub_operation!(unseal, Request);
stub_operation!(derive, Request);
