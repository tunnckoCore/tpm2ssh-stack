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

use std::{fmt, str::FromStr};

use sha2::{Digest as _, Sha256, Sha384, Sha512};

pub use error::{CoreError, Error, Result};
pub use output::{EncodedOutput, OutputFormat};
pub use store::{IdentityRef, ObjectKind, RegistryId, Store, StoreOptions};
pub use tpm::{CommandContext, KeyUsage, PersistentHandle};

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sign => "sign",
            Self::Ecdh => "ecdh",
            Self::Hmac => "hmac",
            Self::Sealed => "sealed",
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

    pub fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(input).to_vec(),
            Self::Sha384 => Sha384::digest(input).to_vec(),
            Self::Sha512 => Sha512::digest(input).to_vec(),
        }
    }

    pub fn validate_digest(self, digest: &[u8]) -> Result<()> {
        let expected = self.digest_len();
        if digest.len() == expected {
            Ok(())
        } else {
            Err(Error::invalid(
                "digest",
                format!(
                    "{} digest must be {expected} bytes, got {} bytes",
                    self,
                    digest.len()
                ),
            ))
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        })
    }
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "sha256" | "SHA256" | "sha-256" => Ok(Self::Sha256),
            "sha384" | "SHA384" | "sha-384" => Ok(Self::Sha384),
            "sha512" | "SHA512" | "sha-512" => Ok(Self::Sha512),
            other => Err(Error::invalid(
                "hash",
                format!("expected sha256, sha384, or sha512; got {other:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ObjectSelector {
    Id(RegistryId),
    Handle(PersistentHandle),
}

impl ObjectSelector {
    pub fn ssh_comment(&self) -> String {
        match self {
            Self::Id(id) => id.ssh_comment(),
            Self::Handle(handle) => handle.to_string(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObjectDescriptor {
    pub selector: ObjectSelector,
    pub usage: KeyUsage,
    pub curve: Option<EccCurve>,
    pub hash: Option<HashAlgorithm>,
    pub public_key: Option<EccPublicKey>,
}

impl ObjectDescriptor {
    pub fn require_usage(&self, expected: KeyUsage) -> Result<()> {
        if self.usage == expected {
            Ok(())
        } else {
            Err(Error::invalid(
                "usage",
                format!("expected {expected} object, got {}", self.usage),
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EccCurve {
    P256,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EccPublicKey {
    curve: EccCurve,
    sec1: Vec<u8>,
}

impl EccPublicKey {
    pub fn p256_sec1(sec1: impl Into<Vec<u8>>) -> Result<Self> {
        let sec1 = sec1.into();
        p256::PublicKey::from_sec1_bytes(&sec1)
            .map_err(|error| Error::invalid("public_key", error.to_string()))?;
        Ok(Self {
            curve: EccCurve::P256,
            sec1,
        })
    }

    pub fn curve(&self) -> EccCurve {
        self.curve
    }

    pub fn sec1(&self) -> &[u8] {
        &self.sec1
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SealTarget {
    Id(RegistryId),
    Handle(PersistentHandle),
}

pub fn unsupported_without_tpm(operation: &'static str) -> Error {
    Error::tpm_unavailable(format!(
        "{operation} requires the TPM/store foundation and a reachable TPM or simulator"
    ))
}
