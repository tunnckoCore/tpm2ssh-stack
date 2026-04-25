//! TPM helper library: typed TPM object management, registry access, output
//! encoders, ECDH/HMAC/signing helpers, and derived software-key operations.

pub mod api;
pub mod derive;
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

pub use error::{CoreError, Error, Result};
pub use output::{EncodedOutput, OutputFormat};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
pub use store::{IdentityRef, ObjectKind, RegistryId, Store, StoreOptions};
pub use tpm::{CommandContext, KeyUsage, PersistentHandle};

/// Signature encodings supported by signing operations.
pub type SignatureFormat = output::SignatureFormat;
/// Public-key encodings supported by public-key export operations.
pub type PublicKeyFormat = output::PublicKeyFormat;
/// Binary/text encodings supported by byte-output operations.
pub type BinaryTextFormat = output::BinaryFormat;
/// Algorithms supported by derived software-key operations.
pub type DeriveAlgorithm = derive::DerivedAlgorithm;
/// Output uses supported by derived software-key operations.
pub type DeriveUse = derive::DeriveUse;

/// Caller-provided input encoding.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InputFormat {
    /// Input bytes are used as-is.
    Raw,
    /// Input bytes contain UTF-8 hexadecimal text.
    Hex,
}

/// Encodings supported by derived-key outputs.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DeriveFormat {
    /// Raw bytes.
    Raw,
    /// Lowercase hexadecimal bytes.
    Hex,
    /// ASN.1 DER signature bytes.
    Der,
    /// EIP-55 Ethereum address for secp256k1 public keys.
    Address,
}

/// Reference to registry material by ID or persistent TPM handle.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MaterialRef {
    /// Registry ID.
    Id(String),
    /// Persistent TPM handle.
    Handle(PersistentHandle),
}

impl MaterialRef {
    /// Parse an ID or lowercase `0x` persistent-handle literal.
    pub fn from_id_or_handle(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.starts_with("0x") {
            Ok(Self::Handle(value.parse::<PersistentHandle>()?))
        } else {
            Ok(Self::Id(value))
        }
    }

    /// Convert into an object selector, validating registry IDs.
    pub fn selector(self) -> Result<ObjectSelector> {
        match self {
            Self::Id(id) => Ok(ObjectSelector::Id(RegistryId::new(id)?)),
            Self::Handle(handle) => Ok(ObjectSelector::Handle(handle)),
        }
    }
}

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

/// Hash algorithms used for TPM and derived ECDSA signing.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
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
        let key = p256::PublicKey::from_sec1_bytes(&sec1)
            .map_err(|error| Error::invalid("public_key", error.to_string()))?;
        let point = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&key, false);
        Ok(Self {
            curve: EccCurve::P256,
            sec1: point.as_bytes().to_vec(),
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

#[cfg(test)]
#[path = "lib.test.rs"]
mod tests;
