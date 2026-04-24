//! Reusable TPM command-domain APIs for `tpmctl`.
//!
//! This crate intentionally contains no CLI parsing and no PKCS#11 entrypoints.
//! In this worktree the public APIs, validation, and output encoders are
//! implemented first. Functions that require a live TPM return
//! [`Error::TpmUnavailable`] until the shared TPM/store foundation is available.

pub mod ecdh;
pub mod hmac;
pub mod keygen;
pub mod output;
pub mod pubkey;
pub mod seal;
pub mod sign;

use std::{fmt, str::FromStr};

use sha2::{Digest as _, Sha256, Sha384, Sha512};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    InvalidArgument {
        field: &'static str,
        message: String,
    },
    Unsupported {
        operation: &'static str,
        message: String,
    },
    TpmUnavailable(String),
}

impl Error {
    pub fn invalid(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidArgument {
            field,
            message: message.into(),
        }
    }

    pub fn unsupported(operation: &'static str, message: impl Into<String>) -> Self {
        Self::Unsupported {
            operation,
            message: message.into(),
        }
    }

    pub fn tpm_unavailable(message: impl Into<String>) -> Self {
        Self::TpmUnavailable(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument { field, message } => write!(f, "invalid {field}: {message}"),
            Self::Unsupported { operation, message } => {
                write!(f, "unsupported {operation}: {message}")
            }
            Self::TpmUnavailable(message) => write!(f, "TPM unavailable: {message}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyUsage {
    Sign,
    Ecdh,
    Hmac,
    Sealed,
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
pub struct RegistryId(String);

impl RegistryId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_registry_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn ssh_comment(&self) -> String {
        self.0.replace('/', "_")
    }
}

impl fmt::Display for RegistryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct PersistentHandle(u32);

impl PersistentHandle {
    pub const MIN: u32 = 0x8100_0000;
    pub const MAX: u32 = 0x81ff_ffff;

    pub fn new(raw: u32) -> Result<Self> {
        if (Self::MIN..=Self::MAX).contains(&raw) {
            Ok(Self(raw))
        } else {
            Err(Error::invalid(
                "handle",
                format!("0x{raw:08x} is outside the persistent handle range"),
            ))
        }
    }

    pub fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Display for PersistentHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl FromStr for PersistentHandle {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(Error::invalid("handle", "empty handle literal"));
        }
        let raw = if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            u32::from_str_radix(hex, 16).map_err(|error| {
                Error::invalid("handle", format!("failed to parse hex handle: {error}"))
            })?
        } else {
            return Err(Error::invalid(
                "handle",
                "expected a hex handle like 0x81010010",
            ));
        };
        Self::new(raw)
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

fn validate_registry_id(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::invalid("id", "registry ID cannot be empty"));
    }
    if value.starts_with('/') {
        return Err(Error::invalid("id", "registry ID must be relative"));
    }
    if value.contains('\\') {
        return Err(Error::invalid(
            "id",
            "registry ID must use '/' separators, not '\\'",
        ));
    }
    if value.contains('\0') {
        return Err(Error::invalid("id", "registry ID cannot contain NUL"));
    }
    for component in value.split('/') {
        if component.is_empty() {
            return Err(Error::invalid(
                "id",
                "registry ID cannot contain empty path components",
            ));
        }
        if component == "." || component == ".." {
            return Err(Error::invalid(
                "id",
                "registry ID cannot contain '.' or '..' components",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_parses_persistent_hex() {
        let handle: PersistentHandle = "0x81010010".parse().unwrap();
        assert_eq!(handle.raw(), 0x8101_0010);
        assert_eq!(handle.to_string(), "0x81010010");
    }

    #[test]
    fn handle_rejects_non_hex_and_non_persistent() {
        assert!("81010010".parse::<PersistentHandle>().is_err());
        assert!("0x80000000".parse::<PersistentHandle>().is_err());
    }

    #[test]
    fn registry_id_rejects_path_traversal() {
        assert!(RegistryId::new("org/acme/alice").is_ok());
        assert!(RegistryId::new("/org/acme").is_err());
        assert!(RegistryId::new("org//acme").is_err());
        assert!(RegistryId::new("org/../acme").is_err());
        assert!(RegistryId::new("org\\acme").is_err());
    }
}
