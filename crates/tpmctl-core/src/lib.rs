//! Core contracts for `tpmctl` frontends.
//!
//! This crate intentionally contains no CLI parser and no PKCS#11 entrypoints.
//! TPM domain operations are represented as typed request contracts so the CLI
//! can validate and dispatch without embedding TPM semantics.

use std::{env, fmt, path::PathBuf, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid persistent handle {value:?}: expected a hex string like 0x81010010")]
    InvalidPersistentHandle { value: String },
    #[error(
        "could not resolve a local registry root; set --store, TPMCTL_STORE, XDG_DATA_HOME, or HOME"
    )]
    MissingStoreRoot,
    #[error("{0} is not implemented yet in tpmctl-core")]
    Unsupported(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoreConfig {
    pub root: PathBuf,
}

impl StoreConfig {
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self> {
        if let Some(root) = explicit {
            return Ok(Self { root });
        }

        if let Some(root) = env::var_os("TPMCTL_STORE").map(PathBuf::from) {
            return Ok(Self { root });
        }

        if let Some(root) = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .map(|path| path.join("tpmctl"))
        {
            return Ok(Self { root });
        }

        if let Some(root) = env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| path.join(".local/share/tpmctl"))
        {
            return Ok(Self { root });
        }

        Err(Error::MissingStoreRoot)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistentHandle(u32);

impl PersistentHandle {
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
        let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        else {
            return Err(Error::InvalidPersistentHandle {
                value: value.to_string(),
            });
        };

        if hex.is_empty() || hex.len() > 8 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::InvalidPersistentHandle {
                value: value.to_string(),
            });
        }

        u32::from_str_radix(hex, 16)
            .map(Self)
            .map_err(|_| Error::InvalidPersistentHandle {
                value: value.to_string(),
            })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum MaterialRef {
    Id(String),
    Handle(PersistentHandle),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyUsage {
    Sign,
    Ecdh,
    Hmac,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignatureFormat {
    Der,
    Raw,
    Hex,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum PublicKeyFormat {
    Raw,
    Hex,
    Pem,
    Der,
    Ssh,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum BinaryTextFormat {
    Raw,
    Hex,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeriveAlgorithm {
    P256,
    Ed25519,
    Secp256k1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeriveUse {
    Secret,
    Pubkey,
    Sign,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeriveFormat {
    Raw,
    Hex,
    Der,
    Address,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutputTarget {
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum InputSource {
    Stdin,
    File(PathBuf),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeOptions {
    pub store: StoreConfig,
    pub json: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeygenRequest {
    pub runtime: RuntimeOptions,
    pub usage: KeyUsage,
    pub id: String,
    pub handle: Option<PersistentHandle>,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub input: SignInput,
    pub hash: HashAlgorithm,
    pub format: SignatureFormat,
    pub output: OutputTarget,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignInput {
    Message(InputSource),
    Digest(InputSource),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PubkeyRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub format: PublicKeyFormat,
    pub output: OutputTarget,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EcdhRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub peer_pub: InputSource,
    pub format: BinaryTextFormat,
    pub output: OutputTarget,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HmacRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub input: InputSource,
    pub hash: Option<HashAlgorithm>,
    pub format: BinaryTextFormat,
    pub output: OutputTarget,
    pub seal: Option<SealDestination>,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SealDestination {
    Id(String),
    Handle(PersistentHandle),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SealRequest {
    pub runtime: RuntimeOptions,
    pub input: InputSource,
    pub destination: SealDestination,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnsealRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub output: OutputTarget,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeriveRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub label: Option<String>,
    pub algorithm: DeriveAlgorithm,
    pub usage: DeriveUse,
    pub input: Option<SignInput>,
    pub hash: Option<HashAlgorithm>,
    pub format: DeriveFormat,
    pub compressed: bool,
    pub output: OutputTarget,
    pub force: bool,
}

pub fn keygen(_request: KeygenRequest) -> Result<()> {
    Err(Error::Unsupported("keygen"))
}

pub fn sign(_request: SignRequest) -> Result<()> {
    Err(Error::Unsupported("sign"))
}

pub fn pubkey(_request: PubkeyRequest) -> Result<()> {
    Err(Error::Unsupported("pubkey"))
}

pub fn ecdh(_request: EcdhRequest) -> Result<()> {
    Err(Error::Unsupported("ecdh"))
}

pub fn hmac(_request: HmacRequest) -> Result<()> {
    Err(Error::Unsupported("hmac"))
}

pub fn seal(_request: SealRequest) -> Result<()> {
    Err(Error::Unsupported("seal"))
}

pub fn unseal(_request: UnsealRequest) -> Result<()> {
    Err(Error::Unsupported("unseal"))
}

pub fn derive(_request: DeriveRequest) -> Result<()> {
    Err(Error::Unsupported("derive"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_persistent_handle() {
        let handle: PersistentHandle = "0x81010010".parse().unwrap();
        assert_eq!(handle.raw(), 0x81010010);
        assert_eq!(handle.to_string(), "0x81010010");
    }

    #[test]
    fn rejects_non_hex_persistent_handle() {
        assert!("81010010".parse::<PersistentHandle>().is_err());
        assert!("0x".parse::<PersistentHandle>().is_err());
        assert!("0xnothex".parse::<PersistentHandle>().is_err());
    }
}
