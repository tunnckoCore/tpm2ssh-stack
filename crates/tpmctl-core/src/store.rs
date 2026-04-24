use std::path::PathBuf;

use crate::{KeyAlgorithm, KeyId, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct StoreConfig {
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct KeyMetadata {
    pub id: KeyId,
    pub algorithm: KeyAlgorithm,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlob {
    pub metadata: KeyMetadata,
    pub private_blob: Vec<u8>,
    pub public_blob: Vec<u8>,
}

pub fn default_store_root() -> Result<PathBuf> {
    Err(crate::TpmctlError::NotImplemented(
        "store::default_store_root",
    ))
}
