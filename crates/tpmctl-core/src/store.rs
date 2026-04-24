use std::path::PathBuf;

/// Store selection supplied by frontends.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct StoreOptions {
    /// Explicit store root, equivalent to `--store <path>`.
    pub root: Option<PathBuf>,
}

/// Stable identifier for existing TPM material.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IdentityRef {
    Id(String),
    Handle(crate::PersistentHandle),
}

/// Object classes persisted in the local registry.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ObjectKind {
    Key,
    Sealed,
}

/// Metadata shared by registry-backed objects.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObjectMetadata {
    pub id: String,
    pub kind: ObjectKind,
    pub usage: crate::KeyUsage,
    pub handle: Option<crate::PersistentHandle>,
    pub persistent: bool,
}

/// Resolve the store root according to the documented precedence.
pub fn resolve_store_root(_options: &StoreOptions) -> crate::Result<PathBuf> {
    Err(crate::Error::unsupported("store::resolve_store_root"))
}

/// Convert a registry ID into a safe relative path.
pub fn id_to_relative_path(_id: &str) -> crate::Result<PathBuf> {
    Err(crate::Error::unsupported("store::id_to_relative_path"))
}
