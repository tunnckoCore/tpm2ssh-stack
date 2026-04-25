use std::{
    env, fmt, fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{CoreError, Result};

/// Environment variable that overrides the default registry store root.
pub const STORE_ENV: &str = "TPMCTL_STORE";
const STORE_DIR_NAME: &str = "tpmctl";
const REGISTRY_RECORD_FILE: &str = "meta.json";
const PUBLIC_BLOB_FILE: &str = "public.tpm";
const PRIVATE_BLOB_FILE: &str = "private.tpm";
const PUBLIC_PEM_FILE: &str = "public.pem";

/// Store selection supplied by callers.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct StoreOptions {
    /// Explicit store root, equivalent to `--store <path>`.
    pub root: Option<PathBuf>,
}

impl StoreOptions {
    /// Resolve the effective store root from the explicit option, environment, or defaults.
    pub fn resolve_root(&self) -> Result<PathBuf> {
        resolve_store_root(self.root.as_deref())
    }
}

/// Stable identifier for existing TPM material.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IdentityRef {
    /// Registry object identifier.
    Id(String),
    /// Persistent TPM handle reference.
    Handle(crate::PersistentHandle),
}

/// Filesystem-backed registry for TPM object metadata and blobs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Create a store by resolving the effective root path.
    pub fn resolve<P: AsRef<Path>>(explicit_root: Option<P>) -> Result<Self> {
        Ok(Self {
            root: resolve_store_root(explicit_root)?,
        })
    }

    /// Create a store rooted at an already chosen path.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Return the root directory for this store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Compute the directory path for an object in a registry collection.
    pub fn path_for(&self, collection: RegistryCollection, id: &RegistryId) -> PathBuf {
        collection
            .apply_to_root(&self.root)
            .join(id.as_relative_path())
    }

    /// Check whether an object entry exists in the requested collection.
    pub fn exists(&self, collection: RegistryCollection, id: &RegistryId) -> bool {
        self.path_for(collection, id)
            .join(REGISTRY_RECORD_FILE)
            .is_file()
    }

    /// Persist an object entry atomically into the requested collection.
    pub fn save_entry(
        &self,
        collection: RegistryCollection,
        entry: &StoredObjectEntry,
        overwrite: bool,
    ) -> Result<PathBuf> {
        let id = RegistryId::parse(&entry.record.id)?;
        let dir = self.path_for(collection, &id);
        if !overwrite && dir.exists() {
            return Err(CoreError::AlreadyExists(dir));
        }

        create_secure_dir_all(&dir)?;
        write_json_atomic(&dir.join(REGISTRY_RECORD_FILE), &entry.record)?;
        write_atomic(&dir.join(PUBLIC_BLOB_FILE), &entry.public_blob)?;
        write_atomic(&dir.join(PRIVATE_BLOB_FILE), entry.private_blob.as_slice())?;

        let public_pem_path = dir.join(PUBLIC_PEM_FILE);
        if let Some(public_pem) = &entry.public_pem {
            write_atomic(&public_pem_path, public_pem)?;
        } else if overwrite && public_pem_path.exists() {
            fs::remove_file(&public_pem_path)
                .map_err(|source| CoreError::io(&public_pem_path, source))?;
        }

        Ok(dir)
    }

    /// Load an object entry and its TPM blobs from the requested collection.
    pub fn load_entry(
        &self,
        collection: RegistryCollection,
        id: &RegistryId,
    ) -> Result<StoredObjectEntry> {
        let dir = self.path_for(collection, id);
        if !dir.is_dir() {
            return Err(CoreError::NotFound(dir));
        }

        let record_path = dir.join(REGISTRY_RECORD_FILE);
        let public_path = dir.join(PUBLIC_BLOB_FILE);
        let private_path = dir.join(PRIVATE_BLOB_FILE);
        let pem_path = dir.join(PUBLIC_PEM_FILE);

        let metadata = read_json(&record_path)?;
        let public_blob =
            fs::read(&public_path).map_err(|source| CoreError::io(public_path, source))?;
        let private_blob = Zeroizing::new(
            fs::read(&private_path).map_err(|source| CoreError::io(private_path, source))?,
        );
        let public_pem = if pem_path.is_file() {
            Some(fs::read(&pem_path).map_err(|source| CoreError::io(pem_path, source))?)
        } else {
            None
        };

        Ok(StoredObjectEntry {
            record: metadata,
            public_blob,
            private_blob,
            public_pem,
        })
    }

    /// Save a key entry into the keys collection.
    pub fn save_key(&self, entry: &StoredObjectEntry, overwrite: bool) -> Result<PathBuf> {
        self.save_entry(RegistryCollection::Keys, entry, overwrite)
    }

    /// Load a key entry from the keys collection.
    pub fn load_key(&self, id: &RegistryId) -> Result<StoredObjectEntry> {
        self.load_entry(RegistryCollection::Keys, id)
    }

    /// Save a sealed-object entry into the sealed collection.
    pub fn save_sealed(&self, entry: &StoredObjectEntry, overwrite: bool) -> Result<PathBuf> {
        self.save_entry(RegistryCollection::Sealed, entry, overwrite)
    }

    /// Load a sealed-object entry from the sealed collection.
    pub fn load_sealed(&self, id: &RegistryId) -> Result<StoredObjectEntry> {
        self.load_entry(RegistryCollection::Sealed, id)
    }
}

/// Top-level registry collection for stored TPM objects.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RegistryCollection {
    /// TPM key objects.
    Keys,
    /// TPM sealed-data objects.
    Sealed,
}

impl RegistryCollection {
    fn apply_to_root(self, root: &Path) -> PathBuf {
        match self {
            Self::Keys => root.join("keys"),
            Self::Sealed => root.join("sealed"),
        }
    }
}

/// Validated registry identifier made of safe relative path components.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegistryId(String);

impl RegistryId {
    /// Validate and create a registry ID from owned string-like input.
    pub fn new(input: impl Into<String>) -> Result<Self> {
        Self::parse(input.into())
    }

    /// Validate and create a registry ID from borrowed string-like input.
    pub fn parse(input: impl AsRef<str>) -> Result<Self> {
        let input = input.as_ref();
        validate_registry_id(input)?;
        Ok(Self(input.to_owned()))
    }

    /// Return the canonical string form of this registry ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert the slash-delimited ID into a relative filesystem path.
    pub fn as_relative_path(&self) -> PathBuf {
        self.0.split('/').collect()
    }

    /// Return a filesystem-safe SSH comment derived from this ID.
    pub fn ssh_comment(&self) -> String {
        self.0.replace('/', "_")
    }
}

impl std::fmt::Display for RegistryId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::str::FromStr for RegistryId {
    type Err = CoreError;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoredObjectKind {
    /// Asymmetric or keyed-hash key object.
    Key,
    /// Sealed-data object.
    Sealed,
}

/// Backwards-compatible alias for the stored object kind enum.
pub type ObjectKind = StoredObjectKind;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
/// Intended operation for a registry object.
pub enum ObjectUsage {
    /// Signing key usage.
    Sign,
    /// ECDH key-agreement usage.
    Ecdh,
    /// HMAC keyed-hash usage.
    Hmac,
    /// Sealed-data usage.
    Sealed,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ParentRecord {
    /// TPM hierarchy used for the parent object.
    pub hierarchy: String,
    /// Human-readable parent template name.
    pub template: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Serializable metadata stored next to TPM public/private blobs.
pub struct RegistryRecord {
    /// Registry ID for the object.
    pub id: String,
    /// Stored object category.
    pub kind: StoredObjectKind,
    /// Intended object operation.
    pub usage: ObjectUsage,
    /// Optional persistent TPM handle string.
    pub handle: Option<String>,
    /// Whether the object is expected to exist at a persistent handle.
    pub persistent: bool,
    /// Optional ECC curve name for asymmetric keys.
    pub curve: Option<String>,
    /// Optional hash algorithm associated with the object.
    pub hash: Option<String>,
    /// Creation timestamp in seconds since the Unix epoch.
    pub created_at: String,
    /// Parent object metadata used to recreate transient loads.
    pub parent: Option<ParentRecord>,
    /// Object template name used when creating the object.
    pub template: Option<String>,
    /// Cached public key material for asymmetric objects.
    pub public_key: Option<String>,
}

impl RegistryRecord {
    /// Build a new registry record with default metadata for the object.
    pub fn new(id: &RegistryId, kind: StoredObjectKind, usage: ObjectUsage) -> Self {
        Self {
            id: id.to_string(),
            kind,
            usage,
            handle: None,
            persistent: false,
            curve: None,
            hash: None,
            created_at: created_at_now(),
            parent: None,
            template: None,
            public_key: None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
/// Complete on-disk object entry including metadata and TPM blobs.
pub struct StoredObjectEntry {
    /// Serializable metadata record.
    pub record: RegistryRecord,
    /// Marshaled TPM public area.
    pub public_blob: Vec<u8>,
    /// Marshaled TPM private area; zeroized when dropped.
    pub private_blob: Zeroizing<Vec<u8>>,
    /// Optional PEM-encoded public key cache.
    pub public_pem: Option<Vec<u8>>,
}

impl fmt::Debug for StoredObjectEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredObjectEntry")
            .field("record", &self.record)
            .field("public_blob", &self.public_blob)
            .field("private_blob", &"<redacted>")
            .field("public_pem", &self.public_pem)
            .finish()
    }
}

/// Shared details for registry-backed objects in higher-level command contracts.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObjectRecord {
    /// Registry identifier.
    pub id: String,
    /// Stored object kind.
    pub kind: ObjectKind,
    /// Operational usage.
    pub usage: crate::KeyUsage,
    /// Optional persistent TPM handle.
    pub handle: Option<crate::PersistentHandle>,
    /// Whether the object is persistent in the TPM.
    pub persistent: bool,
}

/// Resolve the store root from an explicit path, environment, or XDG defaults.
pub fn resolve_store_root<P: AsRef<Path>>(explicit_root: Option<P>) -> Result<PathBuf> {
    if let Some(path) = explicit_root {
        return normalize_store_root(path.as_ref());
    }

    if let Some(value) = non_empty_env(STORE_ENV) {
        return normalize_store_root(Path::new(&value));
    }

    default_store_root()
}

/// Validate an ID and convert it to a relative path.
pub fn id_to_relative_path(id: &str) -> Result<PathBuf> {
    Ok(RegistryId::parse(id)?.as_relative_path())
}

/// Return the default store root under XDG_DATA_HOME or HOME.
pub fn default_store_root() -> Result<PathBuf> {
    if let Some(xdg_data_home) = non_empty_env("XDG_DATA_HOME") {
        return normalize_store_root(Path::new(&xdg_data_home).join(STORE_DIR_NAME).as_path());
    }

    let home = non_empty_env("HOME").ok_or_else(|| {
        CoreError::Config("HOME must be set when XDG_DATA_HOME and TPMCTL_STORE are unset".into())
    })?;
    normalize_store_root(
        Path::new(&home)
            .join(".local/share")
            .join(STORE_DIR_NAME)
            .as_path(),
    )
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn normalize_store_root(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(CoreError::InvalidStorePath {
            path: path.to_path_buf(),
            reason: "path is empty".into(),
        });
    }
    Ok(path.to_path_buf())
}

fn validate_registry_id(input: &str) -> Result<()> {
    if input.is_empty() {
        return Err(invalid_id(input, "id is empty"));
    }
    if input.starts_with('/') {
        return Err(invalid_id(input, "absolute paths are not allowed"));
    }
    if input.contains('\\') {
        return Err(invalid_id(input, "backslash separators are not allowed"));
    }

    if input.split('/').any(str::is_empty) {
        return Err(invalid_id(input, "empty components are not allowed"));
    }
    if input
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        return Err(invalid_id(input, "dot components are not allowed"));
    }

    let path = Path::new(input);
    if path.is_absolute() {
        return Err(invalid_id(input, "absolute paths are not allowed"));
    }

    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let Some(value) = value.to_str() else {
                    return Err(invalid_id(input, "components must be UTF-8"));
                };
                if value.is_empty() {
                    return Err(invalid_id(input, "empty components are not allowed"));
                }
                if value == "." || value == ".." {
                    return Err(invalid_id(input, "dot components are not allowed"));
                }
                if !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
                {
                    return Err(invalid_id(
                        input,
                        "components may contain only ASCII letters, digits, '.', '_', and '-'",
                    ));
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(invalid_id(input, "dot components are not allowed"));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_id(input, "absolute paths are not allowed"));
            }
        }
    }

    Ok(())
}

fn invalid_id(input: &str, reason: impl Into<String>) -> CoreError {
    CoreError::InvalidRegistryId {
        id: input.to_owned(),
        reason: reason.into(),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).map_err(|source| CoreError::io(path, source))?;
    serde_json::from_slice(&bytes).map_err(|source| CoreError::json(path, source))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|source| CoreError::json(path, source))?;
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| CoreError::InvalidStorePath {
        path: path.to_path_buf(),
        reason: "path has no parent".into(),
    })?;
    create_secure_dir_all(parent)?;

    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    if let Err(error) = write_secure_temp_file(&tmp, bytes) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    if let Err(source) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(CoreError::io(path, source));
    }
    set_secure_file_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn create_secure_dir_all(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut to_secure = Vec::new();
    let mut current = path;
    while !current.exists() {
        to_secure.push(current.to_path_buf());
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }

    fs::create_dir_all(path).map_err(|source| CoreError::io(path, source))?;
    to_secure.push(path.to_path_buf());
    to_secure.sort();
    to_secure.dedup();
    for dir in to_secure {
        if dir.is_dir() {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|source| CoreError::io(&dir, source))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_secure_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| CoreError::io(path, source))
}

#[cfg(unix)]
fn write_secure_temp_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| CoreError::io(path, source))?;
    file.write_all(bytes)
        .map_err(|source| CoreError::io(path, source))
}

#[cfg(not(unix))]
fn write_secure_temp_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|source| CoreError::io(path, source))
}

#[cfg(unix)]
fn set_secure_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| CoreError::io(path, source))
}

#[cfg(not(unix))]
fn set_secure_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn created_at_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format!("unix:{seconds}")
}

#[cfg(test)]
#[path = "store.test.rs"]
mod tests;
