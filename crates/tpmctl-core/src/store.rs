use std::{
    env, fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

pub const STORE_ENV: &str = "TPMCTL_STORE";
const STORE_DIR_NAME: &str = "tpmctl";
const META_FILE: &str = "meta.json";
const PUBLIC_BLOB_FILE: &str = "public.tpm";
const PRIVATE_BLOB_FILE: &str = "private.tpm";
const PUBLIC_PEM_FILE: &str = "public.pem";

/// Store selection supplied by frontends.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct StoreOptions {
    /// Explicit store root, equivalent to `--store <path>`.
    pub root: Option<PathBuf>,
}

impl StoreOptions {
    pub fn resolve_root(&self) -> Result<PathBuf> {
        resolve_store_root(self.root.as_deref())
    }
}

/// Stable identifier for existing TPM material.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IdentityRef {
    Id(String),
    Handle(crate::PersistentHandle),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn resolve<P: AsRef<Path>>(explicit_root: Option<P>) -> Result<Self> {
        Ok(Self {
            root: resolve_store_root(explicit_root)?,
        })
    }

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path_for(&self, collection: RegistryCollection, id: &RegistryId) -> PathBuf {
        collection
            .apply_to_root(&self.root)
            .join(id.as_relative_path())
    }

    pub fn exists(&self, collection: RegistryCollection, id: &RegistryId) -> bool {
        self.path_for(collection, id).join(META_FILE).is_file()
    }

    pub fn save_entry(
        &self,
        collection: RegistryCollection,
        entry: &StoredObjectEntry,
        overwrite: bool,
    ) -> Result<PathBuf> {
        let id = RegistryId::parse(&entry.metadata.id)?;
        let dir = self.path_for(collection, &id);
        if !overwrite && dir.exists() {
            return Err(CoreError::AlreadyExists(dir));
        }

        fs::create_dir_all(&dir).map_err(|source| CoreError::io(&dir, source))?;
        write_json_atomic(&dir.join(META_FILE), &entry.metadata)?;
        write_atomic(&dir.join(PUBLIC_BLOB_FILE), &entry.public_blob)?;
        write_atomic(&dir.join(PRIVATE_BLOB_FILE), &entry.private_blob)?;

        if let Some(public_pem) = &entry.public_pem {
            write_atomic(&dir.join(PUBLIC_PEM_FILE), public_pem)?;
        }

        Ok(dir)
    }

    pub fn load_entry(
        &self,
        collection: RegistryCollection,
        id: &RegistryId,
    ) -> Result<StoredObjectEntry> {
        let dir = self.path_for(collection, id);
        if !dir.is_dir() {
            return Err(CoreError::NotFound(dir));
        }

        let meta_path = dir.join(META_FILE);
        let public_path = dir.join(PUBLIC_BLOB_FILE);
        let private_path = dir.join(PRIVATE_BLOB_FILE);
        let pem_path = dir.join(PUBLIC_PEM_FILE);

        let metadata = read_json(&meta_path)?;
        let public_blob =
            fs::read(&public_path).map_err(|source| CoreError::io(public_path, source))?;
        let private_blob =
            fs::read(&private_path).map_err(|source| CoreError::io(private_path, source))?;
        let public_pem = if pem_path.is_file() {
            Some(fs::read(&pem_path).map_err(|source| CoreError::io(pem_path, source))?)
        } else {
            None
        };

        Ok(StoredObjectEntry {
            metadata,
            public_blob,
            private_blob,
            public_pem,
        })
    }

    pub fn save_key(&self, entry: &StoredObjectEntry, overwrite: bool) -> Result<PathBuf> {
        self.save_entry(RegistryCollection::Keys, entry, overwrite)
    }

    pub fn load_key(&self, id: &RegistryId) -> Result<StoredObjectEntry> {
        self.load_entry(RegistryCollection::Keys, id)
    }

    pub fn save_sealed(&self, entry: &StoredObjectEntry, overwrite: bool) -> Result<PathBuf> {
        self.save_entry(RegistryCollection::Sealed, entry, overwrite)
    }

    pub fn load_sealed(&self, id: &RegistryId) -> Result<StoredObjectEntry> {
        self.load_entry(RegistryCollection::Sealed, id)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RegistryCollection {
    Keys,
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

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegistryId(String);

impl RegistryId {
    pub fn parse(input: impl AsRef<str>) -> Result<Self> {
        let input = input.as_ref();
        validate_registry_id(input)?;
        Ok(Self(input.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_relative_path(&self) -> PathBuf {
        self.0.split('/').collect()
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
    Key,
    Sealed,
}

pub type ObjectKind = StoredObjectKind;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectUsage {
    Sign,
    Ecdh,
    Hmac,
    Sealed,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ParentMetadata {
    pub hierarchy: String,
    pub template: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RegistryMetadata {
    pub id: String,
    pub kind: StoredObjectKind,
    pub usage: ObjectUsage,
    pub handle: Option<String>,
    pub persistent: bool,
    pub curve: Option<String>,
    pub hash: Option<String>,
    pub created_at: String,
    pub parent: Option<ParentMetadata>,
    pub template: Option<String>,
    pub public_key: Option<String>,
}

impl RegistryMetadata {
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredObjectEntry {
    pub metadata: RegistryMetadata,
    pub public_blob: Vec<u8>,
    pub private_blob: Vec<u8>,
    pub public_pem: Option<Vec<u8>>,
}

/// Metadata shared by registry-backed objects in higher-level command contracts.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObjectMetadata {
    pub id: String,
    pub kind: ObjectKind,
    pub usage: crate::KeyUsage,
    pub handle: Option<crate::PersistentHandle>,
    pub persistent: bool,
}

pub fn resolve_store_root<P: AsRef<Path>>(explicit_root: Option<P>) -> Result<PathBuf> {
    if let Some(path) = explicit_root {
        return normalize_store_root(path.as_ref());
    }

    if let Some(value) = non_empty_env(STORE_ENV) {
        return normalize_store_root(Path::new(&value));
    }

    default_store_root()
}

pub fn id_to_relative_path(id: &str) -> Result<PathBuf> {
    Ok(RegistryId::parse(id)?.as_relative_path())
}

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
    fs::create_dir_all(parent).map_err(|source| CoreError::io(parent, source))?;

    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    fs::write(&tmp, bytes).map_err(|source| CoreError::io(&tmp, source))?;
    fs::rename(&tmp, path).map_err(|source| CoreError::io(path, source))?;
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
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn store_explicit_path_beats_env() {
        let _guard = env_lock();
        let temp = tempfile::tempdir().unwrap();
        let explicit = temp.path().join("explicit");
        let env_path = temp.path().join("env");
        unsafe {
            env::set_var(STORE_ENV, &env_path);
            env::set_var("XDG_DATA_HOME", temp.path().join("xdg"));
        }

        let root = resolve_store_root(Some(&explicit)).unwrap();
        assert_eq!(root, explicit);

        unsafe {
            env::remove_var(STORE_ENV);
            env::remove_var("XDG_DATA_HOME");
        }
    }

    #[test]
    fn store_env_beats_xdg_default() {
        let _guard = env_lock();
        let temp = tempfile::tempdir().unwrap();
        let env_path = temp.path().join("env");
        unsafe {
            env::set_var(STORE_ENV, &env_path);
            env::set_var("XDG_DATA_HOME", temp.path().join("xdg"));
        }

        let root = resolve_store_root::<&Path>(None).unwrap();
        assert_eq!(root, env_path);

        unsafe {
            env::remove_var(STORE_ENV);
            env::remove_var("XDG_DATA_HOME");
        }
    }

    #[test]
    fn store_xdg_default_is_tpmctl_subdir() {
        let _guard = env_lock();
        let temp = tempfile::tempdir().unwrap();
        unsafe {
            env::remove_var(STORE_ENV);
            env::set_var("XDG_DATA_HOME", temp.path());
        }

        let root = resolve_store_root::<&Path>(None).unwrap();
        assert_eq!(root, temp.path().join("tpmctl"));

        unsafe {
            env::remove_var("XDG_DATA_HOME");
        }
    }

    #[test]
    fn registry_id_rejects_unsafe_paths() {
        for id in ["", "/abs", "a//b", "a/../b", "a/./b", "a\\b", "a/b c"] {
            assert!(RegistryId::parse(id).is_err(), "{id} should be rejected");
        }
    }

    #[test]
    fn registry_id_maps_to_safe_relative_path() {
        let id = RegistryId::parse("org/acme/alice/main-1.2_3").unwrap();
        assert_eq!(
            id.as_relative_path(),
            PathBuf::from("org/acme/alice/main-1.2_3")
        );
    }

    #[test]
    fn store_round_trips_key_entry() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path());
        let id = RegistryId::parse("org/acme/key").unwrap();
        let mut metadata = RegistryMetadata::new(&id, StoredObjectKind::Key, ObjectUsage::Sign);
        metadata.handle = Some("0x81010010".into());
        metadata.persistent = true;
        let entry = StoredObjectEntry {
            metadata,
            public_blob: b"public".to_vec(),
            private_blob: b"private".to_vec(),
            public_pem: Some(b"pem".to_vec()),
        };

        store.save_key(&entry, false).unwrap();
        assert!(store.exists(RegistryCollection::Keys, &id));
        assert!(store.save_key(&entry, false).is_err());

        let loaded = store.load_key(&id).unwrap();
        assert_eq!(loaded, entry);
    }
}
