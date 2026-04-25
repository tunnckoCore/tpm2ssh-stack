use std::{
    env, fmt, fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{CoreError, Result};

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
        self.path_for(collection, id)
            .join(REGISTRY_RECORD_FILE)
            .is_file()
    }

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
    pub fn new(input: impl Into<String>) -> Result<Self> {
        Self::parse(input.into())
    }

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
pub struct ParentRecord {
    pub hierarchy: String,
    pub template: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RegistryRecord {
    pub id: String,
    pub kind: StoredObjectKind,
    pub usage: ObjectUsage,
    pub handle: Option<String>,
    pub persistent: bool,
    pub curve: Option<String>,
    pub hash: Option<String>,
    pub created_at: String,
    pub parent: Option<ParentRecord>,
    pub template: Option<String>,
    pub public_key: Option<String>,
}

impl RegistryRecord {
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
pub struct StoredObjectEntry {
    pub record: RegistryRecord,
    pub public_blob: Vec<u8>,
    pub private_blob: Zeroizing<Vec<u8>>,
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
        let mut metadata = RegistryRecord::new(&id, StoredObjectKind::Key, ObjectUsage::Sign);
        metadata.handle = Some("0x81010010".into());
        metadata.persistent = true;
        let entry = StoredObjectEntry {
            record: metadata,
            public_blob: b"public".to_vec(),
            private_blob: Zeroizing::new(b"private".to_vec()),
            public_pem: Some(b"pem".to_vec()),
        };

        store.save_key(&entry, false).unwrap();
        assert!(store.exists(RegistryCollection::Keys, &id));
        assert!(store.save_key(&entry, false).is_err());

        let loaded = store.load_key(&id).unwrap();
        assert_eq!(loaded, entry);
    }

    #[test]
    fn overwrite_removes_stale_public_pem_when_entry_has_none() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path());
        let id = RegistryId::parse("org/acme/key").unwrap();
        let metadata = RegistryRecord::new(&id, StoredObjectKind::Key, ObjectUsage::Sign);
        let with_pem = StoredObjectEntry {
            record: metadata.clone(),
            public_blob: b"public".to_vec(),
            private_blob: Zeroizing::new(b"private".to_vec()),
            public_pem: Some(b"pem".to_vec()),
        };
        let without_pem = StoredObjectEntry {
            record: metadata,
            public_blob: b"public2".to_vec(),
            private_blob: Zeroizing::new(b"private2".to_vec()),
            public_pem: None,
        };

        let dir = store.save_key(&with_pem, false).unwrap();
        assert!(dir.join(PUBLIC_PEM_FILE).is_file());
        store.save_key(&without_pem, true).unwrap();

        assert!(!dir.join(PUBLIC_PEM_FILE).exists());
        assert_eq!(store.load_key(&id).unwrap(), without_pem);
    }

    #[test]
    fn load_key_rejects_malformed_registry_json() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path());
        let id = RegistryId::parse("org/acme/key").unwrap();
        let entry = test_key_entry(&id);
        let dir = store.save_key(&entry, false).unwrap();
        fs::write(dir.join(REGISTRY_RECORD_FILE), b"{not valid json").unwrap();

        let error = store.load_key(&id).unwrap_err();
        assert!(
            matches!(error, CoreError::Json { ref path, .. } if path == &dir.join(REGISTRY_RECORD_FILE)),
            "expected JSON error for malformed registry record, got {error:?}"
        );
    }

    #[test]
    fn load_key_reports_missing_public_blob_file() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path());
        let id = RegistryId::parse("org/acme/key").unwrap();
        let entry = test_key_entry(&id);
        let dir = store.save_key(&entry, false).unwrap();
        fs::remove_file(dir.join(PUBLIC_BLOB_FILE)).unwrap();

        let error = store.load_key(&id).unwrap_err();
        assert!(
            matches!(error, CoreError::Io { ref path, .. } if path == &dir.join(PUBLIC_BLOB_FILE)),
            "expected I/O error for missing public blob, got {error:?}"
        );
    }

    #[test]
    fn load_key_reports_missing_private_blob_file() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path());
        let id = RegistryId::parse("org/acme/key").unwrap();
        let entry = test_key_entry(&id);
        let dir = store.save_key(&entry, false).unwrap();
        fs::remove_file(dir.join(PRIVATE_BLOB_FILE)).unwrap();

        let error = store.load_key(&id).unwrap_err();
        assert!(
            matches!(error, CoreError::Io { ref path, .. } if path == &dir.join(PRIVATE_BLOB_FILE)),
            "expected I/O error for missing private blob, got {error:?}"
        );
    }

    fn test_key_entry(id: &RegistryId) -> StoredObjectEntry {
        StoredObjectEntry {
            record: RegistryRecord::new(id, StoredObjectKind::Key, ObjectUsage::Sign),
            public_blob: b"public".to_vec(),
            private_blob: Zeroizing::new(b"private".to_vec()),
            public_pem: None,
        }
    }

    #[test]
    fn write_atomic_writes_exact_bytes_and_leaves_no_temp_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("target");

        write_atomic(&path, b"old").unwrap();
        write_atomic(&path, b"new\nbytes").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new\nbytes");
        assert_target_tmp_files_empty(temp.path(), "target");
    }

    #[test]
    fn write_atomic_removes_temp_file_when_rename_fails() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("target");
        fs::create_dir(&path).unwrap();

        assert!(write_atomic(&path, b"data").is_err());
        assert!(path.is_dir());
        assert_target_tmp_files_empty(temp.path(), "target");
    }

    fn assert_target_tmp_files_empty(dir: &Path, target_name: &str) {
        let prefix = format!("{target_name}.tmp-");
        let leftovers = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(&prefix))
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn registry_writes_use_private_unix_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path());
        let id = RegistryId::parse("org/acme/key").unwrap();
        let metadata = RegistryRecord::new(&id, StoredObjectKind::Key, ObjectUsage::Sign);
        let entry = StoredObjectEntry {
            record: metadata,
            public_blob: b"public".to_vec(),
            private_blob: Zeroizing::new(b"private".to_vec()),
            public_pem: Some(b"pem".to_vec()),
        };

        let dir = store.save_key(&entry, false).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for file in [
            REGISTRY_RECORD_FILE,
            PUBLIC_BLOB_FILE,
            PRIVATE_BLOB_FILE,
            PUBLIC_PEM_FILE,
        ] {
            assert_eq!(
                fs::metadata(dir.join(file)).unwrap().permissions().mode() & 0o777,
                0o600,
                "{file} should be private"
            );
        }
    }
}
