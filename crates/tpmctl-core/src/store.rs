use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{Error, Result, config::StoreConfig, handle::PersistentHandle};

/// Slash-separated local registry identifier, safely mappable below a store root.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct Id(String);

impl Id {
    pub fn parse(input: impl Into<String>) -> Result<Self> {
        let input = input.into();
        if input.is_empty() {
            return invalid_id(input, "id must not be empty");
        }
        if input.starts_with('/') || input.starts_with('~') || input.contains('\\') {
            return invalid_id(
                input,
                "id must be relative and use forward-slash separators only",
            );
        }
        let mut saw_segment = false;
        for segment in input.split('/') {
            if segment.is_empty() {
                return invalid_id(input, "segments must not be empty");
            }
            if segment == "." || segment == ".." {
                return invalid_id(input, "segments must not be . or ..");
            }
            if !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            {
                return invalid_id(
                    input,
                    "segments may contain only ASCII letters, digits, '.', '_', and '-'",
                );
            }
            saw_segment = true;
        }
        if !saw_segment {
            return invalid_id(input, "id must contain at least one segment");
        }
        Ok(Self(input))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn to_relative_path(&self) -> PathBuf {
        self.0.split('/').collect()
    }
}

fn invalid_id<T>(input: String, reason: &str) -> Result<T> {
    Err(Error::InvalidId {
        input,
        reason: reason.to_string(),
    })
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Id {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Registry object class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Key,
    Sealed,
}

impl ObjectKind {
    fn directory(self) -> &'static str {
        match self {
            Self::Key => "keys",
            Self::Sealed => "sealed",
        }
    }
}

/// Intended usage for a key or sealed object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Usage {
    Sign,
    Ecdh,
    Hmac,
    Sealed,
}

/// Minimal durable metadata for local registry entries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectMetadata {
    pub id: Id,
    pub kind: ObjectKind,
    pub usage: Usage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<PersistentHandle>,
    pub persistent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<TemplateMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<BlobMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_cache: Option<PublicKeyCacheMetadata>,
}

impl ObjectMetadata {
    pub fn new(id: Id, kind: ObjectKind, usage: Usage) -> Self {
        Self {
            id,
            kind,
            usage,
            handle: None,
            persistent: false,
            curve: None,
            hash: None,
            created_at: unix_timestamp_string(),
            parent: None,
            template: None,
            blobs: Vec::new(),
            public_key_cache: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParentMetadata {
    pub hierarchy: String,
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_handle: Option<PersistentHandle>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TemplateMetadata {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlobMetadata {
    pub path: String,
    pub format: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicKeyCacheMetadata {
    pub path: String,
    pub format: String,
}

/// Local registry rooted at `${XDG_DATA_HOME:-~/.local/share}/tpmctl` unless overridden.
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(config: &StoreConfig) -> Result<Self> {
        let root = config.resolve_root()?;
        Ok(Self { root })
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn object_dir(&self, kind: ObjectKind, id: &Id) -> Result<PathBuf> {
        let path = self.root.join(kind.directory()).join(id.to_relative_path());
        ensure_below(&self.root, &path)?;
        Ok(path)
    }

    pub fn metadata_path(&self, kind: ObjectKind, id: &Id) -> Result<PathBuf> {
        Ok(self.object_dir(kind, id)?.join("meta.json"))
    }

    pub fn create_object_dir(&self, kind: ObjectKind, id: &Id, force: bool) -> Result<PathBuf> {
        let dir = self.object_dir(kind, id)?;
        if dir.exists() && !force {
            return Err(Error::AlreadyExists(dir));
        }
        fs::create_dir_all(&dir).map_err(|err| Error::io(&dir, err))?;
        Ok(dir)
    }

    pub fn read_metadata(&self, kind: ObjectKind, id: &Id) -> Result<ObjectMetadata> {
        let path = self.metadata_path(kind, id)?;
        let mut file = File::open(&path).map_err(|err| Error::io(&path, err))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|err| Error::io(&path, err))?;
        serde_json::from_slice(&bytes).map_err(|err| Error::json(path, err))
    }

    pub fn write_metadata_atomic(&self, metadata: &ObjectMetadata) -> Result<()> {
        let dir = self.create_object_dir(metadata.kind, &metadata.id, true)?;
        let path = dir.join("meta.json");
        let bytes = serde_json::to_vec_pretty(metadata).map_err(|err| Error::json(&path, err))?;
        atomic_write(&path, &bytes)
    }

    pub fn write_blob_atomic(
        &self,
        kind: ObjectKind,
        id: &Id,
        filename: &str,
        bytes: &[u8],
    ) -> Result<PathBuf> {
        if filename.contains('/')
            || filename.contains('\\')
            || filename == "."
            || filename == ".."
            || filename.is_empty()
        {
            return Err(Error::InvalidId {
                input: filename.to_string(),
                reason: "blob filename must be a single safe path segment".to_string(),
            });
        }
        let dir = self.create_object_dir(kind, id, true)?;
        let path = dir.join(filename);
        ensure_below(&self.root, &path)?;
        atomic_write(&path, bytes)?;
        Ok(path)
    }
}

/// Atomically write a file by creating a same-directory temporary file, fsyncing it,
/// renaming it into place, then best-effort fsyncing the parent directory.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|err| Error::io(dir, err))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let mut last_err = None;
    for attempt in 0..16 {
        let tmp = dir.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(mut file) => {
                if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
                    let _ = fs::remove_file(&tmp);
                    return Err(Error::io(&tmp, err));
                }
                fs::rename(&tmp, path).map_err(|err| Error::io(path, err))?;
                sync_dir(dir);
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(err);
            }
            Err(err) => return Err(Error::io(&tmp, err)),
        }
    }
    Err(Error::io(
        path,
        last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "temporary file collision",
            )
        }),
    ))
}

fn sync_dir(dir: &Path) {
    if let Ok(file) = File::open(dir) {
        let _ = file.sync_all();
    }
}

fn ensure_below(root: &Path, path: &Path) -> Result<()> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| Error::PathEscapesStore {
            root: root.to_path_buf(),
            path: path.to_path_buf(),
        })?;
    if rel.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(Error::PathEscapesStore {
            root: root.to_path_buf(),
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn unix_timestamp_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_mapping_rejects_path_traversal() {
        for bad in [
            "", "/abs", "../x", "a/../b", "a//b", "a b", "a\\b", "~/.ssh",
        ] {
            assert!(Id::parse(bad).is_err(), "{bad} should be rejected");
        }
        assert_eq!(
            Id::parse("org/acme/alice/main").unwrap().to_relative_path(),
            PathBuf::from("org/acme/alice/main")
        );
    }

    #[test]
    fn metadata_round_trip_uses_atomic_write() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path());
        let id = Id::parse("org/acme/alice/main").unwrap();
        let mut meta = ObjectMetadata::new(id.clone(), ObjectKind::Key, Usage::Sign);
        meta.handle = Some("0x81010010".parse().unwrap());
        meta.persistent = true;
        meta.curve = Some("nist_p256".to_string());

        store.write_metadata_atomic(&meta).unwrap();
        let loaded = store.read_metadata(ObjectKind::Key, &id).unwrap();
        assert_eq!(loaded.id, id);
        assert_eq!(loaded.handle.unwrap().raw(), 0x8101_0010);
    }

    #[test]
    fn blob_write_rejects_nested_filename() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path());
        let id = Id::parse("org/acme").unwrap();
        assert!(
            store
                .write_blob_atomic(ObjectKind::Key, &id, "../x", b"no")
                .is_err()
        );
        store
            .write_blob_atomic(ObjectKind::Key, &id, "public.tpm", b"yes")
            .unwrap();
    }
}
