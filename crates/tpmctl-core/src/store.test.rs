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
fn stored_object_entry_debug_redacts_private_blob() {
    let id = RegistryId::parse("org/acme/key").unwrap();
    let mut entry = test_key_entry(&id);
    entry.private_blob = Zeroizing::new(b"private-blob-secret".to_vec());

    let debug = format!("{entry:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("private-blob-secret"));
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
