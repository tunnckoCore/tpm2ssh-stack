use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct StateLayout {
    pub root_dir: PathBuf,
    pub profiles_dir: PathBuf,
    pub objects_dir: PathBuf,
    pub exports_dir: PathBuf,
}

impl StateLayout {
    pub fn new(root_dir: PathBuf) -> Self {
        Self {
            profiles_dir: root_dir.join("profiles"),
            objects_dir: root_dir.join("objects"),
            exports_dir: root_dir.join("exports"),
            root_dir,
        }
    }

    pub fn from_optional_root(root_dir: Option<PathBuf>) -> Self {
        Self::new(root_dir.unwrap_or_else(default_state_root))
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        for path in [
            &self.root_dir,
            &self.profiles_dir,
            &self.objects_dir,
            &self.exports_dir,
        ] {
            fs::create_dir_all(path).map_err(|error| {
                Error::State(format!(
                    "failed to create state directory '{}': {error}",
                    path.display()
                ))
            })?;

            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(
                |error| {
                    Error::State(format!(
                        "failed to set permissions on '{}': {error}",
                        path.display()
                    ))
                },
            )?;
        }

        Ok(())
    }

    pub fn profile_path(&self, profile_name: &str) -> PathBuf {
        self.profiles_dir.join(format!("{profile_name}.json"))
    }
}

pub fn default_state_root() -> PathBuf {
    if let Ok(xdg) = env::var("XDG_STATE_HOME") {
        return PathBuf::from(xdg).join("tpm2-derive");
    }

    if let Ok(home) = env::var("HOME") {
        return Path::new(&home)
            .join(".local")
            .join("state")
            .join("tpm2-derive");
    }

    PathBuf::from(".tpm2-derive")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();

        env::temp_dir().join(format!(
            "tpm2-derive-{label}-{}-{sequence}-{now}",
            std::process::id()
        ))
    }

    #[test]
    fn ensure_dirs_creates_required_layout() {
        let root_dir = unique_temp_path("state-layout");
        let layout = StateLayout::new(root_dir.clone());

        layout
            .ensure_dirs()
            .expect("state layout should be created");

        assert!(layout.root_dir.is_dir());
        assert!(layout.profiles_dir.is_dir());
        assert!(layout.objects_dir.is_dir());
        assert!(layout.exports_dir.is_dir());

        fs::remove_dir_all(root_dir).expect("temporary state layout should be removed");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dirs_sets_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let root_dir = unique_temp_path("state-perms");
        let layout = StateLayout::new(root_dir.clone());
        layout.ensure_dirs().expect("dirs created");

        for path in [
            &layout.root_dir,
            &layout.profiles_dir,
            &layout.objects_dir,
            &layout.exports_dir,
        ] {
            let mode = fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "directory {} should be 0700", path.display());
        }

        fs::remove_dir_all(root_dir).expect("cleanup");
    }
}
