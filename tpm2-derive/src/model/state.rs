use std::env;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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

    pub fn profile_path(&self, profile_name: &str) -> PathBuf {
        self.profiles_dir.join(format!("{profile_name}.json"))
    }
}

pub fn default_state_root() -> PathBuf {
    if let Ok(xdg) = env::var("XDG_STATE_HOME") {
        return PathBuf::from(xdg).join("tpm2-derive");
    }

    if let Ok(home) = env::var("HOME") {
        return Path::new(&home).join(".local").join("state").join("tpm2-derive");
    }

    PathBuf::from(".tpm2-derive")
}
