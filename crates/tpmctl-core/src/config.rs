use std::{env, path::PathBuf};

use crate::{Error, Result};

/// Explicit store root provided by a frontend, equivalent to CLI `--store <path>`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct StoreRoot(PathBuf);

impl StoreRoot {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
}

/// Store resolution inputs. Precedence: explicit store, `TPMCTL_STORE`, XDG default.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct StoreConfig {
    explicit_store: Option<StoreRoot>,
}

impl StoreConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_store(mut self, store: impl Into<PathBuf>) -> Self {
        self.explicit_store = Some(StoreRoot::new(store));
        self
    }

    pub fn resolve_root(&self) -> Result<PathBuf> {
        if let Some(root) = &self.explicit_store {
            return Ok(root.as_path().to_path_buf());
        }
        if let Some(root) = non_empty_env("TPMCTL_STORE") {
            return Ok(PathBuf::from(root));
        }
        if let Some(xdg) = non_empty_env("XDG_DATA_HOME") {
            return Ok(PathBuf::from(xdg).join("tpmctl"));
        }
        if let Some(home) = non_empty_env("HOME") {
            return Ok(PathBuf::from(home).join(".local/share/tpmctl"));
        }
        Err(Error::StoreRootUnavailable)
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_store_wins() {
        let cfg = StoreConfig::new().with_store("/tmp/explicit");
        assert_eq!(cfg.resolve_root().unwrap(), PathBuf::from("/tmp/explicit"));
    }
}
