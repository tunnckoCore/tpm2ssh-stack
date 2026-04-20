use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::{Algorithm, Mode, ModePreference, StateLayout, UseCase};

pub const PROFILE_SCHEMA_VERSION: u32 = 1;

static NEXT_TEMP_PROFILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ModeResolution {
    pub requested: ModePreference,
    pub resolved: Mode,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExportPolicy {
    pub public_key_export: bool,
    pub recovery_export: bool,
    pub confirmation_required: bool,
}

impl ExportPolicy {
    pub const fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Native => Self {
                public_key_export: true,
                recovery_export: false,
                confirmation_required: true,
            },
            Mode::Prf => Self {
                public_key_export: false,
                recovery_export: false,
                confirmation_required: true,
            },
            Mode::Seed => Self {
                public_key_export: true,
                recovery_export: true,
                confirmation_required: true,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RootMaterialKind {
    NativeObject,
    PrfRoot,
    SealedSeed,
}

impl RootMaterialKind {
    pub const fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Native => Self::NativeObject,
            Mode::Prf => Self::PrfRoot,
            Mode::Seed => Self::SealedSeed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ProfileStorage {
    pub state_layout: StateLayout,
    pub profile_path: PathBuf,
    pub root_material_kind: RootMaterialKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Profile {
    pub schema_version: u32,
    pub name: String,
    pub algorithm: Algorithm,
    pub uses: Vec<UseCase>,
    pub mode: ModeResolution,
    pub storage: ProfileStorage,
    pub export_policy: ExportPolicy,
    pub metadata: BTreeMap<String, String>,
}

impl Profile {
    pub fn new(
        name: String,
        algorithm: Algorithm,
        uses: Vec<UseCase>,
        mode: ModeResolution,
        state_layout: StateLayout,
    ) -> Self {
        let profile_path = state_layout.profile_path(&name);
        let resolved = mode.resolved;

        Self {
            schema_version: PROFILE_SCHEMA_VERSION,
            name,
            algorithm,
            uses,
            mode,
            storage: ProfileStorage {
                profile_path,
                state_layout,
                root_material_kind: RootMaterialKind::for_mode(resolved),
            },
            export_policy: ExportPolicy::for_mode(resolved),
            metadata: BTreeMap::new(),
        }
    }

    pub fn persist(&self) -> Result<()> {
        self.storage.state_layout.ensure_dirs()?;
        write_json_atomically(&self.storage.profile_path, self)
    }

    pub fn load_named(name: &str, state_dir: Option<PathBuf>) -> Result<Self> {
        Self::load_from_layout(name, StateLayout::from_optional_root(state_dir))
    }

    pub fn load_from_layout(name: &str, state_layout: StateLayout) -> Result<Self> {
        let profile_path = state_layout.profile_path(name);
        let contents = fs::read_to_string(&profile_path).map_err(|error| {
            Error::State(format!(
                "failed to read profile '{}' from '{}': {error}",
                name,
                profile_path.display()
            ))
        })?;

        let mut profile: Self = serde_json::from_str(&contents).map_err(|error| {
            Error::State(format!(
                "failed to parse profile '{}' from '{}': {error}",
                name,
                profile_path.display()
            ))
        })?;

        profile.storage.state_layout = state_layout;
        profile.storage.profile_path = profile_path;

        Ok(profile)
    }
}

fn write_json_atomically(path: &Path, profile: &Profile) -> Result<()> {
    let temp_path = temporary_profile_path(path);
    let payload = format!("{}\n", serde_json::to_string_pretty(profile)?);

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|error| {
            Error::State(format!(
                "failed to create temporary profile file '{}': {error}",
                temp_path.display()
            ))
        })?;

    if let Err(error) = file.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(Error::State(format!(
            "failed to write temporary profile file '{}': {error}",
            temp_path.display()
        )));
    }

    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(Error::State(format!(
            "failed to persist profile to '{}': {error}",
            path.display()
        )));
    }

    Ok(())
}

fn temporary_profile_path(path: &Path) -> PathBuf {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("tmp");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let sequence = NEXT_TEMP_PROFILE_ID.fetch_add(1, Ordering::Relaxed);

    path.with_extension(format!(
        "{extension}.tmp-{}-{now}-{sequence}",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "tpm2-derive-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn persist_and_load_round_trip() {
        let root_dir = unique_temp_path("profile");
        let state_layout = StateLayout::new(root_dir.clone());
        let profile = Profile::new(
            "prod-signer".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Verify],
            ModeResolution {
                requested: ModePreference::Auto,
                resolved: Mode::Native,
                reasons: vec!["native supported".to_string()],
            },
            state_layout.clone(),
        );

        profile.persist().expect("profile should persist");
        let loaded =
            Profile::load_named("prod-signer", Some(root_dir.clone())).expect("profile loads");

        assert_eq!(loaded, profile);

        fs::remove_dir_all(root_dir).expect("temporary profile state should be removed");
    }
}
