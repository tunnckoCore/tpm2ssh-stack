use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::{Algorithm, Mode, ModePreference, StateLayout, UseCase};

pub const PROFILE_SCHEMA_VERSION: u32 = 1;

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
}
