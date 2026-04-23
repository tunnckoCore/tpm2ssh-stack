use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::{Algorithm, Mode, ModePreference, StateLayout, UseCase};
use crate::ops::shared::{IDENTITY_JSON_BYTES_LIMIT, read_path_string_with_limit};

pub const IDENTITY_SCHEMA_VERSION: u32 = 2;
pub const IDENTITY_NAME_POLICY_PATTERN: &str = "^[a-zA-Z0-9_-]+$";

static NEXT_TEMP_IDENTITY_ID: AtomicU64 = AtomicU64::new(0);

pub fn validate_identity_name_policy(name: &str, field: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Validation(format!("{field} must not be empty")));
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::Validation(format!(
            "{field} must match {IDENTITY_NAME_POLICY_PATTERN}"
        )));
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct IdentityModeResolution {
    pub requested: ModePreference,
    pub resolved: Mode,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct IdentityDerivationDefaults {
    pub org: Option<String>,
    pub purpose: Option<String>,
    pub context: BTreeMap<String, String>,
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
                public_key_export: true,
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
pub struct IdentityStorage {
    pub state_layout: StateLayout,
    pub identity_path: PathBuf,
    pub root_material_kind: RootMaterialKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Identity {
    pub schema_version: u32,
    pub name: String,
    pub algorithm: Algorithm,
    pub uses: Vec<UseCase>,
    pub mode: IdentityModeResolution,
    pub defaults: IdentityDerivationDefaults,
    pub storage: IdentityStorage,
    pub export_policy: ExportPolicy,
    pub metadata: BTreeMap<String, String>,
}

impl Identity {
    pub fn new(
        name: String,
        algorithm: Algorithm,
        uses: Vec<UseCase>,
        mode: IdentityModeResolution,
        state_layout: StateLayout,
    ) -> Self {
        Self::with_defaults(
            name,
            algorithm,
            uses,
            mode,
            IdentityDerivationDefaults::default(),
            state_layout,
        )
    }

    pub fn with_defaults(
        name: String,
        algorithm: Algorithm,
        uses: Vec<UseCase>,
        mode: IdentityModeResolution,
        defaults: IdentityDerivationDefaults,
        state_layout: StateLayout,
    ) -> Self {
        let identity_path = state_layout.identity_path(&name);
        let resolved = mode.resolved;

        Self {
            schema_version: IDENTITY_SCHEMA_VERSION,
            name,
            algorithm,
            uses,
            mode,
            defaults,
            storage: IdentityStorage {
                identity_path,
                state_layout,
                root_material_kind: RootMaterialKind::for_mode(resolved),
            },
            export_policy: ExportPolicy::for_mode(resolved),
            metadata: BTreeMap::new(),
        }
    }

    pub fn persist(&self) -> Result<()> {
        validate_identity_name_policy(&self.name, "identity name")?;
        self.storage.state_layout.ensure_dirs()?;
        write_json_atomically(&self.storage.identity_path, self)
    }

    pub fn load_named(name: &str, state_dir: Option<PathBuf>) -> Result<Self> {
        Self::load_from_layout(name, StateLayout::from_optional_root(state_dir))
    }

    pub fn load_from_layout(name: &str, state_layout: StateLayout) -> Result<Self> {
        validate_identity_name_policy(name, "identity name")?;

        let identity_path = state_layout.identity_path(name);
        let contents = read_path_string_with_limit(
            &identity_path,
            &format!("identity '{}'", name),
            IDENTITY_JSON_BYTES_LIMIT,
        )?;

        let mut parsed: serde_json::Value = serde_json::from_str(&contents).map_err(|error| {
            Error::State(format!(
                "failed to parse identity '{}' from '{}': {error}",
                name,
                identity_path.display()
            ))
        })?;

        if let Some(uses) = parsed
            .get_mut("uses")
            .and_then(serde_json::Value::as_array_mut)
        {
            uses.retain(|value| value.as_str() != Some("derive"));
        }

        let mut identity: Self = serde_json::from_value(parsed).map_err(|error| {
            Error::State(format!(
                "failed to decode identity '{}' from '{}': {error}",
                name,
                identity_path.display()
            ))
        })?;

        validate_identity_name_policy(&identity.name, "identity name")?;

        if identity.name != name {
            return Err(Error::State(format!(
                "identity file '{}' declared name '{}' but was loaded as '{}'; recreate the identity instead of repointing persisted state",
                identity_path.display(),
                identity.name,
                name,
            )));
        }
        UseCase::validate_for_mode(&identity.uses, identity.mode.resolved).map_err(|error| {
            Error::State(format!(
                "identity '{}' from '{}' failed mode/use validation: {error}",
                name,
                identity_path.display()
            ))
        })?;

        identity.storage.state_layout = state_layout;
        identity.storage.identity_path = identity_path;

        Ok(identity)
    }
}

fn write_json_atomically(path: &Path, identity: &Identity) -> Result<()> {
    let temp_path = temporary_identity_path(path);
    let payload = format!("{}\n", serde_json::to_string_pretty(identity)?);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(&temp_path).map_err(|error| {
        Error::State(format!(
            "failed to create temporary identity file '{}': {error}",
            temp_path.display()
        ))
    })?;

    if let Err(error) = file.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(Error::State(format!(
            "failed to write temporary identity file '{}': {error}",
            temp_path.display()
        )));
    }

    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(Error::State(format!(
            "failed to persist identity to '{}': {error}",
            path.display()
        )));
    }

    Ok(())
}

fn temporary_identity_path(path: &Path) -> PathBuf {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("tmp");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let sequence = NEXT_TEMP_IDENTITY_ID.fetch_add(1, Ordering::Relaxed);

    path.with_extension(format!(
        "{extension}.tmp-{}-{now}-{sequence}",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs::File;
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
    fn validate_identity_name_policy_rejects_invalid_names() {
        for invalid in [
            ".",
            "nested/name",
            r"nested\name",
            "white space",
            "mix./ bad",
        ] {
            let error = validate_identity_name_policy(invalid, "identity name")
                .expect_err("invalid identity names should fail closed");
            assert!(
                matches!(error, Error::Validation(message) if message.contains(IDENTITY_NAME_POLICY_PATTERN))
            );
        }
    }

    #[test]
    fn persist_rejects_invalid_identity_name() {
        let root_dir = unique_temp_path("identity-invalid-persist");
        let state_layout = StateLayout::new(root_dir.clone());
        let identity = Identity::new(
            ".".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign],
            IdentityModeResolution {
                requested: ModePreference::Auto,
                resolved: Mode::Native,
                reasons: vec!["test".to_string()],
            },
            state_layout,
        );

        let error = identity
            .persist()
            .expect_err("invalid identity names should not persist");
        assert!(
            matches!(error, Error::Validation(message) if message.contains(IDENTITY_NAME_POLICY_PATTERN))
        );
    }

    #[test]
    fn load_named_rejects_invalid_requested_identity_names() {
        let root_dir = unique_temp_path("identity-invalid-load-name");

        for invalid in [
            ".",
            "nested/name",
            r"nested\name",
            "white space",
            "mix./ bad",
        ] {
            let error = Identity::load_named(invalid, Some(root_dir.clone()))
                .expect_err("invalid identity names should fail before path resolution");
            assert!(
                matches!(error, Error::Validation(message) if message.contains(IDENTITY_NAME_POLICY_PATTERN))
            );
        }
    }

    #[test]
    fn persist_and_load_round_trip() {
        let root_dir = unique_temp_path("identity");
        let state_layout = StateLayout::new(root_dir.clone());
        let identity = Identity::with_defaults(
            "prod-signer".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Verify],
            IdentityModeResolution {
                requested: ModePreference::Auto,
                resolved: Mode::Native,
                reasons: vec!["native supported".to_string()],
            },
            IdentityDerivationDefaults {
                org: Some("com.example".to_string()),
                purpose: Some("default".to_string()),
                context: BTreeMap::from([("tenant".to_string(), "alpha".to_string())]),
            },
            state_layout.clone(),
        );

        identity.persist().expect("identity should persist");
        let loaded =
            Identity::load_named("prod-signer", Some(root_dir.clone())).expect("identity loads");

        assert_eq!(loaded, identity);

        fs::remove_dir_all(root_dir).expect("temporary identity state should be removed");
    }

    #[test]
    fn serde_round_trip_keeps_export_secret_and_derivation_defaults() {
        let identity = Identity::with_defaults(
            "portable".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::ExportSecret],
            IdentityModeResolution {
                requested: ModePreference::Prf,
                resolved: Mode::Prf,
                reasons: vec!["test".to_string()],
            },
            IdentityDerivationDefaults {
                org: Some("com.example".to_string()),
                purpose: Some("backup".to_string()),
                context: BTreeMap::from([("tenant".to_string(), "alpha".to_string())]),
            },
            StateLayout::new(PathBuf::from("/tmp/tpm2-derive-identity-serde")),
        );

        let json = serde_json::to_string_pretty(&identity).expect("serialize identity");
        assert!(json.contains("\"export-secret\""));
        assert!(json.contains("\"org\": \"com.example\""));
        assert!(json.contains("\"purpose\": \"backup\""));

        let round_tripped: Identity = serde_json::from_str(&json).expect("deserialize identity");
        assert_eq!(
            round_tripped.uses,
            vec![UseCase::Sign, UseCase::ExportSecret]
        );
        assert_eq!(
            round_tripped.defaults.context,
            BTreeMap::from([("tenant".to_string(), "alpha".to_string())])
        );
    }

    #[cfg(unix)]
    #[test]
    fn persist_creates_identity_file_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let root_dir = unique_temp_path("identity-perms");
        let state_layout = StateLayout::new(root_dir.clone());
        let identity = Identity::new(
            "perm-test".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign],
            IdentityModeResolution {
                requested: ModePreference::Auto,
                resolved: Mode::Native,
                reasons: vec!["test".to_string()],
            },
            state_layout,
        );

        identity.persist().expect("persist");

        let mode = fs::metadata(&identity.storage.identity_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "identity file should be 0600");

        fs::remove_dir_all(root_dir).expect("cleanup");
    }

    #[test]
    fn load_named_rejects_oversized_identity_json() {
        let root_dir = unique_temp_path("identity-oversized");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("create state layout");

        let identity_path = state_layout.identity_path("oversized");
        let file = File::create(&identity_path).expect("create oversized identity file");
        file.set_len((IDENTITY_JSON_BYTES_LIMIT + 1) as u64)
            .expect("oversized identity json");

        let error = Identity::load_named("oversized", Some(root_dir.clone()))
            .expect_err("oversized identity JSON should fail closed");
        assert!(
            matches!(error, Error::Validation(message) if message.contains("identity 'oversized'") && message.contains("limit"))
        );

        fs::remove_dir_all(root_dir).expect("cleanup");
    }

    #[test]
    fn load_named_rejects_repointed_identity_name() {
        let root_dir = unique_temp_path("identity-repoint-name");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("create state layout");
        let identity = Identity::new(
            "prod-signer".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Verify],
            IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout.clone(),
        );
        identity.persist().expect("persist identity");

        let identity_path = state_layout.identity_path("prod-signer");
        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&identity_path).expect("identity json"))
                .expect("parse identity json");
        value["name"] = serde_json::Value::String("other-identity".to_string());
        fs::write(
            &identity_path,
            serde_json::to_vec_pretty(&value).expect("json bytes"),
        )
        .expect("rewrite identity json");

        let error = Identity::load_named("prod-signer", Some(root_dir.clone()))
            .expect_err("repointed identity name should fail");
        assert!(
            matches!(error, Error::State(message) if message.contains("recreate the identity instead of repointing persisted state"))
        );

        fs::remove_dir_all(root_dir).expect("cleanup");
    }

    #[test]
    fn load_named_rejects_invalid_mode_use_combinations() {
        let root_dir = unique_temp_path("identity-invalid-uses");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("create state layout");
        let identity = Identity::new(
            "prod-signer".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Verify],
            IdentityModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            state_layout.clone(),
        );
        identity.persist().expect("persist identity");

        let identity_path = state_layout.identity_path("prod-signer");
        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&identity_path).expect("identity json"))
                .expect("parse identity json");
        value["uses"] = serde_json::json!(["sign", "ssh"]);
        fs::write(
            &identity_path,
            serde_json::to_vec_pretty(&value).expect("json bytes"),
        )
        .expect("rewrite identity json");

        let error = Identity::load_named("prod-signer", Some(root_dir.clone()))
            .expect_err("invalid use bits should fail");
        assert!(
            matches!(error, Error::State(message) if message.contains("failed mode/use validation"))
        );

        fs::remove_dir_all(root_dir).expect("cleanup");
    }
}
