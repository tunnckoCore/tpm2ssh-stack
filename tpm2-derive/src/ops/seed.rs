use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::{Builder as TempfileBuilder, NamedTempFile, TempDir};

use crate::backend::{CommandInvocation, CommandOutput, CommandRunner, ProcessCommandRunner};
use crate::crypto::DerivationSpec;
use crate::error::{Error, Result};
use crate::model::{Algorithm, Diagnostic, DiagnosticLevel, Identity, UseCase};

pub const SEED_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const SEED_RECOVERY_BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const SEED_RECOVERY_BUNDLE_KIND: &str = "seed-recovery-bundle-v1";
pub const MIN_SEED_BYTES: usize = 32;
pub const MAX_SEED_BYTES: usize = 64;
pub const MAX_DERIVED_BYTES: usize = 4096;
pub const DEFAULT_EXPORT_CONFIRMATION_PHRASE: &str =
    "I understand this export weakens TPM-only protection";
pub const SEED_OBJECT_LABEL_METADATA_KEY: &str = "seed.object-label";
pub const SEED_PUBLIC_BLOB_PATH_METADATA_KEY: &str = "seed.public-blob-path";
pub const SEED_PRIVATE_BLOB_PATH_METADATA_KEY: &str = "seed.private-blob-path";
pub const SEED_STORAGE_KIND_METADATA_KEY: &str = "seed.storage-kind";
pub const SEED_DERIVATION_KDF_METADATA_KEY: &str = "seed.kdf";
pub const SEED_DERIVATION_DOMAIN_LABEL_METADATA_KEY: &str = "seed.derivation-domain-label";
pub const SEED_SOFTWARE_DERIVED_AT_USE_TIME_METADATA_KEY: &str =
    "seed.software-derived-at-use-time";

pub type SeedMaterial = SecretBox<Vec<u8>>;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedIdentity {
    pub schema_version: u32,
    pub identity: String,
    pub algorithm: Algorithm,
    pub uses: Vec<UseCase>,
    pub storage: SeedStorage,
    pub derivation: SeedDerivation,
    pub export_policy: SeedExportPolicy,
}

impl SeedIdentity {
    pub fn scaffold(identity: String, algorithm: Algorithm, uses: Vec<UseCase>) -> Result<Self> {
        let candidate = Self {
            schema_version: SEED_PROFILE_SCHEMA_VERSION,
            storage: SeedStorage::tpm_sealed(identity.clone()),
            derivation: SeedDerivation::hkdf_sha256_v1(),
            export_policy: SeedExportPolicy::high_friction_recovery_only(),
            identity,
            algorithm,
            uses: normalize_uses(uses),
        };

        validate_seed_profile(&candidate)?;
        Ok(candidate)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedStorage {
    pub kind: SeedStorageKind,
    pub object_label: String,
    pub sealed_at_rest: bool,
    pub require_tpm_auth_on_open: bool,
    pub allow_insecure_temp_secret_files: bool,
}

impl SeedStorage {
    pub fn tpm_sealed(object_label: String) -> Self {
        Self {
            kind: SeedStorageKind::TpmSealed,
            object_label,
            sealed_at_rest: true,
            require_tpm_auth_on_open: true,
            allow_insecure_temp_secret_files: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedStorageKind {
    TpmSealed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedDerivation {
    pub kdf: SeedKdf,
    pub software_derived_at_use_time: bool,
    pub domain_label: String,
}

impl SeedDerivation {
    pub fn hkdf_sha256_v1() -> Self {
        Self {
            kdf: SeedKdf::HkdfSha256V1,
            software_derived_at_use_time: true,
            domain_label: "tpm2-derive.seed.software-derived".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedKdf {
    HkdfSha256V1,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedExportPolicy {
    pub access: SeedExportAccess,
    pub allow_raw_seed: bool,
    pub require_confirmation_phrase: bool,
    pub confirmation_phrase: String,
    pub require_reason: bool,
    pub require_explicit_destination: bool,
    pub allow_stdout: bool,
}

impl SeedExportPolicy {
    pub fn high_friction_recovery_only() -> Self {
        Self {
            access: SeedExportAccess::RecoveryOnly,
            allow_raw_seed: false,
            require_confirmation_phrase: true,
            confirmation_phrase: DEFAULT_EXPORT_CONFIRMATION_PHRASE.to_string(),
            require_reason: true,
            require_explicit_destination: true,
            allow_stdout: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedExportAccess {
    Deny,
    RecoveryOnly,
}

#[derive(Debug)]
pub struct SeedCreateRequest {
    pub identity: SeedIdentity,
    pub source: SeedCreateSource,
    pub overwrite_existing: bool,
}

#[derive(Debug)]
pub enum SeedCreateSource {
    GenerateRandom {
        bytes: usize,
    },
    Import {
        ingress: SeedImportIngress,
        material: Option<SeedMaterial>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedImportIngress {
    InMemory,
    Stdin,
    CommandArgument,
    EnvironmentVariable(String),
    FilePath(String),
    PredictableTempFile(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedCreatePlan {
    pub identity: SeedIdentity,
    pub source: SeedCreateSourceSummary,
    pub overwrite_existing: bool,
    pub warnings: Vec<Diagnostic>,
    pub next_backend_action: SeedBackendAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum SeedCreateSourceSummary {
    GenerateRandom {
        bytes: usize,
    },
    Import {
        ingress: SeedImportIngress,
        bytes: Option<usize>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedOpenRequest {
    pub identity: SeedIdentity,
    pub auth_source: SeedOpenAuthSource,
    pub output: SeedOpenOutput,
    pub require_fresh_unseal: bool,
    pub confirm_software_derivation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedOpenAuthSource {
    InteractivePrompt,
    Stdin,
    Callback,
    CommandArgument,
    EnvironmentVariable(String),
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum SeedOpenOutput {
    DerivedBytes(SoftwareSeedDerivationRequest),
    RawSeed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedOpenPlan {
    pub sealed_at_rest: bool,
    pub software_derived_at_use_time: bool,
    pub warnings: Vec<Diagnostic>,
    pub next_backend_action: SeedBackendAction,
    pub derivation: Option<SoftwareSeedDerivationPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SoftwareSeedDerivationRequest {
    pub spec: DerivationSpec,
    pub output_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SoftwareSeedDerivationPlan {
    pub kdf: SeedKdf,
    pub output_bytes: usize,
    pub info_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedExportRequest {
    pub identity: SeedIdentity,
    pub auth_source: SeedOpenAuthSource,
    pub destination: SeedExportDestination,
    pub format: SeedExportFormat,
    pub reason: String,
    pub confirm: bool,
    pub confirm_phrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum SeedExportDestination {
    ExplicitPath(String),
    CallerManagedSink,
    Stdout,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedExportFormat {
    RecoveryBundleV1,
    RawSeedBase64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedExportPlan {
    pub warnings: Vec<Diagnostic>,
    pub next_backend_action: SeedBackendAction,
    pub required_confirmations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedRecoveryImportRequest {
    pub bundle: SeedRecoveryBundleV1,
    pub target_profile: Option<String>,
    pub overwrite_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedRecoveryImportPlan {
    pub identity: SeedIdentity,
    pub restored_from_identity: String,
    pub seed_bytes: usize,
    pub warnings: Vec<Diagnostic>,
    pub next_backend_action: SeedBackendAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedRecoveryImportResult {
    pub identity: SeedIdentity,
    pub restored_from_identity: String,
    pub seed_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedRecoveryBundleV1 {
    pub schema_version: u32,
    pub kind: String,
    pub exported_at_unix_seconds: u64,
    pub reason: String,
    pub identity: SeedRecoveryBundleIdentity,
    pub seed: SeedRecoveryBundleSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedRecoveryBundleIdentity {
    pub name: String,
    pub algorithm: Algorithm,
    pub uses: Vec<UseCase>,
    pub derivation: SeedDerivation,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedRecoveryBundleSecret {
    pub encoding: String,
    pub bytes: usize,
    pub sha256: String,
    pub material: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedBackendAction {
    SealNewSeed,
    SealImportedSeed,
    UnsealSeed,
    ExportRecoveryMaterial,
}

pub fn plan_create(request: &SeedCreateRequest) -> Result<SeedCreatePlan> {
    validate_seed_profile(&request.identity)?;

    let mut warnings = seed_mode_usage_warnings(&request.identity);

    let (source, next_backend_action) = match &request.source {
        SeedCreateSource::GenerateRandom { bytes } => {
            validate_seed_len(*bytes)?;
            (
                SeedCreateSourceSummary::GenerateRandom { bytes: *bytes },
                SeedBackendAction::SealNewSeed,
            )
        }
        SeedCreateSource::Import { ingress, material } => {
            validate_safe_import_ingress(ingress)?;

            let bytes = match material {
                Some(material) => {
                    let len = material.expose_secret().len();
                    validate_seed_len(len)?;
                    Some(len)
                }
                None if matches!(ingress, SeedImportIngress::Stdin) => {
                    warnings.push(Diagnostic {
                        level: DiagnosticLevel::Warning,
                        code: "SEED_IMPORT_SIZE_UNCHECKED".to_string(),
                        message: "stdin import is allowed, but seed length cannot be validated until bytes are read and sealed".to_string(),
                    });
                    None
                }
                None => return Err(Error::Validation(
                    "import source requires seed material unless stdin will provide it at runtime"
                        .to_string(),
                )),
            };

            (
                SeedCreateSourceSummary::Import {
                    ingress: ingress.clone(),
                    bytes,
                },
                SeedBackendAction::SealImportedSeed,
            )
        }
    };

    Ok(SeedCreatePlan {
        identity: request.identity.clone(),
        source,
        overwrite_existing: request.overwrite_existing,
        warnings,
        next_backend_action,
    })
}

pub fn plan_open(request: &SeedOpenRequest) -> Result<SeedOpenPlan> {
    validate_seed_profile(&request.identity)?;
    validate_safe_auth_source(&request.auth_source)?;

    if !request.confirm_software_derivation {
        return Err(Error::Validation(
            "seed mode open requires explicit acknowledgement that the seed is sealed at rest but software-derived at use time".to_string(),
        ));
    }

    let mut warnings = seed_mode_usage_warnings(&request.identity);
    warnings.push(Diagnostic {
        level: DiagnosticLevel::Warning,
        code: "SEED_SOFTWARE_DERIVATION".to_string(),
        message: "seed mode keeps the root seed sealed at rest, but derived child material exists in host memory during software derivation".to_string(),
    });

    let derivation = match &request.output {
        SeedOpenOutput::DerivedBytes(derivation) => {
            validate_derivation_request(derivation)?;
            Some(SoftwareSeedDerivationPlan {
                kdf: request.identity.derivation.kdf,
                output_bytes: derivation.output_bytes,
                info_preview: canonical_derivation_info(&request.identity.derivation, &derivation.spec),
            })
        }
        SeedOpenOutput::RawSeed => {
            return Err(Error::Validation(
                "raw seed open is not supported; seed mode only opens through explicit software derivation".to_string(),
            ))
        }
    };

    Ok(SeedOpenPlan {
        sealed_at_rest: request.identity.storage.sealed_at_rest,
        software_derived_at_use_time: request.identity.derivation.software_derived_at_use_time,
        warnings,
        next_backend_action: SeedBackendAction::UnsealSeed,
        derivation,
    })
}

pub fn plan_export(request: &SeedExportRequest) -> Result<SeedExportPlan> {
    validate_seed_profile(&request.identity)?;
    validate_safe_auth_source(&request.auth_source)?;

    let policy = &request.identity.export_policy;

    if matches!(policy.access, SeedExportAccess::Deny) {
        return Err(Error::Validation(
            "seed export is denied by identity policy".to_string(),
        ));
    }

    if !request.confirm {
        return Err(Error::Validation(
            "seed export requires --confirm to acknowledge this is a break-glass recovery operation and exported material leaves TPM protection".to_string(),
        ));
    }

    if policy.require_reason && request.reason.trim().is_empty() {
        return Err(Error::Validation(
            "seed export requires a non-empty reason".to_string(),
        ));
    }

    if policy.require_confirmation_phrase {
        let provided = request.confirm_phrase.as_deref().unwrap_or_default();
        if provided != policy.confirmation_phrase {
            return Err(Error::Validation(
                "seed export confirmation phrase did not match policy".to_string(),
            ));
        }
    }

    match request.destination {
        SeedExportDestination::Stdout if !policy.allow_stdout => {
            return Err(Error::Validation(
                "seed export to stdout is denied by policy".to_string(),
            ));
        }
        SeedExportDestination::ExplicitPath(ref path) => {
            if path.trim().is_empty() {
                return Err(Error::Validation(
                    "seed export destination path must not be empty".to_string(),
                ));
            }
        }
        SeedExportDestination::CallerManagedSink if policy.require_explicit_destination => {
            return Err(Error::Validation(
                "seed export policy requires an explicit operator-chosen destination".to_string(),
            ));
        }
        SeedExportDestination::Stdout | SeedExportDestination::CallerManagedSink => {}
    }

    if matches!(request.format, SeedExportFormat::RawSeedBase64) && !policy.allow_raw_seed {
        return Err(Error::Validation(
            "raw seed export format is denied by policy".to_string(),
        ));
    }

    let mut warnings = seed_mode_usage_warnings(&request.identity);
    warnings.push(Diagnostic {
        level: DiagnosticLevel::Warning,
        code: "SEED_EXPORT_BREAK_GLASS".to_string(),
        message: "seed export is a break-glass recovery path; exported material must be protected outside TPM policy".to_string(),
    });

    Ok(SeedExportPlan {
        warnings,
        next_backend_action: SeedBackendAction::ExportRecoveryMaterial,
        required_confirmations: required_export_confirmations(policy),
    })
}

pub fn seed_profile_from_profile(identity: &Identity) -> Result<SeedIdentity> {
    let mut seed_profile = SeedIdentity::scaffold(
        identity.name.clone(),
        identity.algorithm,
        identity.uses.clone(),
    )?;

    if let Some(object_label) = identity.metadata.get(SEED_OBJECT_LABEL_METADATA_KEY) {
        seed_profile.storage.object_label = object_label.clone();
    }

    Ok(seed_profile)
}

pub fn parse_recovery_bundle_json(payload: &[u8]) -> Result<SeedRecoveryBundleV1> {
    let bundle: SeedRecoveryBundleV1 = serde_json::from_slice(payload)?;
    decode_recovery_bundle_seed(&bundle)?;
    Ok(bundle)
}

pub fn plan_recovery_import(request: &SeedRecoveryImportRequest) -> Result<SeedRecoveryImportPlan> {
    let seed = decode_recovery_bundle_seed(&request.bundle)?;
    let profile_name = request
        .target_profile
        .clone()
        .unwrap_or_else(|| request.bundle.identity.name.clone());
    let identity = SeedIdentity {
        schema_version: SEED_PROFILE_SCHEMA_VERSION,
        identity: profile_name.clone(),
        algorithm: request.bundle.identity.algorithm,
        uses: normalize_uses(request.bundle.identity.uses.clone()),
        storage: SeedStorage::tpm_sealed(profile_name),
        derivation: request.bundle.identity.derivation.clone(),
        export_policy: SeedExportPolicy::high_friction_recovery_only(),
    };
    validate_seed_profile(&identity)?;

    let mut warnings = seed_mode_usage_warnings(&identity);
    warnings.push(Diagnostic {
        level: DiagnosticLevel::Warning,
        code: "SEED_RECOVERY_IMPORT".to_string(),
        message: format!(
            "recovery import consumes exported seed material outside TPM sealed-at-rest protection; protect the bundle until import is complete"
        ),
    });

    Ok(SeedRecoveryImportPlan {
        identity,
        restored_from_identity: request.bundle.identity.name.clone(),
        seed_bytes: seed.len(),
        warnings,
        next_backend_action: SeedBackendAction::SealImportedSeed,
    })
}

pub fn restore_recovery_bundle(
    backend: &dyn SeedBackend,
    request: &SeedRecoveryImportRequest,
) -> Result<SeedRecoveryImportResult> {
    let plan = plan_recovery_import(request)?;
    let seed = decode_recovery_bundle_seed(&request.bundle)?;

    backend.seal_seed(&SeedCreateRequest {
        identity: plan.identity.clone(),
        source: SeedCreateSource::Import {
            ingress: SeedImportIngress::InMemory,
            material: Some(SecretBox::new(Box::new(seed))),
        },
        overwrite_existing: request.overwrite_existing,
    })?;

    Ok(SeedRecoveryImportResult {
        identity: plan.identity,
        restored_from_identity: plan.restored_from_identity,
        seed_bytes: plan.seed_bytes,
    })
}

pub fn export_recovery_bundle(
    backend: &dyn SeedBackend,
    request: &SeedExportRequest,
) -> Result<SeedRecoveryBundleV1> {
    plan_export(request)?;

    match request.format {
        SeedExportFormat::RecoveryBundleV1 => {
            let seed = backend.unseal_seed(&request.identity, &request.auth_source)?;
            Ok(build_recovery_bundle(request, seed.expose_secret()))
        }
        SeedExportFormat::RawSeedBase64 => Err(Error::Unsupported(
            "raw seed export is not wired in this vertical slice; use recovery-bundle export"
                .to_string(),
        )),
    }
}

pub trait SeedBackend {
    fn seal_seed(&self, request: &SeedCreateRequest) -> Result<()>;
    fn unseal_seed(
        &self,
        identity: &SeedIdentity,
        auth_source: &SeedOpenAuthSource,
    ) -> Result<SeedMaterial>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedSealedObjectLayout {
    pub object_dir: PathBuf,
    pub public_blob: PathBuf,
    pub private_blob: PathBuf,
}

impl SeedSealedObjectLayout {
    fn for_profile(objects_dir: &Path, identity: &SeedIdentity) -> Result<Self> {
        validate_profile_name(&identity.storage.object_label)?;

        let object_dir = objects_dir.join(&identity.storage.object_label);
        Ok(Self {
            public_blob: object_dir.join("sealed.pub"),
            private_blob: object_dir.join("sealed.priv"),
            object_dir,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SubprocessSeedBackend<R = ProcessCommandRunner> {
    objects_dir: PathBuf,
    runner: R,
}

impl SubprocessSeedBackend<ProcessCommandRunner> {
    pub fn new(objects_dir: impl Into<PathBuf>) -> Self {
        Self::with_runner(objects_dir, ProcessCommandRunner)
    }
}

impl<R> SubprocessSeedBackend<R> {
    pub fn with_runner(objects_dir: impl Into<PathBuf>, runner: R) -> Self {
        Self {
            objects_dir: objects_dir.into(),
            runner,
        }
    }

    pub fn objects_dir(&self) -> &Path {
        &self.objects_dir
    }

    pub fn sealed_object_layout(&self, identity: &SeedIdentity) -> Result<SeedSealedObjectLayout> {
        SeedSealedObjectLayout::for_profile(&self.objects_dir, identity)
    }
}

impl<R> SeedBackend for SubprocessSeedBackend<R>
where
    R: CommandRunner,
{
    fn seal_seed(&self, request: &SeedCreateRequest) -> Result<()> {
        plan_create(request)?;

        let layout = self.sealed_object_layout(&request.identity)?;
        let source_material = self.materialize_seed_source(&request.source)?;
        let transient = new_seed_tempdir()?;
        let staging = self.new_object_staging_dir()?;
        let primary_context = transient.path().join("primary.ctx");
        let seed_input = write_secret_tempfile(transient.path(), source_material.expose_secret())?;

        self.run_checked(&create_primary_invocation(&primary_context))?;
        self.run_checked(&seal_seed_invocation(
            &primary_context,
            seed_input.path(),
            &staging.public_blob,
            &staging.private_blob,
        ))?;

        self.commit_staging_object(staging, &layout, request.overwrite_existing)
    }

    fn unseal_seed(
        &self,
        identity: &SeedIdentity,
        auth_source: &SeedOpenAuthSource,
    ) -> Result<SeedMaterial> {
        validate_seed_profile(identity)?;
        validate_safe_auth_source(auth_source)?;

        if !matches!(auth_source, SeedOpenAuthSource::None) {
            return Err(Error::Unsupported(
                "seed backend unseal currently supports only auth-source=none; interactive or secret-backed TPM auth needs a richer request model"
                    .to_string(),
            ));
        }

        let layout = self.sealed_object_layout(identity)?;
        ensure_layout_exists(&layout)?;

        let transient = new_seed_tempdir()?;
        let primary_context = transient.path().join("primary.ctx");
        let object_context = transient.path().join("sealed.ctx");
        let output_path = transient.path().join("unsealed.bin");

        self.run_checked(&create_primary_invocation(&primary_context))?;
        self.run_checked(&load_sealed_object_invocation(
            &primary_context,
            &layout.public_blob,
            &layout.private_blob,
            &object_context,
        ))?;
        self.run_checked(&unseal_seed_invocation(&object_context, &output_path))?;

        let seed = read_secret_file(&output_path)?;
        validate_seed_len(seed.len())?;
        Ok(SecretBox::new(Box::new(seed)))
    }
}

impl<R> SubprocessSeedBackend<R>
where
    R: CommandRunner,
{
    fn materialize_seed_source(&self, source: &SeedCreateSource) -> Result<SeedMaterial> {
        match source {
            SeedCreateSource::GenerateRandom { bytes } => self.generate_random_seed(*bytes),
            SeedCreateSource::Import {
                ingress: _,
                material: Some(material),
            } => clone_seed_material(material),
            SeedCreateSource::Import {
                ingress: SeedImportIngress::Stdin,
                material: None,
            } => read_seed_from_stdin(),
            SeedCreateSource::Import { .. } => Err(Error::Validation(
                "import source requires in-memory seed bytes or stdin at execution time"
                    .to_string(),
            )),
        }
    }

    fn generate_random_seed(&self, bytes: usize) -> Result<SeedMaterial> {
        validate_seed_len(bytes)?;

        let transient = new_seed_tempdir()?;
        let output_path = transient.path().join("generated-seed.bin");
        self.run_checked(&generate_random_seed_invocation(bytes, &output_path))?;

        let seed = read_secret_file(&output_path)?;
        validate_seed_len(seed.len())?;
        Ok(SecretBox::new(Box::new(seed)))
    }

    fn new_object_staging_dir(&self) -> Result<SeedObjectStaging> {
        fs::create_dir_all(&self.objects_dir).map_err(|error| {
            Error::State(format!(
                "failed to create seed objects directory {}: {error}",
                self.objects_dir.display()
            ))
        })?;

        let tempdir = TempfileBuilder::new()
            .prefix("seed-object-")
            .tempdir_in(&self.objects_dir)
            .map_err(|error| {
                Error::State(format!(
                    "failed to create staging directory under {}: {error}",
                    self.objects_dir.display()
                ))
            })?;

        Ok(SeedObjectStaging {
            public_blob: tempdir.path().join("sealed.pub"),
            private_blob: tempdir.path().join("sealed.priv"),
            tempdir,
        })
    }

    fn commit_staging_object(
        &self,
        staging: SeedObjectStaging,
        layout: &SeedSealedObjectLayout,
        overwrite_existing: bool,
    ) -> Result<()> {
        if layout.object_dir.exists() && !overwrite_existing {
            return Err(Error::State(format!(
                "seed object already exists for identity '{}'; pass overwrite_existing to replace it",
                layout
                    .object_dir
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("<unknown>")
            )));
        }

        let staging_path = staging.tempdir.keep();

        if layout.object_dir.exists() {
            fs::remove_dir_all(&layout.object_dir).map_err(|error| {
                Error::State(format!(
                    "failed to remove existing seed object directory {}: {error}",
                    layout.object_dir.display()
                ))
            })?;
        }

        fs::rename(&staging_path, &layout.object_dir).map_err(|error| {
            Error::State(format!(
                "failed to persist sealed seed object {} -> {}: {error}",
                staging_path.display(),
                layout.object_dir.display()
            ))
        })?;

        lock_down_sealed_objects(layout)?;

        Ok(())
    }

    fn run_checked(&self, invocation: &CommandInvocation) -> Result<CommandOutput> {
        let output = self.runner.run(invocation);
        if output.error.is_none() && output.exit_code == Some(0) {
            return Ok(output);
        }

        Err(classify_command_error(invocation, &output))
    }
}

#[derive(Debug)]
struct SeedObjectStaging {
    public_blob: PathBuf,
    private_blob: PathBuf,
    tempdir: TempDir,
}

#[derive(Debug, Clone)]
pub struct ScaffoldSeedBackend {
    inner: SubprocessSeedBackend<ProcessCommandRunner>,
}

impl Default for ScaffoldSeedBackend {
    fn default() -> Self {
        let layout = crate::model::StateLayout::from_optional_root(None);
        Self {
            inner: SubprocessSeedBackend::new(layout.objects_dir),
        }
    }
}

impl SeedBackend for ScaffoldSeedBackend {
    fn seal_seed(&self, request: &SeedCreateRequest) -> Result<()> {
        self.inner.seal_seed(request)
    }

    fn unseal_seed(
        &self,
        identity: &SeedIdentity,
        auth_source: &SeedOpenAuthSource,
    ) -> Result<SeedMaterial> {
        self.inner.unseal_seed(identity, auth_source)
    }
}

fn create_primary_invocation(primary_context: &Path) -> CommandInvocation {
    CommandInvocation::new(
        "tpm2_createprimary",
        [
            "-C".to_string(),
            "o".to_string(),
            "-g".to_string(),
            "sha256".to_string(),
            "-G".to_string(),
            "rsa".to_string(),
            "-c".to_string(),
            path_arg(primary_context),
        ],
    )
}

fn seal_seed_invocation(
    primary_context: &Path,
    seed_input: &Path,
    public_blob: &Path,
    private_blob: &Path,
) -> CommandInvocation {
    CommandInvocation::new(
        "tpm2_create",
        [
            "-C".to_string(),
            path_arg(primary_context),
            "-g".to_string(),
            "sha256".to_string(),
            "-G".to_string(),
            "keyedhash".to_string(),
            "-a".to_string(),
            "fixedtpm|fixedparent|userwithauth".to_string(),
            "-i".to_string(),
            path_arg(seed_input),
            "-u".to_string(),
            path_arg(public_blob),
            "-r".to_string(),
            path_arg(private_blob),
        ],
    )
}

fn load_sealed_object_invocation(
    primary_context: &Path,
    public_blob: &Path,
    private_blob: &Path,
    object_context: &Path,
) -> CommandInvocation {
    CommandInvocation::new(
        "tpm2_load",
        [
            "-C".to_string(),
            path_arg(primary_context),
            "-u".to_string(),
            path_arg(public_blob),
            "-r".to_string(),
            path_arg(private_blob),
            "-c".to_string(),
            path_arg(object_context),
        ],
    )
}

fn unseal_seed_invocation(object_context: &Path, output_path: &Path) -> CommandInvocation {
    CommandInvocation::new(
        "tpm2_unseal",
        [
            "-c".to_string(),
            path_arg(object_context),
            "-o".to_string(),
            path_arg(output_path),
        ],
    )
}

fn generate_random_seed_invocation(bytes: usize, output_path: &Path) -> CommandInvocation {
    CommandInvocation::new(
        "tpm2_getrandom",
        ["-o".to_string(), path_arg(output_path), bytes.to_string()],
    )
}

fn new_seed_tempdir() -> Result<TempDir> {
    tempfile::tempdir().map_err(|error| {
        Error::State(format!(
            "failed to create secure temporary directory for seed handling: {error}"
        ))
    })
}

fn write_secret_tempfile(directory: &Path, bytes: &[u8]) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new_in(directory).map_err(|error| {
        Error::State(format!(
            "failed to create secure temporary file in {}: {error}",
            directory.display()
        ))
    })?;
    file.write_all(bytes).map_err(|error| {
        Error::State(format!(
            "failed to write secret material to secure temporary file {}: {error}",
            file.path().display()
        ))
    })?;
    file.flush().map_err(|error| {
        Error::State(format!(
            "failed to flush secret material to secure temporary file {}: {error}",
            file.path().display()
        ))
    })?;
    Ok(file)
}

fn read_secret_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| {
        Error::State(format!(
            "failed to read secret material from {}: {error}",
            path.display()
        ))
    })
}

fn read_seed_from_stdin() -> Result<SeedMaterial> {
    let mut buffer = Vec::new();
    let mut handle = std::io::stdin().lock().take((MAX_SEED_BYTES + 1) as u64);
    handle.read_to_end(&mut buffer).map_err(|error| {
        Error::State(format!("failed to read seed material from stdin: {error}"))
    })?;
    validate_seed_len(buffer.len())?;
    Ok(SecretBox::new(Box::new(buffer)))
}

fn ensure_layout_exists(layout: &SeedSealedObjectLayout) -> Result<()> {
    for path in [&layout.public_blob, &layout.private_blob] {
        if !path.is_file() {
            return Err(Error::State(format!(
                "sealed seed artifact is missing: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

/// Set directory to 0700 and each blob file to 0600.
#[cfg(unix)]
fn lock_down_sealed_objects(layout: &SeedSealedObjectLayout) -> Result<()> {
    fs::set_permissions(&layout.object_dir, fs::Permissions::from_mode(0o700)).map_err(
        |error| {
            Error::State(format!(
                "failed to set permissions on '{}': {error}",
                layout.object_dir.display()
            ))
        },
    )?;

    for path in [&layout.public_blob, &layout.private_blob] {
        if path.is_file() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
                Error::State(format!(
                    "failed to set permissions on '{}': {error}",
                    path.display()
                ))
            })?;
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn lock_down_sealed_objects(_layout: &SeedSealedObjectLayout) -> Result<()> {
    Ok(())
}

fn clone_seed_material(material: &SeedMaterial) -> Result<SeedMaterial> {
    let cloned = material.expose_secret().clone();
    validate_seed_len(cloned.len())?;
    Ok(SecretBox::new(Box::new(cloned)))
}

fn classify_command_error(invocation: &CommandInvocation, output: &CommandOutput) -> Error {
    let detail = render_command_failure_detail(output);
    let lower = detail.to_ascii_lowercase();
    let message = format!(
        "{} failed{}{}",
        invocation.program,
        output
            .exit_code
            .map(|code| format!(" with exit status {code}"))
            .unwrap_or_default(),
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    );

    if lower.contains("auth") || lower.contains("authorization") {
        Error::AuthFailure(message)
    } else if lower.contains("tcti")
        || lower.contains("/dev/tpm")
        || lower.contains("no standard tcti")
        || lower.contains("connection refused")
        || lower.contains("not found")
    {
        Error::TpmUnavailable(message)
    } else {
        Error::State(message)
    }
}

fn render_command_failure_detail(output: &CommandOutput) -> String {
    if let Some(error) = output.error.as_deref() {
        return error.to_string();
    }

    let detail = if !output.stderr.trim().is_empty() {
        output.stderr.trim()
    } else {
        output.stdout.trim()
    };

    preview(detail)
}

fn preview(value: &str) -> String {
    let single_line = value.lines().map(str::trim).collect::<Vec<_>>().join(" ");
    let trimmed = single_line.trim();
    const LIMIT: usize = 180;
    if trimmed.len() > LIMIT {
        format!("{}…", &trimmed[..LIMIT])
    } else {
        trimmed.to_string()
    }
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub trait SeedSoftwareDeriver {
    fn derive(
        &self,
        seed: &SeedMaterial,
        request: &SoftwareSeedDerivationRequest,
    ) -> Result<SeedMaterial>;
}

#[derive(Debug, Default)]
pub struct HkdfSha256SeedDeriver;

impl SeedSoftwareDeriver for HkdfSha256SeedDeriver {
    fn derive(
        &self,
        seed: &SeedMaterial,
        request: &SoftwareSeedDerivationRequest,
    ) -> Result<SeedMaterial> {
        validate_derivation_request(request)?;

        let info = canonical_derivation_info(&SeedDerivation::hkdf_sha256_v1(), &request.spec);
        let hkdf = Hkdf::<Sha256>::new(None, seed.expose_secret());
        let mut derived = vec![0_u8; request.output_bytes];
        hkdf.expand(info.as_bytes(), &mut derived).map_err(|_| {
            Error::Validation("requested derived output exceeds HKDF-SHA256 limits".to_string())
        })?;

        Ok(SecretBox::new(Box::new(derived)))
    }
}

pub fn open_and_derive(
    backend: &dyn SeedBackend,
    deriver: &dyn SeedSoftwareDeriver,
    request: &SeedOpenRequest,
) -> Result<SeedMaterial> {
    plan_open(request)?;
    let seed = backend.unseal_seed(&request.identity, &request.auth_source)?;

    match &request.output {
        SeedOpenOutput::DerivedBytes(derivation) => deriver.derive(&seed, derivation),
        SeedOpenOutput::RawSeed => Err(Error::Validation(
            "raw seed open is not supported".to_string(),
        )),
    }
}

fn build_recovery_bundle(request: &SeedExportRequest, seed: &[u8]) -> SeedRecoveryBundleV1 {
    SeedRecoveryBundleV1 {
        schema_version: SEED_RECOVERY_BUNDLE_SCHEMA_VERSION,
        kind: SEED_RECOVERY_BUNDLE_KIND.to_string(),
        exported_at_unix_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs(),
        reason: request.reason.clone(),
        identity: SeedRecoveryBundleIdentity {
            name: request.identity.identity.clone(),
            algorithm: request.identity.algorithm,
            uses: request.identity.uses.clone(),
            derivation: request.identity.derivation.clone(),
        },
        seed: SeedRecoveryBundleSecret {
            encoding: "hex".to_string(),
            bytes: seed.len(),
            sha256: sha256_hex(seed),
            material: hex_encode(seed),
        },
    }
}

pub fn validate_seed_profile(identity: &SeedIdentity) -> Result<()> {
    validate_profile_name(&identity.identity)?;

    if identity.schema_version != SEED_PROFILE_SCHEMA_VERSION {
        return Err(Error::Validation(format!(
            "unsupported seed identity schema version: {}",
            identity.schema_version
        )));
    }

    if identity.uses.is_empty() {
        return Err(Error::Validation(
            "seed identity must declare at least one use".to_string(),
        ));
    }

    if !matches!(identity.storage.kind, SeedStorageKind::TpmSealed)
        || !identity.storage.sealed_at_rest
    {
        return Err(Error::Validation(
            "seed identities must use TPM-sealed storage at rest".to_string(),
        ));
    }

    if identity.storage.allow_insecure_temp_secret_files {
        return Err(Error::Validation(
            "seed identities may not permit insecure temp secret files".to_string(),
        ));
    }

    if !identity.derivation.software_derived_at_use_time {
        return Err(Error::Validation(
            "seed identities must explicitly record that derivation happens in software at use time"
                .to_string(),
        ));
    }

    Ok(())
}

fn validate_derivation_request(request: &SoftwareSeedDerivationRequest) -> Result<()> {
    if request.output_bytes == 0 || request.output_bytes > MAX_DERIVED_BYTES {
        return Err(Error::Validation(format!(
            "seed derivation output must be between 1 and {MAX_DERIVED_BYTES} bytes"
        )));
    }

    request.spec.canonical_bytes()?;

    Ok(())
}

fn validate_profile_name(identity: &str) -> Result<()> {
    if identity.trim().is_empty() {
        return Err(Error::Validation(
            "identity name must not be empty".to_string(),
        ));
    }

    if !identity
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(Error::Validation(
            "identity name may only contain ASCII letters, digits, '.', '_' or '-'".to_string(),
        ));
    }

    if identity.contains("..") || identity.contains('/') || identity.contains('\\') {
        return Err(Error::Validation(
            "identity name must not contain path traversal or separators".to_string(),
        ));
    }

    Ok(())
}

fn validate_seed_len(bytes: usize) -> Result<()> {
    if !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&bytes) {
        return Err(Error::Validation(format!(
            "seed material must be between {MIN_SEED_BYTES} and {MAX_SEED_BYTES} bytes"
        )));
    }

    Ok(())
}

fn validate_safe_import_ingress(ingress: &SeedImportIngress) -> Result<()> {
    match ingress {
        SeedImportIngress::InMemory | SeedImportIngress::Stdin => Ok(()),
        SeedImportIngress::CommandArgument => Err(Error::Validation(
            "seed import through command arguments is forbidden".to_string(),
        )),
        SeedImportIngress::EnvironmentVariable(name) => Err(Error::Validation(format!(
            "seed import through environment variables is forbidden: {name}"
        ))),
        SeedImportIngress::FilePath(path) => Err(Error::Validation(format!(
            "seed import from file paths is not scaffolded yet; avoid temp-file secret handling: {path}"
        ))),
        SeedImportIngress::PredictableTempFile(path) => Err(Error::Validation(format!(
            "seed import from predictable temp files is forbidden: {path}"
        ))),
    }
}

fn validate_safe_auth_source(source: &SeedOpenAuthSource) -> Result<()> {
    match source {
        SeedOpenAuthSource::InteractivePrompt
        | SeedOpenAuthSource::Stdin
        | SeedOpenAuthSource::Callback
        | SeedOpenAuthSource::None => Ok(()),
        SeedOpenAuthSource::CommandArgument => Err(Error::Validation(
            "TPM auth material may not be supplied via command arguments".to_string(),
        )),
        SeedOpenAuthSource::EnvironmentVariable(name) => Err(Error::Validation(format!(
            "TPM auth material may not be supplied via environment variable: {name}"
        ))),
    }
}

fn normalize_uses(uses: Vec<UseCase>) -> Vec<UseCase> {
    let unique: BTreeSet<_> = uses.into_iter().collect();
    unique.into_iter().collect()
}

fn seed_mode_usage_warnings(identity: &SeedIdentity) -> Vec<Diagnostic> {
    let mut warnings = Vec::new();

    if identity.algorithm == Algorithm::P256
        && identity
            .uses
            .iter()
            .all(|use_case| matches!(use_case, UseCase::Sign | UseCase::Verify))
    {
        warnings.push(Diagnostic {
            level: DiagnosticLevel::Warning,
            code: "SEED_P256_NATIVE_PREFERRED".to_string(),
            message: "p256 sign/verify usually fits native TPM mode better than seed mode"
                .to_string(),
        });
    }

    if matches!(
        identity.export_policy.access,
        SeedExportAccess::RecoveryOnly
    ) {
        warnings.push(Diagnostic {
            level: DiagnosticLevel::Info,
            code: "SEED_RECOVERY_EXPORT".to_string(),
            message: "seed mode permits recovery export only under explicit high-friction policy"
                .to_string(),
        });
    }

    warnings
}

fn required_export_confirmations(policy: &SeedExportPolicy) -> Vec<String> {
    let mut confirmations = vec![
        "--confirm: acknowledge this is a break-glass recovery operation and exported material leaves TPM protection".to_string(),
    ];

    if policy.require_confirmation_phrase {
        confirmations.push(format!(
            "--confirm-phrase: repeat confirmation phrase exactly: {}",
            policy.confirmation_phrase
        ));
    }

    if policy.require_explicit_destination {
        confirmations.push("choose an explicit export destination instead of stdout".to_string());
    }

    confirmations
}

fn decode_recovery_bundle_seed(bundle: &SeedRecoveryBundleV1) -> Result<Vec<u8>> {
    if bundle.schema_version != SEED_RECOVERY_BUNDLE_SCHEMA_VERSION {
        return Err(Error::Validation(format!(
            "unsupported seed recovery bundle schema version: {}",
            bundle.schema_version
        )));
    }

    if bundle.kind != SEED_RECOVERY_BUNDLE_KIND {
        return Err(Error::Validation(format!(
            "unsupported seed recovery bundle kind: {}",
            bundle.kind
        )));
    }

    if bundle.seed.encoding != "hex" {
        return Err(Error::Validation(format!(
            "unsupported seed recovery bundle encoding: {}",
            bundle.seed.encoding
        )));
    }

    let seed = hex_decode(&bundle.seed.material)?;
    validate_seed_len(seed.len())?;

    if bundle.seed.bytes != seed.len() {
        return Err(Error::Validation(format!(
            "seed recovery bundle declared {} bytes but decoded {} bytes",
            bundle.seed.bytes,
            seed.len()
        )));
    }

    let digest = sha256_hex(&seed);
    if bundle.seed.sha256 != digest {
        return Err(Error::Validation(
            "seed recovery bundle sha256 did not match decoded seed material".to_string(),
        ));
    }

    Ok(seed)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(Error::Validation(
            "seed recovery bundle hex material must have an even number of characters".to_string(),
        ));
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
        .map(|(index, pair)| {
            let pair = std::str::from_utf8(pair).expect("hex pairs are ascii");
            u8::from_str_radix(pair, 16).map_err(|_| {
                Error::Validation(format!(
                    "seed recovery bundle hex material contained invalid data at byte index {index}"
                ))
            })
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
}

fn canonical_derivation_info(derivation: &SeedDerivation, spec: &DerivationSpec) -> String {
    let context = spec.context();
    let mut info = vec![
        "tpm2-derive".to_string(),
        "seed".to_string(),
        format!("kdf={}", seed_kdf_name(derivation.kdf)),
        format!("identity-derivation-domain={}", derivation.domain_label),
        format!("spec-version={:?}", spec.version()),
        format!("namespace={}", context.namespace),
        format!("purpose={}", context.purpose),
    ];

    if let Some(label) = &context.label {
        info.push(format!("label={label}"));
    }

    for (key, value) in &context.fields {
        info.push(format!("ctx:{key}={value}"));
    }

    info.join("\0")
}

fn seed_kdf_name(kdf: SeedKdf) -> &'static str {
    match kdf {
        SeedKdf::HkdfSha256V1 => "hkdf-sha256-v1",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::rc::Rc;

    use super::*;

    fn seed_profile() -> SeedIdentity {
        SeedIdentity::scaffold(
            "seed-identity".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::Ssh],
        )
        .expect("seed identity")
    }

    fn derivation_request() -> SoftwareSeedDerivationRequest {
        SoftwareSeedDerivationRequest {
            spec: crate::crypto::DerivationSpec::V1(
                crate::crypto::DerivationSpecV1::software_child_key(
                    "tpm2ssh",
                    "ed25519",
                    "account/alice/default",
                    crate::crypto::OutputKind::SecretBytes,
                )
                .expect("derivation spec"),
            ),
            output_bytes: 32,
        }
    }

    #[test]
    fn create_rejects_insecure_import_ingress() {
        let request = SeedCreateRequest {
            identity: seed_profile(),
            source: SeedCreateSource::Import {
                ingress: SeedImportIngress::CommandArgument,
                material: Some(SecretBox::new(Box::new(vec![7_u8; 32]))),
            },
            overwrite_existing: false,
        };

        let error = plan_create(&request).expect_err("expected validation failure");
        assert!(error.to_string().contains("command arguments is forbidden"));
    }

    #[test]
    fn open_requires_explicit_software_derivation_ack() {
        let request = SeedOpenRequest {
            identity: seed_profile(),
            auth_source: SeedOpenAuthSource::InteractivePrompt,
            output: SeedOpenOutput::DerivedBytes(derivation_request()),
            require_fresh_unseal: true,
            confirm_software_derivation: false,
        };

        let error = plan_open(&request).expect_err("expected validation failure");
        assert!(error.to_string().contains("software-derived at use time"));
    }

    #[test]
    fn export_requires_confirmation_phrase() {
        let request = SeedExportRequest {
            identity: seed_profile(),
            auth_source: SeedOpenAuthSource::InteractivePrompt,
            destination: SeedExportDestination::ExplicitPath(
                "/safe/location/recovery.json".to_string(),
            ),
            format: SeedExportFormat::RecoveryBundleV1,
            reason: "hardware migration".to_string(),
            confirm: true,
            confirm_phrase: Some("wrong phrase".to_string()),
        };

        let error = plan_export(&request).expect_err("expected validation failure");
        assert!(error.to_string().contains("confirmation phrase"));
    }

    #[test]
    fn export_recovery_bundle_materializes_seed_hex() {
        let request = SeedExportRequest {
            identity: seed_profile(),
            auth_source: SeedOpenAuthSource::None,
            destination: SeedExportDestination::ExplicitPath(
                "/safe/location/recovery.json".to_string(),
            ),
            format: SeedExportFormat::RecoveryBundleV1,
            reason: "hardware migration".to_string(),
            confirm: true,
            confirm_phrase: Some(DEFAULT_EXPORT_CONFIRMATION_PHRASE.to_string()),
        };

        let seed = sample_seed();
        let bundle = export_recovery_bundle(&FakeSeedBackend(seed.clone()), &request)
            .expect("recovery bundle should export");

        assert_eq!(bundle.schema_version, SEED_RECOVERY_BUNDLE_SCHEMA_VERSION);
        assert_eq!(bundle.kind, SEED_RECOVERY_BUNDLE_KIND);
        assert_eq!(bundle.reason, "hardware migration");
        assert_eq!(bundle.identity.name, "seed-identity");
        assert_eq!(bundle.seed.encoding, "hex");
        assert_eq!(bundle.seed.bytes, seed.len());
        assert_eq!(bundle.seed.material, hex_encode(&seed));
        assert_eq!(bundle.seed.sha256, sha256_hex(&seed));
        assert!(bundle.exported_at_unix_seconds > 0);
    }

    #[test]
    fn parse_recovery_bundle_json_rejects_sha256_mismatch() {
        let bundle = SeedRecoveryBundleV1 {
            schema_version: SEED_RECOVERY_BUNDLE_SCHEMA_VERSION,
            kind: SEED_RECOVERY_BUNDLE_KIND.to_string(),
            exported_at_unix_seconds: 1,
            reason: "hardware migration".to_string(),
            identity: SeedRecoveryBundleIdentity {
                name: "seed-identity".to_string(),
                algorithm: Algorithm::Ed25519,
                uses: vec![UseCase::Sign],
                derivation: SeedDerivation::hkdf_sha256_v1(),
            },
            seed: SeedRecoveryBundleSecret {
                encoding: "hex".to_string(),
                bytes: 32,
                sha256: "00".repeat(32),
                material: "11".repeat(32),
            },
        };

        let payload = serde_json::to_vec(&bundle).expect("bundle json");
        let error = parse_recovery_bundle_json(&payload).expect_err("sha mismatch should fail");
        assert!(error.to_string().contains("sha256 did not match"));
    }

    #[test]
    fn restore_recovery_bundle_reseals_seed_with_target_profile_override() {
        let seed = sample_seed();
        let request = SeedRecoveryImportRequest {
            bundle: SeedRecoveryBundleV1 {
                schema_version: SEED_RECOVERY_BUNDLE_SCHEMA_VERSION,
                kind: SEED_RECOVERY_BUNDLE_KIND.to_string(),
                exported_at_unix_seconds: 1,
                reason: "hardware migration".to_string(),
                identity: SeedRecoveryBundleIdentity {
                    name: "old-identity".to_string(),
                    algorithm: Algorithm::Ed25519,
                    uses: vec![UseCase::Sign, UseCase::Ssh],
                    derivation: SeedDerivation::hkdf_sha256_v1(),
                },
                seed: SeedRecoveryBundleSecret {
                    encoding: "hex".to_string(),
                    bytes: seed.len(),
                    sha256: sha256_hex(&seed),
                    material: hex_encode(&seed),
                },
            },
            target_profile: Some("new-identity".to_string()),
            overwrite_existing: true,
        };
        let backend = RecordingImportBackend::default();

        let result = restore_recovery_bundle(&backend, &request).expect("restore bundle");

        assert_eq!(result.identity.identity, "new-identity");
        assert_eq!(result.identity.storage.object_label, "new-identity");
        assert_eq!(result.restored_from_identity, "old-identity");
        assert_eq!(result.seed_bytes, seed.len());

        let sealed = backend.last_request.borrow();
        let sealed = sealed.as_ref().expect("seal request recorded");
        assert!(sealed.overwrite_existing);
        assert_eq!(sealed.identity.identity, "new-identity");
        match &sealed.source {
            RecordedSeedCreateSource::Import {
                ingress,
                material: Some(material),
            } => {
                assert_eq!(*ingress, SeedImportIngress::InMemory);
                assert_eq!(material.expose_secret().as_slice(), seed.as_slice());
            }
            other => panic!("expected imported seed, found {other:?}"),
        }
    }

    #[test]
    fn seed_profile_from_profile_uses_metadata_object_label_override() {
        let root = tempfile::tempdir().expect("state root");
        let mut identity = crate::model::Identity::new(
            "seed-identity".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Sign],
            crate::model::IdentityModeResolution {
                requested: crate::model::ModePreference::Seed,
                resolved: crate::model::Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            crate::model::StateLayout::new(root.path().to_path_buf()),
        );
        identity.metadata.insert(
            SEED_OBJECT_LABEL_METADATA_KEY.to_string(),
            "portable-seed-object".to_string(),
        );

        let seed_profile = seed_profile_from_profile(&identity).expect("seed identity from host");
        assert_eq!(seed_profile.storage.object_label, "portable-seed-object");
    }

    #[test]
    fn hkdf_derivation_is_deterministic() {
        let deriver = HkdfSha256SeedDeriver;
        let request = derivation_request();
        let seed = SecretBox::new(Box::new(vec![42_u8; 32]));

        let left = deriver.derive(&seed, &request).expect("left");
        let right = deriver.derive(&seed, &request).expect("right");

        assert_eq!(left.expose_secret(), right.expose_secret());
        assert_eq!(left.expose_secret().len(), 32);
    }

    #[derive(Debug)]
    struct FakeSeedBackend(Vec<u8>);

    impl SeedBackend for FakeSeedBackend {
        fn seal_seed(&self, _request: &SeedCreateRequest) -> Result<()> {
            unreachable!("seed sealing is not used in export tests")
        }

        fn unseal_seed(
            &self,
            _profile: &SeedIdentity,
            _auth_source: &SeedOpenAuthSource,
        ) -> Result<SeedMaterial> {
            Ok(SecretBox::new(Box::new(self.0.clone())))
        }
    }

    #[derive(Debug, Default)]
    struct RecordingImportBackend {
        last_request: RefCell<Option<RecordedSealRequest>>,
    }

    #[derive(Debug)]
    struct RecordedSealRequest {
        identity: SeedIdentity,
        overwrite_existing: bool,
        source: RecordedSeedCreateSource,
    }

    #[derive(Debug)]
    enum RecordedSeedCreateSource {
        GenerateRandom,
        Import {
            ingress: SeedImportIngress,
            material: Option<SeedMaterial>,
        },
    }

    impl SeedBackend for RecordingImportBackend {
        fn seal_seed(&self, request: &SeedCreateRequest) -> Result<()> {
            let source = match &request.source {
                SeedCreateSource::GenerateRandom { .. } => RecordedSeedCreateSource::GenerateRandom,
                SeedCreateSource::Import { ingress, material } => {
                    RecordedSeedCreateSource::Import {
                        ingress: ingress.clone(),
                        material: material.as_ref().map(|material| {
                            clone_seed_material(material).expect("clone seed material")
                        }),
                    }
                }
            };

            self.last_request.replace(Some(RecordedSealRequest {
                identity: request.identity.clone(),
                overwrite_existing: request.overwrite_existing,
                source,
            }));
            Ok(())
        }

        fn unseal_seed(
            &self,
            _profile: &SeedIdentity,
            _auth_source: &SeedOpenAuthSource,
        ) -> Result<SeedMaterial> {
            unreachable!("recovery import does not unseal from the backend")
        }
    }

    #[derive(Debug)]
    struct RecordingRunnerState {
        expected_create_input: Option<Vec<u8>>,
        generated_seed: Option<Vec<u8>>,
        unsealed_seed: Option<Vec<u8>>,
        invocations: RefCell<Vec<CommandInvocation>>,
        create_input_paths: RefCell<Vec<PathBuf>>,
        unseal_output_paths: RefCell<Vec<PathBuf>>,
    }

    impl RecordingRunnerState {
        fn new(
            expected_create_input: Option<Vec<u8>>,
            generated_seed: Option<Vec<u8>>,
            unsealed_seed: Option<Vec<u8>>,
        ) -> Rc<Self> {
            Rc::new(Self {
                expected_create_input,
                generated_seed,
                unsealed_seed,
                invocations: RefCell::new(Vec::new()),
                create_input_paths: RefCell::new(Vec::new()),
                unseal_output_paths: RefCell::new(Vec::new()),
            })
        }
    }

    #[derive(Clone, Debug)]
    struct RecordingRunner {
        state: Rc<RecordingRunnerState>,
    }

    impl RecordingRunner {
        fn new(state: Rc<RecordingRunnerState>) -> Self {
            Self { state }
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.state.invocations.borrow_mut().push(invocation.clone());

            match invocation.program.as_str() {
                "tpm2_getrandom" => {
                    let output = pathbuf_arg(invocation, "-o");
                    let requested = invocation
                        .args
                        .last()
                        .and_then(|value| value.parse::<usize>().ok())
                        .expect("requested byte count");
                    let bytes = self
                        .state
                        .generated_seed
                        .as_ref()
                        .expect("generated seed configured");
                    assert_eq!(bytes.len(), requested);
                    fs::write(&output, bytes).expect("write random seed output");
                    ok_output()
                }
                "tpm2_createprimary" => {
                    fs::write(pathbuf_arg(invocation, "-c"), b"primary-context")
                        .expect("write primary context");
                    ok_output()
                }
                "tpm2_create" => {
                    let input = pathbuf_arg(invocation, "-i");
                    self.state
                        .create_input_paths
                        .borrow_mut()
                        .push(input.clone());
                    if let Some(expected) = &self.state.expected_create_input {
                        let actual = fs::read(&input).expect("read sealing input");
                        assert_eq!(&actual, expected);
                    }
                    fs::write(pathbuf_arg(invocation, "-u"), b"public-blob")
                        .expect("write public blob");
                    fs::write(pathbuf_arg(invocation, "-r"), b"private-blob")
                        .expect("write private blob");
                    ok_output()
                }
                "tpm2_load" => {
                    fs::write(pathbuf_arg(invocation, "-c"), b"sealed-context")
                        .expect("write load context");
                    ok_output()
                }
                "tpm2_unseal" => {
                    let output = pathbuf_arg(invocation, "-o");
                    self.state
                        .unseal_output_paths
                        .borrow_mut()
                        .push(output.clone());
                    let bytes = self
                        .state
                        .unsealed_seed
                        .as_ref()
                        .expect("unsealed seed configured");
                    fs::write(&output, bytes).expect("write unseal output");
                    ok_output()
                }
                other => CommandOutput {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    error: Some(format!("unexpected program: {other}")),
                },
            }
        }
    }

    fn ok_output() -> CommandOutput {
        CommandOutput {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            error: None,
        }
    }

    fn pathbuf_arg(invocation: &CommandInvocation, flag: &str) -> PathBuf {
        PathBuf::from(string_arg(invocation, flag))
    }

    fn string_arg(invocation: &CommandInvocation, flag: &str) -> String {
        let index = invocation
            .args
            .iter()
            .position(|arg| arg == flag)
            .expect("flag present");
        invocation.args[index + 1].clone()
    }

    fn sample_seed() -> Vec<u8> {
        b"0123456789abcdef0123456789abcdef".to_vec()
    }

    fn recorded_programs(state: &RecordingRunnerState) -> Vec<String> {
        state
            .invocations
            .borrow()
            .iter()
            .map(|invocation| invocation.program.clone())
            .collect()
    }

    #[test]
    fn subprocess_backend_seals_imported_seed_with_secure_tempfiles() {
        let objects_dir = tempfile::tempdir().expect("objects dir");
        let seed = sample_seed();
        let state = RecordingRunnerState::new(Some(seed.clone()), None, None);
        let backend = SubprocessSeedBackend::with_runner(
            objects_dir.path().to_path_buf(),
            RecordingRunner::new(state.clone()),
        );
        let identity = seed_profile();
        let layout = backend.sealed_object_layout(&identity).expect("layout");
        let request = SeedCreateRequest {
            identity,
            source: SeedCreateSource::Import {
                ingress: SeedImportIngress::InMemory,
                material: Some(SecretBox::new(Box::new(seed.clone()))),
            },
            overwrite_existing: false,
        };

        backend.seal_seed(&request).expect("seal imported seed");

        assert_eq!(
            recorded_programs(&state),
            vec!["tpm2_createprimary", "tpm2_create"]
        );
        assert_eq!(
            fs::read(&layout.public_blob).expect("public blob"),
            b"public-blob"
        );
        assert_eq!(
            fs::read(&layout.private_blob).expect("private blob"),
            b"private-blob"
        );

        let create_input_path = state.create_input_paths.borrow()[0].clone();
        assert!(
            !create_input_path.exists(),
            "temporary seed input should be cleaned up"
        );

        let seed_as_text = String::from_utf8(seed).expect("ascii seed");
        for invocation in state.invocations.borrow().iter() {
            for arg in &invocation.args {
                assert!(
                    !arg.contains(&seed_as_text),
                    "seed material must not appear in subprocess argv"
                );
            }
        }
    }

    #[test]
    fn subprocess_backend_generates_seed_via_tpm2_getrandom_before_sealing() {
        let objects_dir = tempfile::tempdir().expect("objects dir");
        let seed = b"abcdef0123456789abcdef0123456789".to_vec();
        let state = RecordingRunnerState::new(Some(seed.clone()), Some(seed), None);
        let backend = SubprocessSeedBackend::with_runner(
            objects_dir.path().to_path_buf(),
            RecordingRunner::new(state.clone()),
        );
        let request = SeedCreateRequest {
            identity: seed_profile(),
            source: SeedCreateSource::GenerateRandom { bytes: 32 },
            overwrite_existing: false,
        };

        backend.seal_seed(&request).expect("seal generated seed");

        assert_eq!(
            recorded_programs(&state),
            vec!["tpm2_getrandom", "tpm2_createprimary", "tpm2_create"]
        );
        let create_input_path = state.create_input_paths.borrow()[0].clone();
        assert!(
            !create_input_path.exists(),
            "generated seed tempfile should be cleaned up"
        );
    }

    #[test]
    fn subprocess_backend_unseals_seed_through_output_file() {
        let objects_dir = tempfile::tempdir().expect("objects dir");
        let seed = sample_seed();
        let state = RecordingRunnerState::new(None, None, Some(seed.clone()));
        let backend = SubprocessSeedBackend::with_runner(
            objects_dir.path().to_path_buf(),
            RecordingRunner::new(state.clone()),
        );
        let identity = seed_profile();
        let layout = backend.sealed_object_layout(&identity).expect("layout");
        fs::create_dir_all(&layout.object_dir).expect("object dir");
        fs::write(&layout.public_blob, b"public-blob").expect("public blob");
        fs::write(&layout.private_blob, b"private-blob").expect("private blob");

        let unsealed = backend
            .unseal_seed(&identity, &SeedOpenAuthSource::None)
            .expect("unseal seed");

        assert_eq!(
            recorded_programs(&state),
            vec!["tpm2_createprimary", "tpm2_load", "tpm2_unseal"]
        );
        assert_eq!(unsealed.expose_secret().as_slice(), seed.as_slice());

        let unseal_output_path = state.unseal_output_paths.borrow()[0].clone();
        assert!(
            !unseal_output_path.exists(),
            "unseal output tempfile should be cleaned up"
        );
    }

    #[test]
    fn subprocess_backend_rejects_auth_sources_that_need_secret_transport() {
        let objects_dir = tempfile::tempdir().expect("objects dir");
        let backend = SubprocessSeedBackend::with_runner(
            objects_dir.path().to_path_buf(),
            RecordingRunner::new(RecordingRunnerState::new(None, None, None)),
        );

        let error = backend
            .unseal_seed(&seed_profile(), &SeedOpenAuthSource::InteractivePrompt)
            .expect_err("interactive auth should remain unsupported for now");
        assert!(error.to_string().contains("auth-source=none"));
    }
}
