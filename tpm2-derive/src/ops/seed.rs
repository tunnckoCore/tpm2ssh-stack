use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeSet;

use crate::crypto::DerivationSpec;
use crate::error::{Error, Result};
use crate::model::{Algorithm, Diagnostic, DiagnosticLevel, UseCase};

pub const SEED_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const MIN_SEED_BYTES: usize = 32;
pub const MAX_SEED_BYTES: usize = 64;
pub const MAX_DERIVED_BYTES: usize = 4096;
pub const DEFAULT_EXPORT_CONFIRMATION_PHRASE: &str =
    "I understand this export weakens TPM-only protection";

pub type SeedMaterial = SecretBox<Vec<u8>>;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedProfile {
    pub schema_version: u32,
    pub profile: String,
    pub algorithm: Algorithm,
    pub uses: Vec<UseCase>,
    pub storage: SeedStorage,
    pub derivation: SeedDerivation,
    pub export_policy: SeedExportPolicy,
}

impl SeedProfile {
    pub fn scaffold(profile: String, algorithm: Algorithm, uses: Vec<UseCase>) -> Result<Self> {
        let candidate = Self {
            schema_version: SEED_PROFILE_SCHEMA_VERSION,
            storage: SeedStorage::tpm_sealed(profile.clone()),
            derivation: SeedDerivation::hkdf_sha256_v1(),
            export_policy: SeedExportPolicy::high_friction_recovery_only(),
            profile,
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
    pub profile: SeedProfile,
    pub source: SeedCreateSource,
    pub overwrite_existing: bool,
}

#[derive(Debug)]
pub enum SeedCreateSource {
    GenerateRandom { bytes: usize },
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
    pub profile: SeedProfile,
    pub source: SeedCreateSourceSummary,
    pub overwrite_existing: bool,
    pub warnings: Vec<Diagnostic>,
    pub next_backend_action: SeedBackendAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum SeedCreateSourceSummary {
    GenerateRandom { bytes: usize },
    Import {
        ingress: SeedImportIngress,
        bytes: Option<usize>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SeedOpenRequest {
    pub profile: SeedProfile,
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
    pub profile: SeedProfile,
    pub auth_source: SeedOpenAuthSource,
    pub destination: SeedExportDestination,
    pub format: SeedExportFormat,
    pub reason: String,
    pub confirm_recovery_export: bool,
    pub confirm_sealed_at_rest_boundary: bool,
    pub confirmation_phrase: Option<String>,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedBackendAction {
    SealNewSeed,
    SealImportedSeed,
    UnsealSeed,
    ExportRecoveryMaterial,
}

pub fn plan_create(request: &SeedCreateRequest) -> Result<SeedCreatePlan> {
    validate_seed_profile(&request.profile)?;

    let mut warnings = seed_mode_usage_warnings(&request.profile);

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
                None => {
                    return Err(Error::Validation(
                        "import source requires seed material unless stdin will provide it at runtime"
                            .to_string(),
                    ))
                }
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
        profile: request.profile.clone(),
        source,
        overwrite_existing: request.overwrite_existing,
        warnings,
        next_backend_action,
    })
}

pub fn plan_open(request: &SeedOpenRequest) -> Result<SeedOpenPlan> {
    validate_seed_profile(&request.profile)?;
    validate_safe_auth_source(&request.auth_source)?;

    if !request.confirm_software_derivation {
        return Err(Error::Validation(
            "seed mode open requires explicit acknowledgement that the seed is sealed at rest but software-derived at use time".to_string(),
        ));
    }

    let mut warnings = seed_mode_usage_warnings(&request.profile);
    warnings.push(Diagnostic {
        level: DiagnosticLevel::Warning,
        code: "SEED_SOFTWARE_DERIVATION".to_string(),
        message: "seed mode keeps the root seed sealed at rest, but derived child material exists in host memory during software derivation".to_string(),
    });

    let derivation = match &request.output {
        SeedOpenOutput::DerivedBytes(derivation) => {
            validate_derivation_request(derivation)?;
            Some(SoftwareSeedDerivationPlan {
                kdf: request.profile.derivation.kdf,
                output_bytes: derivation.output_bytes,
                info_preview: canonical_derivation_info(&request.profile.derivation, &derivation.spec),
            })
        }
        SeedOpenOutput::RawSeed => {
            return Err(Error::Validation(
                "raw seed open is not supported; seed mode only opens through explicit software derivation".to_string(),
            ))
        }
    };

    Ok(SeedOpenPlan {
        sealed_at_rest: request.profile.storage.sealed_at_rest,
        software_derived_at_use_time: request.profile.derivation.software_derived_at_use_time,
        warnings,
        next_backend_action: SeedBackendAction::UnsealSeed,
        derivation,
    })
}

pub fn plan_export(request: &SeedExportRequest) -> Result<SeedExportPlan> {
    validate_seed_profile(&request.profile)?;
    validate_safe_auth_source(&request.auth_source)?;

    let policy = &request.profile.export_policy;

    if matches!(policy.access, SeedExportAccess::Deny) {
        return Err(Error::Validation(
            "seed export is denied by profile policy".to_string(),
        ));
    }

    if !request.confirm_recovery_export {
        return Err(Error::Validation(
            "seed export requires explicit recovery-export confirmation".to_string(),
        ));
    }

    if !request.confirm_sealed_at_rest_boundary {
        return Err(Error::Validation(
            "seed export requires acknowledgement that exported material no longer benefits from TPM sealed-at-rest protection".to_string(),
        ));
    }

    if policy.require_reason && request.reason.trim().is_empty() {
        return Err(Error::Validation(
            "seed export requires a non-empty reason".to_string(),
        ));
    }

    if policy.require_confirmation_phrase {
        let provided = request.confirmation_phrase.as_deref().unwrap_or_default();
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
            ))
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
            ))
        }
        SeedExportDestination::Stdout | SeedExportDestination::CallerManagedSink => {}
    }

    if matches!(request.format, SeedExportFormat::RawSeedBase64) && !policy.allow_raw_seed {
        return Err(Error::Validation(
            "raw seed export format is denied by policy".to_string(),
        ));
    }

    let mut warnings = seed_mode_usage_warnings(&request.profile);
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

pub trait SeedBackend {
    fn seal_seed(&self, request: &SeedCreateRequest) -> Result<()>;
    fn unseal_seed(&self, profile: &SeedProfile, auth_source: &SeedOpenAuthSource) -> Result<SeedMaterial>;
}

#[derive(Debug, Default)]
pub struct ScaffoldSeedBackend;

impl SeedBackend for ScaffoldSeedBackend {
    fn seal_seed(&self, _request: &SeedCreateRequest) -> Result<()> {
        Err(Error::Unsupported(
            "real TPM seed sealing backend is not implemented yet".to_string(),
        ))
    }

    fn unseal_seed(&self, _profile: &SeedProfile, _auth_source: &SeedOpenAuthSource) -> Result<SeedMaterial> {
        Err(Error::Unsupported(
            "real TPM seed unseal backend is not implemented yet".to_string(),
        ))
    }
}

pub trait SeedSoftwareDeriver {
    fn derive(&self, seed: &SeedMaterial, request: &SoftwareSeedDerivationRequest) -> Result<SeedMaterial>;
}

#[derive(Debug, Default)]
pub struct HkdfSha256SeedDeriver;

impl SeedSoftwareDeriver for HkdfSha256SeedDeriver {
    fn derive(&self, seed: &SeedMaterial, request: &SoftwareSeedDerivationRequest) -> Result<SeedMaterial> {
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
    let seed = backend.unseal_seed(&request.profile, &request.auth_source)?;

    match &request.output {
        SeedOpenOutput::DerivedBytes(derivation) => deriver.derive(&seed, derivation),
        SeedOpenOutput::RawSeed => Err(Error::Validation(
            "raw seed open is not supported".to_string(),
        )),
    }
}

pub fn validate_seed_profile(profile: &SeedProfile) -> Result<()> {
    validate_profile_name(&profile.profile)?;

    if profile.schema_version != SEED_PROFILE_SCHEMA_VERSION {
        return Err(Error::Validation(format!(
            "unsupported seed profile schema version: {}",
            profile.schema_version
        )));
    }

    if profile.uses.is_empty() {
        return Err(Error::Validation(
            "seed profile must declare at least one use".to_string(),
        ));
    }

    if profile
        .uses
        .iter()
        .any(|use_case| matches!(use_case, UseCase::Encrypt | UseCase::Decrypt))
    {
        return Err(Error::Validation(
            "seed mode scaffold does not support encrypt/decrypt uses".to_string(),
        ));
    }

    if !matches!(profile.storage.kind, SeedStorageKind::TpmSealed) || !profile.storage.sealed_at_rest {
        return Err(Error::Validation(
            "seed profiles must use TPM-sealed storage at rest".to_string(),
        ));
    }

    if profile.storage.allow_insecure_temp_secret_files {
        return Err(Error::Validation(
            "seed profiles may not permit insecure temp secret files".to_string(),
        ));
    }

    if !profile.derivation.software_derived_at_use_time {
        return Err(Error::Validation(
            "seed profiles must explicitly record that derivation happens in software at use time"
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

fn validate_profile_name(profile: &str) -> Result<()> {
    if profile.trim().is_empty() {
        return Err(Error::Validation(
            "profile name must not be empty".to_string(),
        ));
    }

    if !profile
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(Error::Validation(
            "profile name may only contain ASCII letters, digits, '.', '_' or '-'"
                .to_string(),
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

fn seed_mode_usage_warnings(profile: &SeedProfile) -> Vec<Diagnostic> {
    let mut warnings = Vec::new();

    if profile.algorithm == Algorithm::P256
        && profile
            .uses
            .iter()
            .all(|use_case| matches!(use_case, UseCase::Sign | UseCase::Verify))
    {
        warnings.push(Diagnostic {
            level: DiagnosticLevel::Warning,
            code: "SEED_P256_NATIVE_PREFERRED".to_string(),
            message: "p256 sign/verify usually fits native TPM mode better than seed mode".to_string(),
        });
    }

    if matches!(profile.export_policy.access, SeedExportAccess::RecoveryOnly) {
        warnings.push(Diagnostic {
            level: DiagnosticLevel::Info,
            code: "SEED_RECOVERY_EXPORT".to_string(),
            message: "seed mode permits recovery export only under explicit high-friction policy".to_string(),
        });
    }

    warnings
}

fn required_export_confirmations(policy: &SeedExportPolicy) -> Vec<String> {
    let mut confirmations = vec![
        "confirm this is a break-glass recovery operation".to_string(),
        "acknowledge exported material is no longer protected by TPM sealed-at-rest policy"
            .to_string(),
    ];

    if policy.require_confirmation_phrase {
        confirmations.push(format!(
            "repeat confirmation phrase exactly: {}",
            policy.confirmation_phrase
        ));
    }

    if policy.require_explicit_destination {
        confirmations.push("choose an explicit export destination instead of stdout".to_string());
    }

    confirmations
}

fn canonical_derivation_info(derivation: &SeedDerivation, spec: &DerivationSpec) -> String {
    let context = spec.context();
    let mut info = vec![
        "tpm2-derive".to_string(),
        "seed".to_string(),
        format!("kdf={}", seed_kdf_name(derivation.kdf)),
        format!("profile-derivation-domain={}", derivation.domain_label),
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
    use super::*;


    fn seed_profile() -> SeedProfile {
        SeedProfile::scaffold(
            "seed-profile".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Derive, UseCase::SshAgent],
        )
        .expect("seed profile")
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
            profile: seed_profile(),
            source: SeedCreateSource::Import {
                ingress: SeedImportIngress::CommandArgument,
                material: Some(SecretBox::new(Box::new(vec![7_u8; 32]))),
            },
            overwrite_existing: false,
        };

        let error = plan_create(&request).expect_err("expected validation failure");
        assert!(error
            .to_string()
            .contains("command arguments is forbidden"));
    }

    #[test]
    fn open_requires_explicit_software_derivation_ack() {
        let request = SeedOpenRequest {
            profile: seed_profile(),
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
            profile: seed_profile(),
            auth_source: SeedOpenAuthSource::InteractivePrompt,
            destination: SeedExportDestination::ExplicitPath("/safe/location/recovery.json".to_string()),
            format: SeedExportFormat::RecoveryBundleV1,
            reason: "hardware migration".to_string(),
            confirm_recovery_export: true,
            confirm_sealed_at_rest_boundary: true,
            confirmation_phrase: Some("wrong phrase".to_string()),
        };

        let error = plan_export(&request).expect_err("expected validation failure");
        assert!(error.to_string().contains("confirmation phrase"));
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
}
