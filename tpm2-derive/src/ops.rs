//! High-level operations root for `tpm2-derive`.
//!
//! This file is the `crate::ops` module root and intentionally coexists with
//! the `src/ops/` directory, which contains its submodules.

pub mod derive;
pub mod encrypt;
mod enforcement;
pub mod keygen;
pub mod native;
pub mod prf;
pub mod seed;
pub mod ssh;

use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::pkcs8::EncodePublicKey;
use secrecy::ExposeSecret;
use sha2::{Digest as _, Sha256};
use tempfile::Builder as TempfileBuilder;

use ssh_key::{
    PublicKey as SshPublicKey,
    public::{EcdsaPublicKey as SshEcdsaPublicKey, KeyData as SshKeyData},
};

use crate::backend::recommend::mode_rejection_reason;
use crate::backend::{CapabilityProbe, CommandOutput, CommandRunner, ProcessCommandRunner};
use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, CapabilityReport, ExportArtifact, ExportFormat, ExportKind, ExportRequest,
    ExportResult, InspectRequest, Mode, ModePreference, ModeResolution, Profile,
    PublicKeyExportFormat, RecoveryImportRequest, RecoveryImportResult, SetupRequest, SetupResult,
    StateLayout, UseCase, expand_mode_requested_uses,
};
use crate::ops::native::subprocess::{
    NativeCommandSpec, NativeKeyLocator, NativePersistentHandle, NativePublicKeyExportOptions,
    NativeSetupArtifacts, plan_export_public_key, plan_setup,
};
use crate::ops::native::{
    NativeAlgorithm, NativeCurve, NativeHardwareBinding, NativeKeyRef, NativeKeyUse,
    NativePrivateKeyPolicy, NativePublicKeyEncoding, NativePublicKeyExportRequest,
    NativeSetupRequest,
};
use crate::ops::prf::{
    PRF_CONTEXT_PATH_METADATA_KEY, PRF_PARENT_CONTEXT_PATH_METADATA_KEY,
    PRF_PRIVATE_PATH_METADATA_KEY, PRF_PUBLIC_PATH_METADATA_KEY, PrfRootLayout,
    SubprocessPrfBackend,
};
use crate::ops::seed::{
    HkdfSha256SeedDeriver, MIN_SEED_BYTES, SEED_DERIVATION_DOMAIN_LABEL_METADATA_KEY,
    SEED_DERIVATION_KDF_METADATA_KEY, SEED_OBJECT_LABEL_METADATA_KEY,
    SEED_PRIVATE_BLOB_PATH_METADATA_KEY, SEED_PUBLIC_BLOB_PATH_METADATA_KEY,
    SEED_SOFTWARE_DERIVED_AT_USE_TIME_METADATA_KEY, SEED_STORAGE_KIND_METADATA_KEY, SeedBackend,
    SeedCreateRequest, SeedCreateSource, SeedExportDestination, SeedExportFormat,
    SeedExportRequest, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest, SeedProfile,
    SeedRecoveryBundleV1, SeedRecoveryImportRequest, SeedSoftwareDeriver, SeedStorageKind,
    SoftwareSeedDerivationRequest, SubprocessSeedBackend,
    export_recovery_bundle as export_seed_recovery_bundle, open_and_derive,
    parse_recovery_bundle_json, restore_recovery_bundle as restore_seed_recovery_bundle,
    seed_profile_from_profile,
};

const DEFAULT_SETUP_SEED_BYTES: usize = MIN_SEED_BYTES;
const SEED_PUBLIC_KEY_NAMESPACE: &str = "tpm2-derive.export";
const SEED_PUBLIC_KEY_PATH: &str = "m/public-key/default";
const SEED_SCALAR_RETRY_DOMAIN: &[u8] = b"tpm2-derive\0seed-scalar-retry\0v1";
const SEED_SCALAR_RETRY_LIMIT: u32 = 16;

pub fn inspect(probe: &dyn CapabilityProbe, request: &InspectRequest) -> CapabilityReport {
    probe.detect(request.algorithm, &normalize_uses(request.uses.clone()))
}

pub fn resolve_profile(probe: &dyn CapabilityProbe, request: &SetupRequest) -> Result<SetupResult> {
    resolve_profile_with_runner(probe, request, &ProcessCommandRunner)
}

fn resolve_profile_with_runner<R>(
    probe: &dyn CapabilityProbe,
    request: &SetupRequest,
    runner: &R,
) -> Result<SetupResult>
where
    R: CommandRunner,
{
    let mut profile = build_setup_profile(probe, request)?;

    let persisted = if request.dry_run {
        false
    } else {
        let provisioned_dir = match profile.mode.resolved {
            Mode::Native => {
                materialize_native_setup(&mut profile, runner)?;
                None
            }
            Mode::Prf => {
                let layout = materialize_prf_setup(&mut profile, runner)?;
                Some(layout.object_dir)
            }
            Mode::Seed => {
                let backend =
                    SubprocessSeedBackend::new(profile.storage.state_layout.objects_dir.clone());
                persist_seed_setup_profile(&mut profile, &backend)?;
                None
            }
        };

        if let Err(error) = profile.persist() {
            if let Some(path) = provisioned_dir {
                let _ = fs::remove_dir_all(path);
            }
            return Err(error);
        }

        true
    };

    Ok(SetupResult {
        profile,
        dry_run: request.dry_run,
        persisted,
    })
}

#[cfg(test)]
fn resolve_profile_with_seed_backend(
    probe: &dyn CapabilityProbe,
    request: &SetupRequest,
    seed_backend: &dyn SeedBackend,
) -> Result<SetupResult> {
    let mut profile = build_setup_profile(probe, request)?;
    let persisted = if request.dry_run {
        false
    } else {
        persist_seed_setup_profile(&mut profile, seed_backend)?;
        profile.persist()?;
        true
    };

    Ok(SetupResult {
        profile,
        dry_run: request.dry_run,
        persisted,
    })
}

fn build_setup_profile(probe: &dyn CapabilityProbe, request: &SetupRequest) -> Result<Profile> {
    validate_profile_name(&request.profile)?;

    let requested_uses = normalize_uses(request.uses.clone());
    if requested_uses.is_empty() {
        return Err(Error::Validation(
            "at least one --use value is required for setup".to_string(),
        ));
    }

    let report = probe.detect(Some(request.algorithm), &requested_uses);
    let resolved_mode = resolve_mode(
        probe,
        request.requested_mode,
        request.algorithm,
        &requested_uses,
        &report,
    )?;
    let uses = expand_mode_requested_uses(
        resolved_mode,
        Some(request.algorithm),
        &report.native,
        &requested_uses,
    );
    if uses.is_empty() {
        return Err(Error::CapabilityMismatch(format!(
            "requested uses {:?} expand to an empty supported set for {resolved_mode:?} mode and {:?}",
            requested_uses, request.algorithm
        )));
    }

    // Enforce mode/use compatibility at setup time after mode-aware expansion.
    UseCase::validate_for_mode(&uses, resolved_mode)?;

    let mut reasons = if let Some(explicit) = request.requested_mode.explicit() {
        vec![format!("mode explicitly requested as {explicit:?}")]
    } else {
        report.recommendation_reasons.clone()
    };

    if requested_uses.iter().any(|use_case| use_case.is_all()) {
        reasons.push(format!(
            "expanded --use all for {resolved_mode:?} mode into {:?}",
            uses
        ));
    }

    Ok(Profile::new(
        request.profile.clone(),
        request.algorithm,
        uses,
        ModeResolution {
            requested: request.requested_mode,
            resolved: resolved_mode,
            reasons,
        },
        StateLayout::from_optional_root(request.state_dir.clone()),
    ))
}

fn persist_seed_setup_profile(profile: &mut Profile, seed_backend: &dyn SeedBackend) -> Result<()> {
    let seed_profile = SeedProfile::scaffold(
        profile.name.clone(),
        profile.algorithm,
        profile.uses.clone(),
    )?;

    seed_backend.seal_seed(&SeedCreateRequest {
        profile: seed_profile.clone(),
        source: SeedCreateSource::GenerateRandom {
            bytes: DEFAULT_SETUP_SEED_BYTES,
        },
        overwrite_existing: false,
    })?;

    apply_seed_profile_metadata(profile, &seed_profile);
    Ok(())
}

fn apply_seed_profile_metadata(profile: &mut Profile, seed_profile: &SeedProfile) {
    let object_dir = profile
        .storage
        .state_layout
        .objects_dir
        .join(&seed_profile.storage.object_label);
    let public_blob = object_dir.join("sealed.pub");
    let private_blob = object_dir.join("sealed.priv");

    profile.metadata.insert(
        SEED_OBJECT_LABEL_METADATA_KEY.to_string(),
        seed_profile.storage.object_label.clone(),
    );
    profile.metadata.insert(
        SEED_PUBLIC_BLOB_PATH_METADATA_KEY.to_string(),
        state_relative_metadata_path(profile, &public_blob),
    );
    profile.metadata.insert(
        SEED_PRIVATE_BLOB_PATH_METADATA_KEY.to_string(),
        state_relative_metadata_path(profile, &private_blob),
    );
    profile.metadata.insert(
        SEED_STORAGE_KIND_METADATA_KEY.to_string(),
        seed_storage_kind_name(seed_profile.storage.kind).to_string(),
    );
    profile.metadata.insert(
        SEED_DERIVATION_KDF_METADATA_KEY.to_string(),
        seed_kdf_name(seed_profile.derivation.kdf).to_string(),
    );
    profile.metadata.insert(
        SEED_DERIVATION_DOMAIN_LABEL_METADATA_KEY.to_string(),
        seed_profile.derivation.domain_label.clone(),
    );
    profile.metadata.insert(
        SEED_SOFTWARE_DERIVED_AT_USE_TIME_METADATA_KEY.to_string(),
        seed_profile
            .derivation
            .software_derived_at_use_time
            .to_string(),
    );
}

fn state_relative_metadata_path(profile: &Profile, path: &Path) -> String {
    path.strip_prefix(&profile.storage.state_layout.root_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn seed_storage_kind_name(kind: SeedStorageKind) -> &'static str {
    match kind {
        SeedStorageKind::TpmSealed => "tpm-sealed",
    }
}

fn seed_kdf_name(kdf: crate::ops::seed::SeedKdf) -> &'static str {
    match kdf {
        crate::ops::seed::SeedKdf::HkdfSha256V1 => "hkdf-sha256-v1",
    }
}

pub fn load_profile(profile: &str, state_dir: Option<PathBuf>) -> Result<Profile> {
    validate_profile_name(profile)?;
    Profile::load_named(profile, state_dir)
}

pub fn import_recovery_bundle(request: &RecoveryImportRequest) -> Result<RecoveryImportResult> {
    validate_recovery_bundle_input_path(&request.bundle_path)?;

    let payload = fs::read(&request.bundle_path).map_err(|error| {
        Error::State(format!(
            "failed to read recovery bundle '{}': {error}",
            request.bundle_path.display()
        ))
    })?;
    let bundle = parse_recovery_bundle_json(&payload)?;
    let state_layout = StateLayout::from_optional_root(request.state_dir.clone());
    let backend = SubprocessSeedBackend::new(state_layout.objects_dir.clone());

    import_recovery_bundle_with_backend(request, bundle, state_layout, &backend)
}

fn import_recovery_bundle_with_backend<B>(
    request: &RecoveryImportRequest,
    bundle: SeedRecoveryBundleV1,
    state_layout: StateLayout,
    backend: &B,
) -> Result<RecoveryImportResult>
where
    B: SeedBackend,
{
    let target_profile = request
        .profile
        .clone()
        .unwrap_or_else(|| bundle.profile.name.clone());
    validate_profile_name(&target_profile)?;
    ensure_recovery_import_target_available(
        &target_profile,
        &state_layout,
        request.overwrite_existing,
    )?;

    let restored = restore_seed_recovery_bundle(
        backend,
        &SeedRecoveryImportRequest {
            bundle,
            target_profile: Some(target_profile),
            overwrite_existing: request.overwrite_existing,
        },
    )?;
    let mut profile = Profile::new(
        restored.profile.profile.clone(),
        restored.profile.algorithm,
        restored.profile.uses.clone(),
        ModeResolution {
            requested: ModePreference::Seed,
            resolved: Mode::Seed,
            reasons: vec![format!(
                "restored from seed recovery bundle for profile '{}'",
                restored.restored_from_profile
            )],
        },
        state_layout,
    );
    apply_seed_profile_metadata(&mut profile, &restored.profile);
    profile.persist()?;

    Ok(RecoveryImportResult {
        profile,
        restored_from_profile: restored.restored_from_profile,
        seed_bytes: restored.seed_bytes,
    })
}

fn validate_recovery_bundle_input_path(path: &Path) -> Result<()> {
    if path == Path::new("-") {
        return Err(Error::Validation(
            "recovery import requires --bundle to be a file path; stdin is intentionally unsupported for secret-bearing recovery material"
                .to_string(),
        ));
    }

    if path.is_dir() {
        return Err(Error::Validation(format!(
            "recovery import bundle '{}' must be a file path, not a directory",
            path.display()
        )));
    }

    Ok(())
}

fn ensure_recovery_import_target_available(
    target_profile: &str,
    state_layout: &StateLayout,
    overwrite_existing: bool,
) -> Result<()> {
    if overwrite_existing {
        return Ok(());
    }

    let profile_path = state_layout.profile_path(target_profile);
    let object_dir = state_layout.objects_dir.join(target_profile);
    if profile_path.exists() || object_dir.exists() {
        return Err(Error::State(format!(
            "recovery import target '{}' already exists; pass --overwrite-existing to replace the persisted profile and sealed seed state",
            target_profile
        )));
    }

    Ok(())
}

fn apply_prf_root_metadata(profile: &mut Profile, layout: &PrfRootLayout) -> Result<()> {
    profile.metadata.insert(
        PRF_PARENT_CONTEXT_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&profile.storage.state_layout, &layout.parent_context_path)?,
    );
    profile.metadata.insert(
        PRF_PUBLIC_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&profile.storage.state_layout, &layout.public_path)?,
    );
    profile.metadata.insert(
        PRF_PRIVATE_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&profile.storage.state_layout, &layout.private_path)?,
    );
    profile.metadata.insert(
        PRF_CONTEXT_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&profile.storage.state_layout, &layout.loaded_context_path)?,
    );
    Ok(())
}

fn materialize_prf_setup<R>(profile: &mut Profile, runner: &R) -> Result<PrfRootLayout>
where
    R: CommandRunner,
{
    let backend =
        SubprocessPrfBackend::with_runner(profile.storage.state_layout.objects_dir.clone(), runner);
    let layout = backend.provision_root(&profile.name)?;
    apply_prf_root_metadata(profile, &layout)?;
    Ok(layout)
}

fn persistable_state_path(state_layout: &StateLayout, path: &Path) -> Result<String> {
    if path.starts_with(&state_layout.root_dir) {
        let relative = path.strip_prefix(&state_layout.root_dir).map_err(|error| {
            Error::State(format!(
                "failed to persist state path '{}' relative to '{}': {error}",
                path.display(),
                state_layout.root_dir.display()
            ))
        })?;
        return Ok(relative.display().to_string());
    }

    Ok(path.display().to_string())
}

pub fn export(request: &ExportRequest) -> Result<ExportResult> {
    validate_profile_name(&request.profile)?;

    if request.kind != ExportKind::PublicKey && request.public_key_format.is_some() {
        return Err(Error::Validation(
            "--format is supported only with --kind public-key".to_string(),
        ));
    }

    let profile = load_profile(&request.profile, request.state_dir.clone())?;
    match request.kind {
        ExportKind::PublicKey => export_public_key(
            &profile,
            request.output.as_deref(),
            request.public_key_format,
        ),
        ExportKind::RecoveryBundle => export_recovery_bundle(&profile, request),
    }
}

fn export_public_key(
    profile: &Profile,
    requested_output: Option<&Path>,
    requested_format: Option<PublicKeyExportFormat>,
) -> Result<ExportResult> {
    let format = requested_format.unwrap_or(PublicKeyExportFormat::SpkiDer);
    match profile.mode.resolved {
        Mode::Prf => Err(Error::PolicyRefusal(format!(
            "profile '{}' resolved to PRF mode; PRF roots do not expose a standalone public key",
            profile.name
        ))),
        Mode::Native => {
            if !profile.export_policy.public_key_export {
                return Err(Error::PolicyRefusal(format!(
                    "profile '{}' resolved to {:?} mode, which does not allow public-key export",
                    profile.name, profile.mode.resolved
                )));
            }

            export_native_public_key_with_runner(
                profile,
                requested_output,
                format,
                &ProcessCommandRunner,
            )
        }
        Mode::Seed => {
            if !profile.export_policy.public_key_export {
                return Err(Error::PolicyRefusal(format!(
                    "profile '{}' resolved to {:?} mode, which does not allow public-key export",
                    profile.name, profile.mode.resolved
                )));
            }

            let backend =
                SubprocessSeedBackend::new(profile.storage.state_layout.objects_dir.clone());
            let deriver = HkdfSha256SeedDeriver;
            export_seed_public_key_with_backend(
                profile,
                requested_output,
                format,
                &backend,
                &deriver,
            )
        }
    }
}

fn export_recovery_bundle(profile: &Profile, request: &ExportRequest) -> Result<ExportResult> {
    let backend = SubprocessSeedBackend::new(profile.storage.state_layout.objects_dir.clone());
    export_recovery_bundle_with_backend(profile, request, &backend)
}

fn export_recovery_bundle_with_backend<B>(
    profile: &Profile,
    request: &ExportRequest,
    backend: &B,
) -> Result<ExportResult>
where
    B: crate::ops::seed::SeedBackend,
{
    if !profile.export_policy.recovery_export {
        return Err(Error::PolicyRefusal(format!(
            "profile '{}' resolved to {:?} mode, which does not allow recovery-bundle export",
            profile.name, profile.mode.resolved
        )));
    }

    if profile.mode.resolved != Mode::Seed {
        return Err(Error::PolicyRefusal(format!(
            "profile '{}' resolved to {:?} mode; recovery-bundle export is only available for seed-mode profiles",
            profile.name, profile.mode.resolved
        )));
    }

    let destination = resolve_recovery_bundle_output_path(request.output.as_deref())?;
    let seed_profile = seed_profile_from_profile(profile)?;
    let bundle = export_seed_recovery_bundle(
        backend,
        &SeedExportRequest {
            profile: seed_profile,
            auth_source: SeedOpenAuthSource::None,
            destination: SeedExportDestination::ExplicitPath(destination.display().to_string()),
            format: SeedExportFormat::RecoveryBundleV1,
            reason: request.reason.clone().unwrap_or_default(),
            confirm: request.confirm,
            confirm_phrase: request.confirm_phrase.clone(),
        },
    )?;

    let bytes_written = write_recovery_bundle_output(&destination, &bundle)?;

    Ok(ExportResult {
        profile: profile.name.clone(),
        mode: profile.mode.resolved,
        kind: ExportKind::RecoveryBundle,
        artifact: ExportArtifact {
            format: ExportFormat::RecoveryBundleJson,
            path: destination,
            bytes_written,
        },
    })
}

fn export_seed_public_key_with_backend<B, D>(
    profile: &Profile,
    requested_output: Option<&Path>,
    format: PublicKeyExportFormat,
    backend: &B,
    deriver: &D,
) -> Result<ExportResult>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_profile = seed_profile_from_profile(profile)?;
    let derived = open_and_derive(
        backend,
        deriver,
        &SeedOpenRequest {
            profile: seed_profile,
            auth_source: SeedOpenAuthSource::None,
            output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
                spec: seed_public_key_derivation_spec(profile)?,
                output_bytes: 32,
            }),
            require_fresh_unseal: true,
            confirm_software_derivation: true,
        },
    )?;

    let public_key_der = seed_public_key_spki_der(profile, derived.expose_secret())?;
    let rendered_public_key = render_seed_public_key_export(profile, format, &public_key_der)?;
    let destination = resolve_public_key_output_path(profile, requested_output, format)?;
    write_public_key_output(&destination, &rendered_public_key)?;

    Ok(ExportResult {
        profile: profile.name.clone(),
        mode: profile.mode.resolved,
        kind: ExportKind::PublicKey,
        artifact: ExportArtifact {
            format: format.into(),
            path: destination,
            bytes_written: rendered_public_key.len(),
        },
    })
}

fn seed_public_key_derivation_spec(profile: &Profile) -> Result<DerivationSpec> {
    match profile.algorithm {
        Algorithm::Ed25519
            if profile
                .uses
                .iter()
                .any(|use_case| matches!(use_case, UseCase::SshAgent)) =>
        {
            crate::ops::ssh::ssh_ed25519_derivation_spec()
        }
        Algorithm::Ed25519 => seed_software_child_key_spec("ed25519", OutputKind::Ed25519Seed),
        Algorithm::Secp256k1 => {
            seed_software_child_key_spec("secp256k1", OutputKind::Secp256k1Scalar)
        }
        Algorithm::P256 => seed_software_child_key_spec("p256", OutputKind::P256Scalar),
    }
}

fn seed_software_child_key_spec(
    algorithm: &str,
    output_kind: OutputKind,
) -> Result<DerivationSpec> {
    Ok(DerivationSpec::V1(DerivationSpecV1::software_child_key(
        SEED_PUBLIC_KEY_NAMESPACE,
        algorithm,
        SEED_PUBLIC_KEY_PATH,
        output_kind,
    )?))
}

fn seed_public_key_spki_der(profile: &Profile, derived_secret: &[u8]) -> Result<Vec<u8>> {
    match profile.algorithm {
        Algorithm::Ed25519 => seed_ed25519_public_key_spki_der(profile, derived_secret),
        Algorithm::Secp256k1 => seed_secp256k1_public_key_spki_der(profile, derived_secret),
        Algorithm::P256 => seed_p256_public_key_spki_der(profile, derived_secret),
    }
}

fn seed_ed25519_public_key_spki_der(profile: &Profile, derived_secret: &[u8]) -> Result<Vec<u8>> {
    let seed_bytes = seed_secret_bytes(profile, derived_secret)?;
    let signing_key = Ed25519SigningKey::from_bytes(&seed_bytes);
    signing_key
        .verifying_key()
        .to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|error| {
            Error::Internal(format!(
                "failed to encode ed25519 seed public key for profile '{}': {error}",
                profile.name
            ))
        })
}

fn seed_secp256k1_public_key_spki_der(profile: &Profile, derived_secret: &[u8]) -> Result<Vec<u8>> {
    let scalar_bytes = seed_valid_ec_scalar_bytes(profile, derived_secret, |candidate| {
        k256::SecretKey::from_slice(candidate).is_ok()
    })?;
    let secret_key = k256::SecretKey::from_slice(&scalar_bytes).map_err(|error| {
        Error::Internal(format!(
            "failed to materialize secp256k1 seed secret key for profile '{}': {error}",
            profile.name
        ))
    })?;

    secret_key
        .public_key()
        .to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|error| {
            Error::Internal(format!(
                "failed to encode secp256k1 seed public key for profile '{}': {error}",
                profile.name
            ))
        })
}

fn seed_p256_public_key_spki_der(profile: &Profile, derived_secret: &[u8]) -> Result<Vec<u8>> {
    let scalar_bytes = seed_valid_ec_scalar_bytes(profile, derived_secret, |candidate| {
        p256::SecretKey::from_slice(candidate).is_ok()
    })?;
    let secret_key = p256::SecretKey::from_slice(&scalar_bytes).map_err(|error| {
        Error::Internal(format!(
            "failed to materialize p256 seed secret key for profile '{}': {error}",
            profile.name
        ))
    })?;

    secret_key
        .public_key()
        .to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|error| {
            Error::Internal(format!(
                "failed to encode p256 seed public key for profile '{}': {error}",
                profile.name
            ))
        })
}

fn seed_secret_bytes(profile: &Profile, derived_secret: &[u8]) -> Result<[u8; 32]> {
    derived_secret.try_into().map_err(|_| {
        Error::Internal(format!(
            "seed public-key derivation for profile '{}' unexpectedly produced {} bytes instead of 32",
            profile.name,
            derived_secret.len()
        ))
    })
}

fn seed_valid_ec_scalar_bytes<F>(
    profile: &Profile,
    derived_secret: &[u8],
    is_valid: F,
) -> Result<[u8; 32]>
where
    F: Fn(&[u8]) -> bool,
{
    let seed_bytes = seed_secret_bytes(profile, derived_secret)?;
    if is_valid(&seed_bytes) {
        return Ok(seed_bytes);
    }

    for counter in 1..=SEED_SCALAR_RETRY_LIMIT {
        let candidate = seed_scalar_retry_bytes(&seed_bytes, profile.algorithm, counter);
        if is_valid(&candidate) {
            return Ok(candidate);
        }
    }

    Err(Error::Internal(format!(
        "seed public-key derivation could not produce a valid {:?} scalar for profile '{}' after {} retries",
        profile.algorithm, profile.name, SEED_SCALAR_RETRY_LIMIT
    )))
}

fn seed_scalar_retry_bytes(seed_bytes: &[u8; 32], algorithm: Algorithm, counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEED_SCALAR_RETRY_DOMAIN);
    hasher.update(match algorithm {
        Algorithm::Ed25519 => b"ed25519".as_slice(),
        Algorithm::Secp256k1 => b"secp256k1".as_slice(),
        Algorithm::P256 => b"p256".as_slice(),
    });
    hasher.update(counter.to_be_bytes());
    hasher.update(seed_bytes);
    hasher.finalize().into()
}

/// Standalone EC scalar validation that doesn't require a `Profile` reference.
/// Used by the CLI seed sign/verify paths.
pub fn seed_valid_ec_scalar_bytes_standalone(
    derived_secret: &[u8],
    algorithm: Algorithm,
) -> Result<[u8; 32]> {
    let seed_bytes: [u8; 32] = derived_secret.try_into().map_err(|_| {
        Error::Internal(format!(
            "seed derivation unexpectedly produced {} bytes instead of 32",
            derived_secret.len()
        ))
    })?;

    let is_valid: Box<dyn Fn(&[u8]) -> bool> = match algorithm {
        Algorithm::P256 => {
            Box::new(|candidate: &[u8]| p256::SecretKey::from_slice(candidate).is_ok())
        }
        Algorithm::Secp256k1 => {
            Box::new(|candidate: &[u8]| k256::SecretKey::from_slice(candidate).is_ok())
        }
        Algorithm::Ed25519 => return Ok(seed_bytes),
    };

    if is_valid(&seed_bytes) {
        return Ok(seed_bytes);
    }

    for counter in 1..=SEED_SCALAR_RETRY_LIMIT {
        let candidate = seed_scalar_retry_bytes(&seed_bytes, algorithm, counter);
        if is_valid(&candidate) {
            return Ok(candidate);
        }
    }

    Err(Error::Internal(format!(
        "seed derivation could not produce a valid {algorithm:?} scalar after {SEED_SCALAR_RETRY_LIMIT} retries"
    )))
}

fn materialize_native_setup<R>(profile: &mut Profile, runner: &R) -> Result<()>
where
    R: CommandRunner,
{
    if profile.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native setup is currently wired only for P-256 profiles, got {:?}",
            profile.algorithm
        )));
    }

    let allowed_uses = native_key_uses(profile)?;
    let key_id = native_key_id(profile);
    let native_dir = native_state_dir(profile);
    let scratch_dir = native_dir.join("setup-work");
    let handle_path = native_handle_path(profile);
    let persistent_handle = allocate_native_persistent_handle(runner)?;

    profile.storage.state_layout.ensure_dirs()?;
    fs::create_dir_all(&native_dir).map_err(|error| {
        Error::State(format!(
            "failed to create native setup directory '{}': {error}",
            native_dir.display()
        ))
    })?;

    if scratch_dir.exists() {
        remove_path_if_present(&scratch_dir);
    }
    fs::create_dir_all(&scratch_dir).map_err(|error| {
        Error::State(format!(
            "failed to create native scratch directory '{}': {error}",
            scratch_dir.display()
        ))
    })?;

    let setup_request = NativeSetupRequest {
        profile: profile.name.clone(),
        key_label: Some(profile.name.clone()),
        algorithm: NativeAlgorithm::P256,
        curve: NativeCurve::NistP256,
        allowed_uses,
        hardware_binding: NativeHardwareBinding::Required,
        private_key_policy: NativePrivateKeyPolicy::NonExportable,
    };
    let plan = plan_setup(
        &setup_request,
        &NativeSetupArtifacts {
            scratch_dir: scratch_dir.clone(),
            key_id: key_id.clone(),
            persistent: NativePersistentHandle {
                handle: persistent_handle.clone(),
                serialized_handle_path: handle_path.clone(),
            },
        },
    )?;

    let execution = plan
        .commands
        .iter()
        .try_for_each(|command| run_native_command_for_operation(command, runner, "native setup"));

    for path in &plan.cleanup_paths {
        remove_path_if_present(path);
    }
    remove_path_if_present(&scratch_dir);

    execution?;

    if !handle_path.is_file() {
        return Err(Error::State(format!(
            "native setup completed without creating serialized handle state '{}'; sign/export cannot locate the TPM object",
            handle_path.display()
        )));
    }

    persist_native_metadata(profile, &key_id, &persistent_handle, &handle_path);
    Ok(())
}

fn export_native_public_key_with_runner<R>(
    profile: &Profile,
    requested_output: Option<&Path>,
    format: PublicKeyExportFormat,
    runner: &R,
) -> Result<ExportResult>
where
    R: CommandRunner,
{
    if profile.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native public-key export is currently wired only for P-256 profiles, got {:?}",
            profile.algorithm
        )));
    }

    profile.storage.state_layout.ensure_dirs()?;

    let locator = resolve_native_key_locator(profile)?;
    let tempdir = TempfileBuilder::new()
        .prefix("native-public-key-export-")
        .tempdir_in(&profile.storage.state_layout.exports_dir)
        .map_err(|error| {
            Error::State(format!(
                "failed to create native export workspace in '{}': {error}",
                profile.storage.state_layout.exports_dir.display()
            ))
        })?;

    let requested_encoding = native_public_key_encoding(format);
    let plan = plan_export_public_key(
        &NativePublicKeyExportRequest {
            key: NativeKeyRef {
                profile: profile.name.clone(),
                key_id: native_key_id(profile),
            },
            encodings: vec![requested_encoding],
        },
        &NativePublicKeyExportOptions {
            locator,
            output_dir: tempdir.path().to_path_buf(),
            file_stem: profile.name.clone(),
        },
    )?;

    for command in &plan.commands {
        run_native_command_for_operation(command, runner, "native public-key export")?;
    }

    let exported = plan
        .outputs
        .iter()
        .find(|output| output.encoding == requested_encoding)
        .ok_or_else(|| {
            Error::Internal(format!(
                "native public-key export plan did not produce the expected {:?} artifact",
                requested_encoding
            ))
        })?;

    let exported_bytes = fs::read(&exported.path).map_err(|error| {
        Error::State(format!(
            "failed to read native public key from '{}': {error}",
            exported.path.display()
        ))
    })?;
    let rendered_public_key = render_native_public_key_export(profile, format, &exported_bytes)?;

    let destination = resolve_public_key_output_path(profile, requested_output, format)?;
    write_public_key_output(&destination, &rendered_public_key)?;

    Ok(ExportResult {
        profile: profile.name.clone(),
        mode: profile.mode.resolved,
        kind: ExportKind::PublicKey,
        artifact: ExportArtifact {
            format: format.into(),
            path: destination,
            bytes_written: rendered_public_key.len(),
        },
    })
}

const TPM_PERSISTENT_HANDLE_MIN: u32 = 0x8100_0000;
const TPM_PERSISTENT_HANDLE_MAX: u32 = 0x81ff_ffff;
const TPM_PERSISTENT_HANDLE_START: u32 = 0x8101_0000;

pub(crate) fn resolve_native_key_locator(profile: &Profile) -> Result<NativeKeyLocator> {
    if let Some(path) = metadata_path(
        profile,
        &[
            "native.serialized_handle_path",
            "native.serialized-handle-path",
        ],
    ) {
        return Ok(NativeKeyLocator::SerializedHandle { path });
    }

    if let Some(handle) = metadata_value(
        profile,
        &["native.persistent_handle", "native.persistent-handle"],
    ) {
        return Ok(NativeKeyLocator::PersistentHandle { handle });
    }

    for path in native_handle_path_candidates(profile) {
        if path.is_file() {
            return Ok(NativeKeyLocator::SerializedHandle { path });
        }
    }

    Err(Error::State(format!(
        "profile '{}' resolved to native mode but no serialized handle state was found; checked {}",
        profile.name,
        native_handle_path_candidates(profile)
            .into_iter()
            .map(|path| format!("'{}'", path.display()))
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn native_key_uses(profile: &Profile) -> Result<Vec<NativeKeyUse>> {
    let uses: Vec<_> = profile
        .uses
        .iter()
        .map(|use_case| match use_case {
            UseCase::Sign => Ok(NativeKeyUse::Sign),
            UseCase::Verify => Ok(NativeKeyUse::Verify),
            unsupported => Err(Error::Unsupported(format!(
                "native setup is currently wired only for sign/verify uses, but profile '{}' requested {:?}",
                profile.name, unsupported
            ))),
        })
        .collect::<Result<_>>()?;

    if uses.is_empty() {
        return Err(Error::Validation(
            "native setup requires at least one sign/verify use".to_string(),
        ));
    }

    Ok(uses)
}

fn allocate_native_persistent_handle<R>(runner: &R) -> Result<String>
where
    R: CommandRunner,
{
    let output = runner.run(&crate::backend::CommandInvocation::new(
        "tpm2_getcap",
        ["handles-persistent"],
    ));

    if output.error.is_some() {
        return Err(Error::TpmUnavailable(format!(
            "failed to discover TPM persistent handles via 'tpm2_getcap handles-persistent': {}",
            render_command_detail(&output)
        )));
    }

    if output.exit_code != Some(0) {
        return Err(Error::CapabilityMismatch(format!(
            "failed to discover TPM persistent handles via 'tpm2_getcap handles-persistent': {}",
            render_command_detail(&output)
        )));
    }

    let taken = parse_persistent_handles(&output.stdout)?;
    for candidate in TPM_PERSISTENT_HANDLE_START..=TPM_PERSISTENT_HANDLE_MAX {
        let handle = format!("0x{candidate:08x}");
        if !taken.contains(&handle) {
            return Ok(handle);
        }
    }

    Err(Error::State(
        "no free TPM persistent handles remain in the persistent-object range".to_string(),
    ))
}

fn parse_persistent_handles(stdout: &str) -> Result<BTreeSet<String>> {
    let mut handles = BTreeSet::new();

    for line in stdout.lines() {
        for token in
            line.split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | '[' | ']' | ':' | '-'))
        {
            let token = token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | ','));
            if let Some(handle) = parse_persistent_handle_token(token)? {
                handles.insert(handle);
            }
        }
    }

    Ok(handles)
}

fn parse_persistent_handle_token(token: &str) -> Result<Option<String>> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let normalized = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if normalized.len() != 8 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(None);
    }

    let value = u32::from_str_radix(normalized, 16).map_err(|error| {
        Error::State(format!(
            "failed to parse persistent handle token '{trimmed}': {error}"
        ))
    })?;
    if !(TPM_PERSISTENT_HANDLE_MIN..=TPM_PERSISTENT_HANDLE_MAX).contains(&value) {
        return Ok(None);
    }

    Ok(Some(format!("0x{value:08x}")))
}

fn persist_native_metadata(
    profile: &mut Profile,
    key_id: &str,
    persistent_handle: &str,
    handle_path: &Path,
) {
    profile
        .metadata
        .insert("native.backend".to_string(), "subprocess".to_string());
    profile
        .metadata
        .insert("native.key_id".to_string(), key_id.to_string());
    profile.metadata.insert(
        "native.locator_kind".to_string(),
        "serialized-handle".to_string(),
    );
    profile.metadata.insert(
        "native.serialized_handle_path".to_string(),
        path_for_metadata(&profile.storage.state_layout.root_dir, handle_path),
    );
    profile.metadata.insert(
        "native.persistent_handle".to_string(),
        persistent_handle.to_string(),
    );
}

fn path_for_metadata(root_dir: &Path, path: &Path) -> String {
    path.strip_prefix(root_dir)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn native_state_dir(profile: &Profile) -> PathBuf {
    profile
        .storage
        .state_layout
        .objects_dir
        .join(&profile.name)
        .join("native")
}

fn native_handle_path(profile: &Profile) -> PathBuf {
    native_state_dir(profile).join(format!("{}.handle", native_key_id(profile)))
}

pub(crate) fn metadata_path(profile: &Profile, keys: &[&str]) -> Option<PathBuf> {
    let value = metadata_value(profile, keys)?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(profile.storage.state_layout.root_dir.join(path))
    }
}

pub(crate) fn metadata_value(profile: &Profile, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| profile.metadata.get(*key).cloned())
}

pub(crate) fn native_handle_path_candidates(profile: &Profile) -> Vec<PathBuf> {
    let objects_dir = &profile.storage.state_layout.objects_dir;
    vec![
        native_handle_path(profile),
        objects_dir.join(format!("{}.handle", profile.name)),
        objects_dir
            .join(&profile.name)
            .join(format!("{}.handle", profile.name)),
        objects_dir.join(&profile.name).join("key.handle"),
        objects_dir.join(&profile.name).join("persistent.handle"),
    ]
}

pub(crate) fn native_key_id(profile: &Profile) -> String {
    metadata_value(profile, &["native.key_id", "native.key-id"])
        .unwrap_or_else(|| format!("{}-signing-key", profile.name))
}

fn resolve_public_key_output_path(
    profile: &Profile,
    requested_output: Option<&Path>,
    format: PublicKeyExportFormat,
) -> Result<PathBuf> {
    match requested_output {
        Some(path) if path.is_dir() => Err(Error::Validation(format!(
            "export output '{}' must be a file path, not a directory",
            path.display()
        ))),
        Some(path) => Ok(path.to_path_buf()),
        None => Ok(profile.storage.state_layout.exports_dir.join(format!(
            "{}.{}",
            profile.name,
            public_key_export_default_suffix(format)
        ))),
    }
}

fn native_public_key_encoding(format: PublicKeyExportFormat) -> NativePublicKeyEncoding {
    match format {
        PublicKeyExportFormat::SpkiDer => NativePublicKeyEncoding::SpkiDer,
        PublicKeyExportFormat::SpkiPem => NativePublicKeyEncoding::Pem,
        PublicKeyExportFormat::SpkiHex | PublicKeyExportFormat::Openssh => {
            NativePublicKeyEncoding::SpkiDer
        }
    }
}

fn render_native_public_key_export(
    profile: &Profile,
    format: PublicKeyExportFormat,
    exported_bytes: &[u8],
) -> Result<Vec<u8>> {
    match format {
        PublicKeyExportFormat::SpkiDer | PublicKeyExportFormat::SpkiPem => {
            Ok(exported_bytes.to_vec())
        }
        PublicKeyExportFormat::SpkiHex => Ok(hex_encode(exported_bytes).into_bytes()),
        PublicKeyExportFormat::Openssh => {
            render_openssh_public_key(profile, exported_bytes).map(String::into_bytes)
        }
    }
}

fn render_seed_public_key_export(
    profile: &Profile,
    format: PublicKeyExportFormat,
    spki_der: &[u8],
) -> Result<Vec<u8>> {
    match format {
        PublicKeyExportFormat::SpkiDer => Ok(spki_der.to_vec()),
        PublicKeyExportFormat::SpkiPem => Ok(spki_der_to_pem(spki_der).into_bytes()),
        PublicKeyExportFormat::SpkiHex => Ok(hex_encode(spki_der).into_bytes()),
        PublicKeyExportFormat::Openssh => match profile.algorithm {
            Algorithm::P256 => render_openssh_public_key(profile, spki_der).map(String::into_bytes),
            Algorithm::Ed25519 | Algorithm::Secp256k1 => Err(Error::Unsupported(format!(
                "OpenSSH public-key export is not wired for seed {:?} profiles yet",
                profile.algorithm
            ))),
        },
    }
}

fn spki_der_to_pem(spki_der: &[u8]) -> String {
    let base64 = base64_encode(spki_der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        output.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

fn render_openssh_public_key(profile: &Profile, spki_der: &[u8]) -> Result<String> {
    let sec1 = crate::ops::native::subprocess::extract_p256_sec1_from_spki_der(spki_der)?;
    let key_data = SshKeyData::Ecdsa(SshEcdsaPublicKey::from_sec1_bytes(&sec1).map_err(
        |error| {
            Error::State(format!(
                "failed to convert exported SPKI DER into an OpenSSH ECDSA public key for profile '{}': {error}",
                profile.name
            ))
        },
    )?);
    let public_key = SshPublicKey::new(key_data, profile.name.clone());

    public_key.to_openssh().map_err(|error| {
        Error::State(format!(
            "failed to render OpenSSH public key for profile '{}': {error}",
            profile.name
        ))
    })
}

fn public_key_export_default_suffix(format: PublicKeyExportFormat) -> &'static str {
    match format {
        PublicKeyExportFormat::SpkiDer => "public-key.spki.der",
        PublicKeyExportFormat::SpkiPem => "public-key.spki.pem",
        PublicKeyExportFormat::SpkiHex => "public-key.spki.hex",
        PublicKeyExportFormat::Openssh => "public-key.openssh.pub",
    }
}

fn resolve_recovery_bundle_output_path(requested_output: Option<&Path>) -> Result<PathBuf> {
    let path = requested_output.ok_or_else(|| {
        Error::Validation(
            "recovery-bundle export requires --output so the operator chooses an explicit destination"
                .to_string(),
        )
    })?;

    if path.is_dir() {
        return Err(Error::Validation(format!(
            "export output '{}' must be a file path, not a directory",
            path.display()
        )));
    }

    if path == Path::new("-") {
        return Err(Error::Validation(
            "recovery-bundle export may not write to stdout; choose an explicit file path"
                .to_string(),
        ));
    }

    Ok(path.to_path_buf())
}

fn write_public_key_output(path: &Path, public_key: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            Error::State(format!(
                "failed to create export directory '{}': {error}",
                parent.display()
            ))
        })?;
    }

    fs::write(path, public_key).map_err(|error| {
        Error::State(format!(
            "failed to write public key export to '{}': {error}",
            path.display()
        ))
    })?;

    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        Error::State(format!(
            "failed to set permissions on '{}': {error}",
            path.display()
        ))
    })?;

    Ok(())
}

fn write_recovery_bundle_output(path: &Path, bundle: &SeedRecoveryBundleV1) -> Result<usize> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            Error::State(format!(
                "failed to create export directory '{}': {error}",
                parent.display()
            ))
        })?;
    }

    let payload = format!(
        "{}\n",
        serde_json::to_string_pretty(bundle).map_err(crate::error::Error::from)?
    );
    fs::write(path, payload.as_bytes()).map_err(|error| {
        Error::State(format!(
            "failed to write recovery-bundle export to '{}': {error}",
            path.display()
        ))
    })?;

    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        Error::State(format!(
            "failed to set permissions on '{}': {error}",
            path.display()
        ))
    })?;

    Ok(payload.len())
}

fn remove_path_if_present(path: &Path) {
    if path.is_dir() {
        let _ = fs::remove_dir_all(path);
    } else if path.exists() {
        let _ = fs::remove_file(path);
    }
}

fn run_native_command_for_operation<R>(
    command: &NativeCommandSpec,
    runner: &R,
    operation: &str,
) -> Result<()>
where
    R: CommandRunner,
{
    let output = runner.run(&crate::backend::CommandInvocation::new(
        &command.program,
        command.args.iter().cloned(),
    ));

    if output.error.is_some() {
        return Err(Error::TpmUnavailable(format!(
            "{operation} failed while running '{} {}': {}",
            command.program,
            command.args.join(" "),
            render_command_detail(&output)
        )));
    }

    if output.exit_code != Some(0) {
        return Err(Error::CapabilityMismatch(format!(
            "{operation} failed while running '{} {}': {}",
            command.program,
            command.args.join(" "),
            render_command_detail(&output)
        )));
    }

    Ok(())
}

fn render_command_detail(output: &CommandOutput) -> String {
    if let Some(error) = output.error.as_deref() {
        return error.to_string();
    }

    let detail = if !output.stderr.trim().is_empty() {
        output.stderr.trim()
    } else {
        output.stdout.trim()
    };

    if detail.is_empty() {
        "command produced no diagnostic output".to_string()
    } else {
        preview(detail)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
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

fn resolve_mode(
    probe: &dyn CapabilityProbe,
    requested_mode: crate::model::ModePreference,
    algorithm: Algorithm,
    uses: &[UseCase],
    report: &CapabilityReport,
) -> Result<Mode> {
    match requested_mode.explicit() {
        Some(mode) if probe.supports_mode(algorithm, uses, mode) => Ok(mode),
        Some(mode) => Err(Error::CapabilityMismatch(mode_rejection_reason(
            report, algorithm, uses, mode,
        ))),
        None => report.recommended_mode.ok_or_else(|| {
            let reasons = [Mode::Native, Mode::Prf, Mode::Seed]
                .into_iter()
                .map(|mode| mode_rejection_reason(report, algorithm, uses, mode))
                .collect::<Vec<_>>()
                .join("; ");
            Error::CapabilityMismatch(format!(
                "no single mode can satisfy {uses:?} for {algorithm:?}: {reasons}"
            ))
        }),
    }
}

fn validate_profile_name(profile: &str) -> Result<()> {
    if profile.trim().is_empty() {
        return Err(Error::Validation(
            "profile name must not be empty".to_string(),
        ));
    }

    if !profile
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(Error::Validation(
            "profile name may contain only ASCII letters, numbers, '.', '-', and '_'".to_string(),
        ));
    }

    if profile.contains("..") {
        return Err(Error::Validation(
            "profile name must not contain '..'".to_string(),
        ));
    }

    Ok(())
}

fn normalize_uses(mut uses: Vec<UseCase>) -> Vec<UseCase> {
    uses.sort();
    uses.dedup();
    uses
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::env;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use secrecy::ExposeSecret;
    use ssh_key::PublicKey as SshPublicKey;

    use crate::backend::{
        CapabilityProbe, CommandInvocation, CommandOutput, CommandRunner, HeuristicProbe,
    };
    use crate::model::{Diagnostic, ModePreference, NativeCapabilitySummary, TpmStatus};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "tpm2-derive-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn setup_persists_materialized_native_profile_when_not_dry_run() {
        let root_dir = unique_temp_path("setup-persist");
        let runner = FakeNativeSetupRunner::new();
        let request = SetupRequest {
            profile: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Verify, UseCase::Sign],
            requested_mode: ModePreference::Native,
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };

        let result = resolve_profile_with_runner(&HeuristicProbe, &request, &runner)
            .expect("setup should succeed");
        let profile_path = root_dir.join("profiles").join("prod-signer.json");
        let handle_path = root_dir
            .join("objects")
            .join("prod-signer")
            .join("native")
            .join("prod-signer-signing-key.handle");

        assert!(result.persisted);
        assert_eq!(result.profile.storage.profile_path, profile_path);
        assert!(profile_path.is_file());
        assert!(handle_path.is_file());
        assert_eq!(
            result.profile.metadata.get("native.key_id"),
            Some(&"prod-signer-signing-key".to_string())
        );
        assert_eq!(
            result.profile.metadata.get("native.serialized_handle_path"),
            Some(&"objects/prod-signer/native/prod-signer-signing-key.handle".to_string())
        );
        assert_eq!(
            result.profile.metadata.get("native.persistent_handle"),
            Some(&"0x81010002".to_string())
        );
        assert!(
            !root_dir
                .join("objects")
                .join("prod-signer")
                .join("native")
                .join("setup-work")
                .exists()
        );

        let loaded = load_profile("prod-signer", Some(root_dir.clone())).expect("profile loads");
        assert_eq!(loaded, result.profile);
        assert_eq!(runner.calls().len(), 5);

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn setup_dry_run_does_not_touch_state() {
        let root_dir = unique_temp_path("setup-dry-run");
        let runner = FakeNativeSetupRunner::new();
        let request = SetupRequest {
            profile: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign],
            requested_mode: ModePreference::Native,
            state_dir: Some(root_dir.clone()),
            dry_run: true,
        };

        let result = resolve_profile_with_runner(&HeuristicProbe, &request, &runner)
            .expect("setup should succeed");

        assert!(!result.persisted);
        assert!(!root_dir.exists());
        assert!(runner.calls().is_empty());

        if root_dir.exists() {
            fs::remove_dir_all(root_dir).expect("temporary dry-run state should be removed");
        }
    }

    #[test]
    fn setup_prf_provisions_root_material_and_persists_relative_metadata() {
        let root_dir = unique_temp_path("setup-prf-provision");
        let request = SetupRequest {
            profile: "prf-default".to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Derive],
            requested_mode: ModePreference::Prf,
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };
        let probe = StaticCapabilityProbe::prf();
        let runner = FakePrfSetupRunner::default();

        let result = resolve_profile_with_runner(&probe, &request, &runner)
            .expect("PRF setup should succeed");
        let object_dir = root_dir.join("objects").join("prf-default");

        assert!(result.persisted);
        assert!(object_dir.join("parent.ctx").is_file());
        assert!(object_dir.join("prf-root.pub").is_file());
        assert!(object_dir.join("prf-root.priv").is_file());
        assert!(object_dir.join("prf-root.ctx").is_file());
        assert_eq!(
            result
                .profile
                .metadata
                .get(PRF_PARENT_CONTEXT_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/parent.ctx")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(PRF_PUBLIC_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/prf-root.pub")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(PRF_PRIVATE_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/prf-root.priv")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(PRF_CONTEXT_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/prf-root.ctx")
        );

        let loaded = load_profile("prf-default", Some(root_dir.clone())).expect("profile loads");
        assert_eq!(loaded.metadata, result.profile.metadata);
        assert_eq!(
            runner.recorded_programs(),
            vec!["tpm2_createprimary", "tpm2_create", "tpm2_load"]
        );

        fs::remove_dir_all(root_dir).expect("temporary prf setup state should be removed");
    }

    #[test]
    fn setup_seed_persists_relative_metadata_and_records_backend_request() {
        let root_dir = unique_temp_path("setup-seed-provision");
        let request = SetupRequest {
            profile: "seed-default".to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Derive, UseCase::SshAgent],
            requested_mode: ModePreference::Seed,
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };
        let probe = StaticCapabilityProbe::seed();
        let backend = RecordingSeedSetupBackend::new(root_dir.join("objects"));

        let result = resolve_profile_with_seed_backend(&probe, &request, &backend)
            .expect("seed setup should succeed");
        let object_dir = root_dir.join("objects").join("seed-default");

        assert!(result.persisted);
        assert!(object_dir.join("sealed.pub").is_file());
        assert!(object_dir.join("sealed.priv").is_file());
        assert_eq!(
            result
                .profile
                .metadata
                .get(SEED_OBJECT_LABEL_METADATA_KEY)
                .map(String::as_str),
            Some("seed-default")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(SEED_PUBLIC_BLOB_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/seed-default/sealed.pub")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(SEED_PRIVATE_BLOB_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/seed-default/sealed.priv")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(SEED_STORAGE_KIND_METADATA_KEY)
                .map(String::as_str),
            Some("tpm-sealed")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(SEED_DERIVATION_KDF_METADATA_KEY)
                .map(String::as_str),
            Some("hkdf-sha256-v1")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(SEED_DERIVATION_DOMAIN_LABEL_METADATA_KEY)
                .map(String::as_str),
            Some("tpm2-derive.seed.software-derived")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(SEED_SOFTWARE_DERIVED_AT_USE_TIME_METADATA_KEY)
                .map(String::as_str),
            Some("true")
        );

        let loaded = load_profile("seed-default", Some(root_dir.clone())).expect("profile loads");
        assert_eq!(loaded.metadata, result.profile.metadata);
        assert_eq!(
            backend.calls(),
            vec![SeedSealCall {
                object_label: "seed-default".to_string(),
                bytes: DEFAULT_SETUP_SEED_BYTES,
            }]
        );

        fs::remove_dir_all(root_dir).expect("temporary seed setup state should be removed");
    }

    #[test]
    fn export_loads_profile_and_writes_native_public_key() {
        let root_dir = unique_temp_path("export-native-public-key");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let mut profile = Profile {
            schema_version: crate::model::PROFILE_SCHEMA_VERSION,
            name: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign, UseCase::Verify],
            mode: ModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            storage: crate::model::ProfileStorage {
                state_layout: state_layout.clone(),
                profile_path: state_layout.profile_path("prod-signer"),
                root_material_kind: crate::model::RootMaterialKind::NativeObject,
            },
            export_policy: crate::model::ExportPolicy::for_mode(Mode::Native),
            metadata: BTreeMap::new(),
        };

        let handle_path = state_layout
            .objects_dir
            .join("prod-signer")
            .join("native")
            .join("prod-signer-signing-key.handle");
        fs::create_dir_all(handle_path.parent().expect("handle parent")).expect("handle dir");
        fs::write(&handle_path, b"serialized-handle").expect("handle file");
        persist_native_metadata(
            &mut profile,
            "prod-signer-signing-key",
            "0x81010002",
            &handle_path,
        );
        profile.persist().expect("persist profile");

        let output_path = root_dir.join("custom").join("prod-signer.der");
        let result = export_native_public_key_with_runner(
            &profile,
            Some(output_path.as_path()),
            PublicKeyExportFormat::SpkiDer,
            &FakeNativeExportRunner::success(example_spki_der()),
        )
        .expect("native export should succeed");

        assert_eq!(result.profile, "prod-signer");
        assert_eq!(result.mode, Mode::Native);
        assert_eq!(result.kind, ExportKind::PublicKey);
        assert_eq!(result.artifact.format, ExportFormat::SpkiDer);
        assert_eq!(result.artifact.path, output_path);
        assert_eq!(
            fs::read(&result.artifact.path).expect("export output"),
            example_spki_der()
        );

        fs::remove_dir_all(root_dir).expect("temporary native export state should be removed");
    }

    #[test]
    fn export_writes_seed_ed25519_public_key_for_ssh_profile() {
        let root_dir = unique_temp_path("export-seed-ed25519-public-key");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let profile = Profile::new(
            "seed-ed25519".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::SshAgent],
            ModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout,
        );
        let seed = vec![0x11; 32];
        let output_path = root_dir.join("exports").join("seed-ed25519.der");

        let result = export_seed_public_key_with_backend(
            &profile,
            Some(output_path.as_path()),
            PublicKeyExportFormat::SpkiDer,
            &FakeSeedExportBackend::new(seed.clone()),
            &HkdfSha256SeedDeriver,
        )
        .expect("seed ed25519 export should succeed");

        let expected = expected_seed_public_key_der(
            &seed,
            crate::ops::ssh::ssh_ed25519_derivation_spec().expect("ssh ed25519 spec"),
            Algorithm::Ed25519,
        );

        assert_eq!(result.profile, "seed-ed25519");
        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.kind, ExportKind::PublicKey);
        assert_eq!(result.artifact.format, ExportFormat::SpkiDer);
        assert_eq!(
            fs::read(&result.artifact.path).expect("ed25519 export output"),
            expected
        );

        fs::remove_dir_all(root_dir).expect("temporary ed25519 export state should be removed");
    }

    #[test]
    fn export_writes_seed_secp256k1_public_key() {
        let root_dir = unique_temp_path("export-seed-secp256k1-public-key");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let profile = Profile::new(
            "seed-secp256k1".to_string(),
            Algorithm::Secp256k1,
            vec![UseCase::Derive],
            ModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout,
        );
        let seed = vec![0x22; 32];
        let output_path = root_dir.join("exports").join("seed-secp256k1.der");

        let result = export_seed_public_key_with_backend(
            &profile,
            Some(output_path.as_path()),
            PublicKeyExportFormat::SpkiDer,
            &FakeSeedExportBackend::new(seed.clone()),
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secp256k1 export should succeed");

        let expected = expected_seed_public_key_der(
            &seed,
            seed_public_key_derivation_spec(&profile).expect("secp256k1 export spec"),
            Algorithm::Secp256k1,
        );

        assert_eq!(result.artifact.format, ExportFormat::SpkiDer);
        assert_eq!(
            fs::read(&result.artifact.path).expect("secp256k1 export output"),
            expected
        );

        fs::remove_dir_all(root_dir).expect("temporary secp256k1 export state should be removed");
    }

    #[test]
    fn export_writes_seed_p256_public_key_without_touching_native_path() {
        let root_dir = unique_temp_path("export-seed-p256-public-key");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let profile = Profile::new(
            "seed-p256".to_string(),
            Algorithm::P256,
            vec![UseCase::Derive],
            ModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout,
        );
        let seed = vec![0x33; 32];
        let output_path = root_dir.join("exports").join("seed-p256.der");

        let result = export_seed_public_key_with_backend(
            &profile,
            Some(output_path.as_path()),
            PublicKeyExportFormat::SpkiDer,
            &FakeSeedExportBackend::new(seed.clone()),
            &HkdfSha256SeedDeriver,
        )
        .expect("seed p256 export should succeed");

        let expected = expected_seed_public_key_der(
            &seed,
            seed_public_key_derivation_spec(&profile).expect("p256 export spec"),
            Algorithm::P256,
        );

        assert_eq!(result.artifact.format, ExportFormat::SpkiDer);
        assert_eq!(
            fs::read(&result.artifact.path).expect("p256 export output"),
            expected
        );

        fs::remove_dir_all(root_dir).expect("temporary p256 export state should be removed");
    }

    #[test]
    fn export_native_public_key_supports_spki_pem_output() {
        let root_dir = unique_temp_path("export-native-public-key-pem");
        let (profile, _) = persisted_native_export_profile(&root_dir);

        let output_path = root_dir.join("custom").join("prod-signer.pem");
        let result = export_native_public_key_with_runner(
            &profile,
            Some(output_path.as_path()),
            PublicKeyExportFormat::SpkiPem,
            &FakeNativeExportRunner::success(example_spki_der()),
        )
        .expect("native pem export should succeed");

        assert_eq!(result.artifact.format, ExportFormat::SpkiPem);
        let exported = fs::read_to_string(&result.artifact.path).expect("pem output");
        assert!(exported.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(exported.ends_with("-----END PUBLIC KEY-----\n"));

        fs::remove_dir_all(root_dir).expect("temporary native export state should be removed");
    }

    #[test]
    fn export_native_public_key_supports_spki_hex_output() {
        let root_dir = unique_temp_path("export-native-public-key-hex");
        let (profile, _) = persisted_native_export_profile(&root_dir);

        let output_path = root_dir.join("custom").join("prod-signer.hex");
        let result = export_native_public_key_with_runner(
            &profile,
            Some(output_path.as_path()),
            PublicKeyExportFormat::SpkiHex,
            &FakeNativeExportRunner::success(example_spki_der()),
        )
        .expect("native hex export should succeed");

        assert_eq!(result.artifact.format, ExportFormat::SpkiHex);
        assert_eq!(
            fs::read_to_string(&result.artifact.path).expect("hex output"),
            hex_encode(&example_spki_der())
        );

        fs::remove_dir_all(root_dir).expect("temporary native export state should be removed");
    }

    #[test]
    fn export_native_public_key_supports_openssh_output() {
        let root_dir = unique_temp_path("export-native-public-key-openssh");
        let (profile, _) = persisted_native_export_profile(&root_dir);

        let result = export_native_public_key_with_runner(
            &profile,
            None,
            PublicKeyExportFormat::Openssh,
            &FakeNativeExportRunner::success(example_spki_der()),
        )
        .expect("native openssh export should succeed");

        assert_eq!(result.artifact.format, ExportFormat::Openssh);
        assert_eq!(
            result.artifact.path,
            root_dir
                .join("exports")
                .join("prod-signer.public-key.openssh.pub")
        );

        let exported = fs::read_to_string(&result.artifact.path).expect("openssh output");
        assert!(exported.starts_with("ecdsa-sha2-nistp256 "));
        let parsed = SshPublicKey::from_openssh(&exported).expect("parse openssh public key");
        assert_eq!(parsed.comment(), "prod-signer");

        fs::remove_dir_all(root_dir).expect("temporary native export state should be removed");
    }

    #[test]
    fn export_refuses_prf_public_key_requests_after_loading_profile() {
        let root_dir = unique_temp_path("export-prf-refusal");
        let profile = Profile::new(
            "prf-default".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Derive],
            ModeResolution {
                requested: ModePreference::Prf,
                resolved: Mode::Prf,
                reasons: vec!["prf requested".to_string()],
            },
            StateLayout::new(root_dir.clone()),
        );
        profile.persist().expect("persist profile");

        let error = export(&ExportRequest {
            profile: "prf-default".to_string(),
            kind: ExportKind::PublicKey,
            output: None,
            public_key_format: None,
            state_dir: Some(root_dir.clone()),
            reason: None,
            confirm: false,
            confirm_phrase: None,
        })
        .expect_err("prf export should refuse");

        assert!(matches!(error, Error::PolicyRefusal(message) if message.contains("PRF mode")));

        fs::remove_dir_all(root_dir).expect("temporary prf export state should be removed");
    }

    #[derive(Clone, Default)]
    struct FakeNativeSetupRunner {
        calls: Arc<Mutex<Vec<CommandInvocation>>>,
    }

    impl FakeNativeSetupRunner {
        fn new() -> Self {
            Self::default()
        }

        fn calls(&self) -> Vec<CommandInvocation> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl CommandRunner for FakeNativeSetupRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.calls
                .lock()
                .expect("calls lock")
                .push(invocation.clone());

            match invocation.program.as_str() {
                "tpm2_getcap" => CommandOutput {
                    exit_code: Some(0),
                    stdout: "- 0x81010000\n- 0x81010001\n".to_string(),
                    stderr: String::new(),
                    error: None,
                },
                "tpm2_createprimary" => {
                    write_output_flag(invocation, "-c", b"primary-context");
                    success_output()
                }
                "tpm2_create" => {
                    write_output_flag(invocation, "-u", b"public-blob");
                    write_output_flag(invocation, "-r", b"private-blob");
                    success_output()
                }
                "tpm2_load" => {
                    write_output_flag(invocation, "-c", b"loaded-context");
                    write_output_flag(invocation, "-n", b"object-name");
                    success_output()
                }
                "tpm2_evictcontrol" => {
                    write_output_flag(invocation, "-o", b"serialized-handle");
                    success_output()
                }
                other => panic!("unexpected command {other}"),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct StaticCapabilityProbe {
        report: CapabilityReport,
    }

    impl StaticCapabilityProbe {
        fn prf() -> Self {
            Self {
                report: CapabilityReport {
                    tpm: TpmStatus {
                        present: Some(true),
                        accessible: Some(true),
                    },
                    native: NativeCapabilitySummary {
                        algorithms: Vec::new(),
                    },
                    prf_available: Some(true),
                    seed_available: Some(true),
                    recommended_mode: Some(Mode::Prf),
                    recommendation_reasons: vec!["fake PRF support".to_string()],
                    diagnostics: vec![Diagnostic::info("fake-probe", "PRF is supported")],
                },
            }
        }

        fn seed() -> Self {
            Self {
                report: CapabilityReport {
                    tpm: TpmStatus {
                        present: Some(true),
                        accessible: Some(true),
                    },
                    native: NativeCapabilitySummary {
                        algorithms: Vec::new(),
                    },
                    prf_available: Some(false),
                    seed_available: Some(true),
                    recommended_mode: Some(Mode::Seed),
                    recommendation_reasons: vec!["fake sealed-seed support".to_string()],
                    diagnostics: vec![Diagnostic::info("fake-probe", "seed mode is supported")],
                },
            }
        }
    }

    impl CapabilityProbe for StaticCapabilityProbe {
        fn detect(&self, _algorithm: Option<Algorithm>, _uses: &[UseCase]) -> CapabilityReport {
            self.report.clone()
        }
    }

    #[derive(Clone, Default)]
    struct FakePrfSetupRunner {
        programs: Arc<Mutex<Vec<String>>>,
    }

    impl FakePrfSetupRunner {
        fn recorded_programs(&self) -> Vec<String> {
            self.programs.lock().expect("recorded programs").clone()
        }
    }

    impl CommandRunner for FakePrfSetupRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.programs
                .lock()
                .expect("recorded programs")
                .push(invocation.program.clone());

            match invocation.program.as_str() {
                "tpm2_createprimary" => {
                    fs::write(pathbuf_arg(invocation, "-c"), b"parent-context")
                        .expect("write parent context");
                }
                "tpm2_create" => {
                    fs::write(pathbuf_arg(invocation, "-u"), b"prf-public")
                        .expect("write public blob");
                    fs::write(pathbuf_arg(invocation, "-r"), b"prf-private")
                        .expect("write private blob");
                }
                "tpm2_load" => {
                    fs::write(pathbuf_arg(invocation, "-c"), b"prf-context")
                        .expect("write loaded context");
                }
                other => {
                    return CommandOutput {
                        exit_code: Some(1),
                        stdout: String::new(),
                        stderr: format!("unexpected command: {other}"),
                        error: None,
                    };
                }
            }

            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SeedSealCall {
        object_label: String,
        bytes: usize,
    }

    #[derive(Clone)]
    struct RecordingSeedSetupBackend {
        objects_dir: PathBuf,
        calls: Arc<Mutex<Vec<SeedSealCall>>>,
    }

    impl RecordingSeedSetupBackend {
        fn new(objects_dir: PathBuf) -> Self {
            Self {
                objects_dir,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> Vec<SeedSealCall> {
            self.calls.lock().expect("seed setup calls").clone()
        }
    }

    impl SeedBackend for RecordingSeedSetupBackend {
        fn seal_seed(&self, request: &SeedCreateRequest) -> Result<()> {
            let bytes = match request.source {
                SeedCreateSource::GenerateRandom { bytes } => bytes,
                SeedCreateSource::Import { .. } => {
                    return Err(Error::Validation(
                        "seed setup test backend only supports generated seed material".to_string(),
                    ));
                }
            };

            self.calls
                .lock()
                .expect("seed setup calls")
                .push(SeedSealCall {
                    object_label: request.profile.storage.object_label.clone(),
                    bytes,
                });

            let object_dir = self.objects_dir.join(&request.profile.storage.object_label);
            fs::create_dir_all(&object_dir).map_err(|error| {
                Error::State(format!(
                    "failed to create fake seed object directory '{}': {error}",
                    object_dir.display()
                ))
            })?;
            fs::write(object_dir.join("sealed.pub"), b"seed-public").map_err(|error| {
                Error::State(format!("failed to write fake seed public blob: {error}"))
            })?;
            fs::write(object_dir.join("sealed.priv"), b"seed-private").map_err(|error| {
                Error::State(format!("failed to write fake seed private blob: {error}"))
            })?;

            Ok(())
        }

        fn unseal_seed(
            &self,
            _profile: &SeedProfile,
            _auth_source: &SeedOpenAuthSource,
        ) -> Result<crate::ops::seed::SeedMaterial> {
            unreachable!("seed setup tests do not unseal material")
        }
    }

    fn pathbuf_arg(invocation: &CommandInvocation, flag: &str) -> PathBuf {
        invocation
            .args
            .windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| PathBuf::from(&pair[1]))
            .unwrap_or_else(|| panic!("missing {flag} argument"))
    }

    #[test]
    fn export_writes_seed_recovery_bundle_when_confirmed() {
        let root_dir = unique_temp_path("export-seed-recovery-bundle");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let profile = Profile::new(
            "seed-default".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Derive, UseCase::SshAgent],
            ModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout.clone(),
        );

        let output_path = root_dir.join("backup").join("seed-default.recovery.json");
        let result = export_recovery_bundle_with_backend(
            &profile,
            &ExportRequest {
                profile: profile.name.clone(),
                kind: ExportKind::RecoveryBundle,
                output: Some(output_path.clone()),
                public_key_format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("hardware migration".to_string()),
                confirm: true,
                confirm_phrase: Some(
                    crate::ops::seed::DEFAULT_EXPORT_CONFIRMATION_PHRASE.to_string(),
                ),
            },
            &FakeSeedExportBackend::new(vec![0x7a; 32]),
        )
        .expect("seed recovery export should succeed");

        assert_eq!(result.profile, "seed-default");
        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.kind, ExportKind::RecoveryBundle);
        assert_eq!(result.artifact.format, ExportFormat::RecoveryBundleJson);
        assert_eq!(result.artifact.path, output_path);

        let payload = fs::read_to_string(&result.artifact.path).expect("recovery bundle output");
        assert!(payload.contains("seed-recovery-bundle-v1"));
        assert!(payload.contains("hardware migration"));
        assert!(payload.contains("7a7a7a7a"));

        fs::remove_dir_all(root_dir).expect("temporary recovery export state should be removed");
    }

    #[test]
    fn export_recovery_bundle_requires_explicit_output_path() {
        let root_dir = unique_temp_path("export-seed-recovery-missing-output");
        let profile = Profile::new(
            "seed-default".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Derive],
            ModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            StateLayout::new(root_dir.clone()),
        );

        let error = export_recovery_bundle_with_backend(
            &profile,
            &ExportRequest {
                profile: profile.name.clone(),
                kind: ExportKind::RecoveryBundle,
                output: None,
                public_key_format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("hardware migration".to_string()),
                confirm: true,
                confirm_phrase: Some(
                    crate::ops::seed::DEFAULT_EXPORT_CONFIRMATION_PHRASE.to_string(),
                ),
            },
            &FakeSeedExportBackend::new(vec![0x7a; 32]),
        )
        .expect_err("missing output should fail");

        assert!(
            matches!(error, Error::Validation(message) if message.contains("requires --output"))
        );
    }

    #[test]
    fn recovery_import_requires_overwrite_when_target_profile_state_exists() {
        let root_dir = unique_temp_path("import-seed-recovery-existing-target");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let existing = Profile::new(
            "restored-profile".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Derive],
            ModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout.clone(),
        );
        existing.persist().expect("persist existing profile");

        let seed = vec![0x24; 32];
        let backend = FakeSeedImportBackend::default();
        let error = import_recovery_bundle_with_backend(
            &RecoveryImportRequest {
                bundle_path: root_dir.join("backup").join("seed.recovery.json"),
                profile: Some("restored-profile".to_string()),
                state_dir: Some(root_dir.clone()),
                overwrite_existing: false,
            },
            sample_recovery_bundle("old-profile", &seed),
            state_layout,
            &backend,
        )
        .expect_err("existing target should require overwrite");

        assert!(matches!(error, Error::State(message) if message.contains("--overwrite-existing")));
        assert!(backend.last_request_opt().is_none());

        fs::remove_dir_all(root_dir).expect("temporary import state should be removed");
    }

    #[test]
    fn recovery_import_persists_restored_seed_profile_metadata() {
        let root_dir = unique_temp_path("import-seed-recovery-bundle");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let seed = vec![0x42; 32];
        let bundle = sample_recovery_bundle("old-profile", &seed);
        let backend = FakeSeedImportBackend::default();

        let result = import_recovery_bundle_with_backend(
            &RecoveryImportRequest {
                bundle_path: root_dir.join("backup").join("seed.recovery.json"),
                profile: Some("restored-profile".to_string()),
                state_dir: Some(root_dir.clone()),
                overwrite_existing: true,
            },
            bundle,
            state_layout.clone(),
            &backend,
        )
        .expect("recovery import should succeed");

        assert_eq!(result.profile.name, "restored-profile");
        assert_eq!(result.profile.mode.resolved, Mode::Seed);
        assert_eq!(result.restored_from_profile, "old-profile");
        assert_eq!(result.seed_bytes, seed.len());
        assert_eq!(
            result.profile.metadata.get(SEED_OBJECT_LABEL_METADATA_KEY),
            Some(&"restored-profile".to_string())
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(SEED_PUBLIC_BLOB_PATH_METADATA_KEY),
            Some(&"objects/restored-profile/sealed.pub".to_string())
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(SEED_PRIVATE_BLOB_PATH_METADATA_KEY),
            Some(&"objects/restored-profile/sealed.priv".to_string())
        );

        let persisted = Profile::load_named("restored-profile", Some(root_dir.clone()))
            .expect("persisted restored profile");
        assert_eq!(persisted.mode.resolved, Mode::Seed);
        assert!(
            persisted
                .mode
                .reasons
                .iter()
                .any(|reason| reason.contains("old-profile"))
        );

        let sealed = backend.last_request();
        assert_eq!(sealed.profile_name, "restored-profile");
        assert_eq!(sealed.object_label, "restored-profile");
        assert!(sealed.overwrite_existing);
        assert_eq!(sealed.seed, seed);

        fs::remove_dir_all(root_dir).expect("temporary import state should be removed");
    }

    #[derive(Clone, Default)]
    struct FakeSeedImportBackend {
        last_request: Arc<Mutex<Option<RecordedSeedImport>>>,
    }

    impl FakeSeedImportBackend {
        fn last_request(&self) -> RecordedSeedImport {
            self.last_request
                .lock()
                .expect("last request")
                .clone()
                .expect("recorded seed import")
        }

        fn last_request_opt(&self) -> Option<RecordedSeedImport> {
            self.last_request.lock().expect("last request").clone()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedSeedImport {
        profile_name: String,
        object_label: String,
        overwrite_existing: bool,
        seed: Vec<u8>,
    }

    impl crate::ops::seed::SeedBackend for FakeSeedImportBackend {
        fn seal_seed(&self, request: &crate::ops::seed::SeedCreateRequest) -> Result<()> {
            let seed = match &request.source {
                crate::ops::seed::SeedCreateSource::Import {
                    ingress,
                    material: Some(material),
                } => {
                    assert_eq!(*ingress, crate::ops::seed::SeedImportIngress::InMemory);
                    material.expose_secret().clone()
                }
                other => panic!("expected imported seed source, found {other:?}"),
            };

            self.last_request
                .lock()
                .expect("last request")
                .replace(RecordedSeedImport {
                    profile_name: request.profile.profile.clone(),
                    object_label: request.profile.storage.object_label.clone(),
                    overwrite_existing: request.overwrite_existing,
                    seed,
                });
            Ok(())
        }

        fn unseal_seed(
            &self,
            _profile: &crate::ops::seed::SeedProfile,
            _auth_source: &crate::ops::seed::SeedOpenAuthSource,
        ) -> Result<crate::ops::seed::SeedMaterial> {
            unreachable!("recovery import should only seal imported seeds")
        }
    }

    #[derive(Clone)]
    struct FakeSeedExportBackend {
        seed: Vec<u8>,
    }

    impl FakeSeedExportBackend {
        fn new(seed: Vec<u8>) -> Self {
            Self { seed }
        }
    }

    impl crate::ops::seed::SeedBackend for FakeSeedExportBackend {
        fn seal_seed(&self, _request: &crate::ops::seed::SeedCreateRequest) -> Result<()> {
            unreachable!("seed sealing is not used in recovery export tests")
        }

        fn unseal_seed(
            &self,
            _profile: &crate::ops::seed::SeedProfile,
            _auth_source: &crate::ops::seed::SeedOpenAuthSource,
        ) -> Result<crate::ops::seed::SeedMaterial> {
            Ok(secrecy::SecretBox::new(Box::new(self.seed.clone())))
        }
    }

    fn persisted_native_export_profile(root_dir: &Path) -> (Profile, PathBuf) {
        let state_layout = StateLayout::new(root_dir.to_path_buf());
        state_layout.ensure_dirs().expect("state dirs");

        let mut profile = Profile {
            schema_version: crate::model::PROFILE_SCHEMA_VERSION,
            name: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign, UseCase::Verify],
            mode: ModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            storage: crate::model::ProfileStorage {
                state_layout: state_layout.clone(),
                profile_path: state_layout.profile_path("prod-signer"),
                root_material_kind: crate::model::RootMaterialKind::NativeObject,
            },
            export_policy: crate::model::ExportPolicy::for_mode(Mode::Native),
            metadata: BTreeMap::new(),
        };

        let handle_path = state_layout
            .objects_dir
            .join("prod-signer")
            .join("native")
            .join("prod-signer-signing-key.handle");
        fs::create_dir_all(handle_path.parent().expect("handle parent")).expect("handle dir");
        fs::write(&handle_path, b"serialized-handle").expect("handle file");
        persist_native_metadata(
            &mut profile,
            "prod-signer-signing-key",
            "0x81010002",
            &handle_path,
        );
        profile.persist().expect("persist profile");

        (profile, handle_path)
    }

    #[derive(Clone)]
    struct FakeNativeExportRunner {
        der: Vec<u8>,
    }

    impl FakeNativeExportRunner {
        fn success(der: Vec<u8>) -> Self {
            Self { der }
        }
    }

    impl CommandRunner for FakeNativeExportRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            assert_eq!(invocation.program, "tpm2_readpublic");

            let output_path = invocation
                .args
                .windows(2)
                .find(|pair| pair[0] == "-o")
                .map(|pair| PathBuf::from(&pair[1]))
                .expect("-o output path");
            let output_format = invocation
                .args
                .windows(2)
                .find(|pair| pair[0] == "-f")
                .map(|pair| pair[1].as_str())
                .expect("-f format");
            let bytes = match output_format {
                "der" => self.der.clone(),
                "pem" => example_spki_pem(),
                other => panic!("unexpected export format {other}"),
            };
            fs::write(output_path, bytes).expect("fake public key output");

            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    fn expected_seed_public_key_der(
        seed: &[u8],
        spec: DerivationSpec,
        algorithm: Algorithm,
    ) -> Vec<u8> {
        let derived = HkdfSha256SeedDeriver
            .derive(
                &secrecy::SecretBox::new(Box::new(seed.to_vec())),
                &SoftwareSeedDerivationRequest {
                    spec,
                    output_bytes: 32,
                },
            )
            .expect("seed derivation for expected public key");
        let derived_bytes: [u8; 32] = derived
            .expose_secret()
            .as_slice()
            .try_into()
            .expect("expected 32-byte derived key material");

        match algorithm {
            Algorithm::Ed25519 => Ed25519SigningKey::from_bytes(&derived_bytes)
                .verifying_key()
                .to_public_key_der()
                .expect("ed25519 public key DER")
                .as_bytes()
                .to_vec(),
            Algorithm::Secp256k1 => k256::SecretKey::from_slice(&derived_bytes)
                .expect("valid secp256k1 scalar")
                .public_key()
                .to_public_key_der()
                .expect("secp256k1 public key DER")
                .as_bytes()
                .to_vec(),
            Algorithm::P256 => p256::SecretKey::from_slice(&derived_bytes)
                .expect("valid p256 scalar")
                .public_key()
                .to_public_key_der()
                .expect("p256 public key DER")
                .as_bytes()
                .to_vec(),
        }
    }

    fn sample_recovery_bundle(profile_name: &str, seed: &[u8]) -> SeedRecoveryBundleV1 {
        SeedRecoveryBundleV1 {
            schema_version: crate::ops::seed::SEED_RECOVERY_BUNDLE_SCHEMA_VERSION,
            kind: crate::ops::seed::SEED_RECOVERY_BUNDLE_KIND.to_string(),
            exported_at_unix_seconds: 1,
            reason: "hardware migration".to_string(),
            profile: crate::ops::seed::SeedRecoveryBundleProfile {
                name: profile_name.to_string(),
                algorithm: Algorithm::Ed25519,
                uses: vec![UseCase::Derive, UseCase::SshAgent],
                derivation: crate::ops::seed::SeedDerivation::hkdf_sha256_v1(),
            },
            seed: crate::ops::seed::SeedRecoveryBundleSecret {
                encoding: "hex".to_string(),
                bytes: seed.len(),
                sha256: seed_sha256_hex(seed),
                material: seed_hex_encode(seed),
            },
        }
    }

    fn seed_hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn seed_sha256_hex(bytes: &[u8]) -> String {
        let digest = sha2::Sha256::digest(bytes);
        seed_hex_encode(&digest)
    }

    fn write_output_flag(invocation: &CommandInvocation, flag: &str, bytes: &[u8]) {
        let output_path = invocation
            .args
            .windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| PathBuf::from(&pair[1]))
            .unwrap_or_else(|| panic!("{flag} output path"));
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).expect("output parent dir");
        }
        fs::write(output_path, bytes).expect("fake TPM output");
    }

    fn success_output() -> CommandOutput {
        CommandOutput {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            error: None,
        }
    }

    fn example_spki_der() -> Vec<u8> {
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        der.extend_from_slice(&[0x11; 32]);
        der.extend_from_slice(&[0x22; 32]);
        der
    }

    fn example_spki_pem() -> Vec<u8> {
        let base64 = base64_encode(&example_spki_der());
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in base64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem.into_bytes()
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);

        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

            output.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
            output.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
            if chunk.len() > 1 {
                output.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
            } else {
                output.push('=');
            }
            if chunk.len() > 2 {
                output.push(TABLE[(triple & 0x3f) as usize] as char);
            } else {
                output.push('=');
            }
        }

        output
    }
}
