//! High-level operations root for `tpm2-derive`.
//!
//! This file is the `crate::ops` module root and intentionally coexists with
//! the `src/ops/` directory, which contains its submodules.

pub mod encrypt;
mod enforcement;
pub mod keygen;
pub mod native;
pub mod prf;
pub mod seed;
pub(crate) mod shared;
pub mod sign;
pub mod ssh;
pub mod verify;

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, OnceLock};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey as Ed25519EncodePrivateKey;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use secrecy::ExposeSecret;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use tempfile::Builder as TempfileBuilder;
use zeroize::Zeroizing;

use ssh_key::{
    PublicKey as SshPublicKey,
    public::{EcdsaPublicKey as SshEcdsaPublicKey, KeyData as SshKeyData},
};

use crate::backend::recommend::mode_rejection_reason;
use crate::backend::{CapabilityProbe, CommandOutput, CommandRunner, ProcessCommandRunner};
use crate::crypto::DerivationSpec;
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, CapabilityReport, DerivationOverrides, ExportArtifact, ExportFormat, ExportKind,
    ExportRequest, ExportResult, Format, Identity, IdentityCreateRequest, IdentityCreateResult,
    IdentityDerivationDefaults, IdentityModeResolution, InspectRequest, Mode, StateLayout, UseCase,
    expand_mode_requested_uses,
};
use crate::ops::native::subprocess::{
    NativeCommandSpec, NativeKeyLocator, NativePersistentHandle, NativePublicKeyExportOptions,
    NativeSetupArtifacts, plan_export_public_key, plan_setup,
};
use crate::ops::native::{
    NativeAlgorithm, NativeCurve, NativeHardwareBinding, NativeIdentityCreateRequest, NativeKeyRef,
    NativeKeyUse, NativePrivateKeyPolicy, NativePublicKeyEncoding, NativePublicKeyExportRequest,
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
    SeedCreateRequest, SeedCreateSource, SeedIdentity, SeedOpenAuthSource, SeedOpenOutput,
    SeedOpenRequest, SeedSoftwareDeriver, SeedStorageKind, SoftwareSeedDerivationRequest,
    SubprocessSeedBackend, open_and_derive, seed_profile_from_profile,
};

const DEFAULT_SETUP_SEED_BYTES: usize = MIN_SEED_BYTES;
const SEED_PUBLIC_KEY_NAMESPACE: &str = "tpm2-derive.export";
const SEED_PUBLIC_KEY_PATH: &str = "m/public-key/default";
const SEED_SCALAR_RETRY_DOMAIN: &[u8] = b"tpm2-derive\0seed-scalar-retry\0v1";
const SEED_SCALAR_RETRY_LIMIT: u32 = 16;

pub fn inspect(probe: &dyn CapabilityProbe, request: &InspectRequest) -> CapabilityReport {
    probe.detect(request.algorithm, &normalize_uses(request.uses.clone()))
}

pub fn resolve_identity(
    probe: &dyn CapabilityProbe,
    request: &IdentityCreateRequest,
) -> Result<IdentityCreateResult> {
    resolve_identity_with_runner(probe, request, &ProcessCommandRunner)
}

fn resolve_identity_with_runner<R>(
    probe: &dyn CapabilityProbe,
    request: &IdentityCreateRequest,
    runner: &R,
) -> Result<IdentityCreateResult>
where
    R: CommandRunner,
{
    let mut identity = build_identity_record(probe, request)?;

    let persisted = if request.dry_run {
        false
    } else {
        match identity.mode.resolved {
            Mode::Native => {
                let _setup_guard = acquire_native_setup_lock(&identity);
                ensure_identity_does_not_exist(&identity)?;
                let materialized = materialize_native_setup(&mut identity, runner)?;
                if let Err(error) = identity.persist() {
                    if let Err(rollback_error) =
                        rollback_materialized_native_setup(runner, &materialized)
                    {
                        return Err(Error::State(format!(
                            "failed to persist identity '{}': {error}; additionally failed to roll back native TPM handle '{}': {rollback_error}",
                            identity.name, materialized.persistent_handle
                        )));
                    }
                    return Err(error);
                }
            }
            Mode::Prf => {
                let layout = materialize_prf_setup(&mut identity, runner)?;
                if let Err(error) = identity.persist() {
                    let _ = fs::remove_dir_all(layout.object_dir);
                    return Err(error);
                }
            }
            Mode::Seed => {
                let backend =
                    SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
                persist_seed_identity(&mut identity, &backend)?;
                identity.persist()?;
            }
        }

        true
    };

    Ok(IdentityCreateResult {
        identity,
        dry_run: request.dry_run,
        persisted,
    })
}

#[cfg(test)]
fn resolve_identity_with_seed_backend(
    probe: &dyn CapabilityProbe,
    request: &IdentityCreateRequest,
    seed_backend: &dyn SeedBackend,
) -> Result<IdentityCreateResult> {
    let mut identity = build_identity_record(probe, request)?;
    let persisted = if request.dry_run {
        false
    } else {
        persist_seed_identity(&mut identity, seed_backend)?;
        identity.persist()?;
        true
    };

    Ok(IdentityCreateResult {
        identity,
        dry_run: request.dry_run,
        persisted,
    })
}

fn build_identity_record(
    probe: &dyn CapabilityProbe,
    request: &IdentityCreateRequest,
) -> Result<Identity> {
    validate_profile_name(&request.identity)?;

    let requested_uses = normalize_uses(request.uses.clone());
    if requested_uses.is_empty() {
        return Err(Error::Validation(
            "at least one --use value is required for identity creation".to_string(),
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

    if resolved_mode == Mode::Native && !request.defaults.is_empty() {
        return Err(Error::Validation(
            "native identities reject derivation defaults; remove identity-level --org, --purpose, and --context flags"
                .to_string(),
        ));
    }

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

    Ok(Identity::with_defaults(
        request.identity.clone(),
        request.algorithm,
        uses,
        IdentityModeResolution {
            requested: request.requested_mode,
            resolved: resolved_mode,
            reasons,
        },
        IdentityDerivationDefaults {
            org: request.defaults.org.clone(),
            purpose: request.defaults.purpose.clone(),
            context: request.defaults.context.clone(),
        },
        StateLayout::from_optional_root(request.state_dir.clone()),
    ))
}

fn persist_seed_identity(identity: &mut Identity, seed_backend: &dyn SeedBackend) -> Result<()> {
    let seed_profile = SeedIdentity::scaffold(
        identity.name.clone(),
        identity.algorithm,
        identity.uses.clone(),
    )?;

    seed_backend.seal_seed(&SeedCreateRequest {
        identity: seed_profile.clone(),
        source: SeedCreateSource::GenerateRandom {
            bytes: DEFAULT_SETUP_SEED_BYTES,
        },
        overwrite_existing: false,
    })?;

    apply_seed_profile_metadata(identity, &seed_profile);
    Ok(())
}

fn apply_seed_profile_metadata(identity: &mut Identity, seed_profile: &SeedIdentity) {
    let object_dir = identity
        .storage
        .state_layout
        .objects_dir
        .join(&seed_profile.storage.object_label);
    let public_blob = object_dir.join("sealed.pub");
    let private_blob = object_dir.join("sealed.priv");

    identity.metadata.insert(
        SEED_OBJECT_LABEL_METADATA_KEY.to_string(),
        seed_profile.storage.object_label.clone(),
    );
    identity.metadata.insert(
        SEED_PUBLIC_BLOB_PATH_METADATA_KEY.to_string(),
        state_relative_metadata_path(identity, &public_blob),
    );
    identity.metadata.insert(
        SEED_PRIVATE_BLOB_PATH_METADATA_KEY.to_string(),
        state_relative_metadata_path(identity, &private_blob),
    );
    identity.metadata.insert(
        SEED_STORAGE_KIND_METADATA_KEY.to_string(),
        seed_storage_kind_name(seed_profile.storage.kind).to_string(),
    );
    identity.metadata.insert(
        SEED_DERIVATION_KDF_METADATA_KEY.to_string(),
        seed_kdf_name(seed_profile.derivation.kdf).to_string(),
    );
    identity.metadata.insert(
        SEED_DERIVATION_DOMAIN_LABEL_METADATA_KEY.to_string(),
        seed_profile.derivation.domain_label.clone(),
    );
    identity.metadata.insert(
        SEED_SOFTWARE_DERIVED_AT_USE_TIME_METADATA_KEY.to_string(),
        seed_profile
            .derivation
            .software_derived_at_use_time
            .to_string(),
    );
}

fn state_relative_metadata_path(identity: &Identity, path: &Path) -> String {
    path.strip_prefix(&identity.storage.state_layout.root_dir)
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

pub fn load_identity(identity: &str, state_dir: Option<PathBuf>) -> Result<Identity> {
    validate_profile_name(identity)?;
    Identity::load_named(identity, state_dir)
}

fn apply_prf_root_metadata(identity: &mut Identity, layout: &PrfRootLayout) -> Result<()> {
    identity.metadata.insert(
        PRF_PARENT_CONTEXT_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&identity.storage.state_layout, &layout.parent_context_path)?,
    );
    identity.metadata.insert(
        PRF_PUBLIC_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&identity.storage.state_layout, &layout.public_path)?,
    );
    identity.metadata.insert(
        PRF_PRIVATE_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&identity.storage.state_layout, &layout.private_path)?,
    );
    if layout.loaded_context_path.is_file() {
        identity.metadata.insert(
            PRF_CONTEXT_PATH_METADATA_KEY.to_string(),
            persistable_state_path(&identity.storage.state_layout, &layout.loaded_context_path)?,
        );
    }
    Ok(())
}

fn materialize_prf_setup<R>(identity: &mut Identity, runner: &R) -> Result<PrfRootLayout>
where
    R: CommandRunner,
{
    let backend = SubprocessPrfBackend::with_runner(
        identity.storage.state_layout.objects_dir.clone(),
        runner,
    );
    let layout = backend.provision_root(&identity.name)?;
    apply_prf_root_metadata(identity, &layout)?;
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
    validate_profile_name(&request.identity)?;

    let identity = load_identity(&request.identity, request.state_dir.clone())?;
    match request.kind {
        ExportKind::PublicKey => export_public_key(&identity, request),
        ExportKind::SecretKey => export_secret_key(&identity, request),
        ExportKind::Keypair => export_keypair(&identity, request),
    }
}

fn export_public_key(identity: &Identity, request: &ExportRequest) -> Result<ExportResult> {
    export_public_key_with_runner(identity, request, &ProcessCommandRunner)
}

fn export_public_key_with_runner<R>(
    identity: &Identity,
    request: &ExportRequest,
    runner: &R,
) -> Result<ExportResult>
where
    R: CommandRunner,
{
    shared::ensure_derivation_overrides_allowed(identity, &request.derivation)?;

    let format = resolve_public_key_export_format(request.format)?;

    match identity.mode.resolved {
        Mode::Native => export_native_public_key_with_runner(
            identity,
            request.output.as_deref(),
            format,
            runner,
        ),
        Mode::Prf | Mode::Seed => {
            let material = crate::ops::keygen::derive_identity_key_material_with_defaults(
                identity,
                &request.derivation,
                runner,
            )?;
            let public_key_der = crate::ops::keygen::public_key_spki_der_from_material(
                identity,
                material.expose_secret(),
            )?;
            let (rendered_public_key, artifact_format) = render_derived_public_key_export(
                identity,
                format,
                &public_key_der,
                material.expose_secret(),
            )?;
            let destination =
                resolve_public_key_output_path(identity, request.output.as_deref(), format)?;
            write_public_key_output(&destination, &rendered_public_key)?;

            Ok(ExportResult {
                identity: identity.name.clone(),
                mode: identity.mode.resolved,
                kind: ExportKind::PublicKey,
                artifact: ExportArtifact {
                    format: artifact_format,
                    path: destination,
                    bytes_written: rendered_public_key.len(),
                },
            })
        }
    }
}

fn export_secret_key(identity: &Identity, request: &ExportRequest) -> Result<ExportResult> {
    export_secret_key_with_runner(identity, request, &ProcessCommandRunner)
}

fn export_secret_key_with_runner<R>(
    identity: &Identity,
    request: &ExportRequest,
    runner: &R,
) -> Result<ExportResult>
where
    R: CommandRunner,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    export_secret_key_with_dependencies(
        identity,
        request,
        runner,
        &seed_backend,
        &HkdfSha256SeedDeriver,
    )
}

fn export_secret_key_with_dependencies<R, B, D>(
    identity: &Identity,
    request: &ExportRequest,
    runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<ExportResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    enforce_secret_export_policy(identity, request, ExportKind::SecretKey)?;

    let material = crate::ops::keygen::derive_identity_key_material(
        identity,
        &request.derivation,
        runner,
        seed_backend,
        seed_deriver,
    )?;
    let format = resolve_secret_key_export_format(request.format)?;
    let secret_key_bytes =
        crate::ops::keygen::normalized_secret_key_bytes(identity, material.expose_secret())?;
    let (rendered_secret_key, artifact_format) = render_secret_key_export(
        identity,
        format,
        secret_key_bytes.as_ref(),
        material.expose_secret(),
    )?;
    let destination = resolve_secret_export_output_path(
        identity,
        request.output.as_deref(),
        secret_key_export_default_suffix(format),
    )?;
    write_secret_output(&destination, rendered_secret_key.as_ref())?;

    Ok(ExportResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        kind: ExportKind::SecretKey,
        artifact: ExportArtifact {
            format: artifact_format,
            path: destination,
            bytes_written: rendered_secret_key.len(),
        },
    })
}

fn export_keypair(identity: &Identity, request: &ExportRequest) -> Result<ExportResult> {
    export_keypair_with_runner(identity, request, &ProcessCommandRunner)
}

fn export_keypair_with_runner<R>(
    identity: &Identity,
    request: &ExportRequest,
    runner: &R,
) -> Result<ExportResult>
where
    R: CommandRunner,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    export_keypair_with_dependencies(
        identity,
        request,
        runner,
        &seed_backend,
        &HkdfSha256SeedDeriver,
    )
}

fn export_keypair_with_dependencies<R, B, D>(
    identity: &Identity,
    request: &ExportRequest,
    runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<ExportResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    enforce_secret_export_policy(identity, request, ExportKind::Keypair)?;

    let material = crate::ops::keygen::derive_identity_key_material(
        identity,
        &request.derivation,
        runner,
        seed_backend,
        seed_deriver,
    )?;
    let format = resolve_keypair_export_format(request.format)?;
    let payload = render_keypair_json_bytes(identity, format, material.expose_secret())?;
    let destination =
        resolve_secret_export_output_path(identity, request.output.as_deref(), "keypair.json")?;
    write_secret_output(&destination, payload.as_ref())?;

    Ok(ExportResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        kind: ExportKind::Keypair,
        artifact: ExportArtifact {
            format: ExportFormat::Json,
            path: destination,
            bytes_written: payload.len(),
        },
    })
}

fn render_secret_key_export(
    identity: &Identity,
    format: Format,
    secret_key_bytes: &[u8],
    material: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, ExportFormat)> {
    match format {
        Format::Der => match identity.algorithm {
            Algorithm::Ed25519 => {
                let signing_key =
                    Ed25519SigningKey::from_bytes(&secret_key_bytes.try_into().map_err(|_| {
                        Error::Internal("ed25519 secret-key export expected 32 bytes".to_string())
                    })?);
                let der = signing_key.to_pkcs8_der().map_err(|error| {
                    Error::Internal(format!("failed to render pkcs8 DER: {error}"))
                })?;
                Ok((
                    Zeroizing::new(der.as_bytes().to_vec()),
                    ExportFormat::Pkcs8Der,
                ))
            }
            Algorithm::P256 => {
                let secret_key =
                    p256::SecretKey::from_slice(secret_key_bytes).map_err(|error| {
                        Error::Internal(format!("failed to materialize p256 secret key: {error}"))
                    })?;
                let der = secret_key.to_sec1_der().map_err(|error| {
                    Error::Internal(format!("failed to render sec1 DER: {error}"))
                })?;
                Ok((Zeroizing::new(der.to_vec()), ExportFormat::Sec1Der))
            }
            Algorithm::Secp256k1 => {
                let secret_key =
                    k256::SecretKey::from_slice(secret_key_bytes).map_err(|error| {
                        Error::Internal(format!(
                            "failed to materialize secp256k1 secret key: {error}"
                        ))
                    })?;
                let der = secret_key.to_sec1_der().map_err(|error| {
                    Error::Internal(format!("failed to render sec1 DER: {error}"))
                })?;
                Ok((Zeroizing::new(der.to_vec()), ExportFormat::Sec1Der))
            }
        },
        Format::Pem => match identity.algorithm {
            Algorithm::Ed25519 => {
                let (der, actual_format) =
                    render_secret_key_export(identity, Format::Der, secret_key_bytes, material)?;
                Ok((
                    Zeroizing::new(pem_wrap("PRIVATE KEY", der.as_ref()).into_bytes()),
                    match actual_format {
                        ExportFormat::Pkcs8Der => ExportFormat::Pkcs8Pem,
                        other => other,
                    },
                ))
            }
            Algorithm::P256 | Algorithm::Secp256k1 => {
                let (der, _) =
                    render_secret_key_export(identity, Format::Der, secret_key_bytes, material)?;
                Ok((
                    Zeroizing::new(pem_wrap("EC PRIVATE KEY", der.as_ref()).into_bytes()),
                    ExportFormat::Sec1Pem,
                ))
            }
        },
        Format::Openssh => Ok((
            Zeroizing::new(
                crate::ops::ssh::openssh_private_key_from_material(
                    identity,
                    material,
                    &identity.name,
                )?
                .as_bytes()
                .to_vec(),
            ),
            ExportFormat::Openssh,
        )),
        Format::Hex => Ok((
            Zeroizing::new(hex_encode(secret_key_bytes).into_bytes()),
            ExportFormat::Hex,
        )),
        Format::Base64 => Ok((
            Zeroizing::new(shared::base64_encode(secret_key_bytes).into_bytes()),
            ExportFormat::Base64,
        )),
        Format::Eth => Ok((
            Zeroizing::new(hex_encode(secret_key_bytes).into_bytes()),
            ExportFormat::Hex,
        )),
    }
}

#[derive(Serialize)]
struct KeypairJsonField<'a> {
    format: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<&'a str>,
    value: &'a str,
}

#[derive(Serialize)]
struct KeypairJsonPayload<'a> {
    identity: &'a str,
    mode: Mode,
    algorithm: Algorithm,
    private_key: KeypairJsonField<'a>,
    public_key: KeypairJsonField<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<KeypairJsonField<'a>>,
}

fn render_keypair_json_bytes(
    identity: &Identity,
    format: Format,
    material: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let secret_key_bytes = crate::ops::keygen::normalized_secret_key_bytes(identity, material)?;
    let public_key_der = crate::ops::keygen::public_key_spki_der_from_material(identity, material)?;
    let raw_public = raw_public_key_bytes_from_material(identity, material)?;

    let mut secret_text_guard = None::<Zeroizing<String>>;
    let mut secret_bytes_guard = None::<Zeroizing<Vec<u8>>>;
    let private_format;
    let private_encoding;
    let public_format;
    let public_encoding;
    let public_text;
    let address_text;

    match format {
        Format::Der => {
            let (private_bytes, private_export_format) = render_secret_key_export(
                identity,
                Format::Der,
                secret_key_bytes.as_ref(),
                material,
            )?;
            secret_text_guard = Some(Zeroizing::new(shared::base64_encode(
                private_bytes.as_ref(),
            )));
            secret_bytes_guard = Some(private_bytes);
            private_format = export_format_name(private_export_format);
            private_encoding = Some("base64");
            public_format = "spki-der";
            public_encoding = Some("base64");
            public_text = shared::base64_encode(&public_key_der);
            address_text = None;
        }
        Format::Pem => {
            let (private_bytes, private_export_format) = render_secret_key_export(
                identity,
                Format::Pem,
                secret_key_bytes.as_ref(),
                material,
            )?;
            secret_bytes_guard = Some(private_bytes);
            private_format = export_format_name(private_export_format);
            private_encoding = None;
            public_format = "spki-pem";
            public_encoding = None;
            public_text = spki_der_to_pem(&public_key_der);
            address_text = None;
        }
        Format::Openssh => {
            secret_text_guard = Some(crate::ops::ssh::openssh_private_key_from_material(
                identity,
                material,
                &identity.name,
            )?);
            private_format = "openssh";
            private_encoding = None;
            public_format = "openssh";
            public_encoding = None;
            public_text = crate::ops::ssh::openssh_public_key_from_material(identity, material)?;
            address_text = None;
        }
        Format::Hex => {
            secret_text_guard = Some(Zeroizing::new(hex_encode(secret_key_bytes.as_ref())));
            private_format = "hex";
            private_encoding = None;
            public_format = "hex";
            public_encoding = None;
            public_text = hex_encode(&raw_public);
            address_text = None;
        }
        Format::Base64 => {
            secret_text_guard = Some(Zeroizing::new(shared::base64_encode(
                secret_key_bytes.as_ref(),
            )));
            private_format = "base64";
            private_encoding = None;
            public_format = "base64";
            public_encoding = None;
            public_text = shared::base64_encode(&raw_public);
            address_text = None;
        }
        Format::Eth => {
            ensure_ethereum_address_algorithm(identity)?;
            secret_text_guard = Some(Zeroizing::new(hex_encode(secret_key_bytes.as_ref())));
            private_format = "hex";
            private_encoding = None;
            public_format = "hex";
            public_encoding = None;
            public_text = hex_encode(&raw_public);
            address_text = Some(ethereum_address_from_raw_public_bytes(&raw_public)?);
        }
    }

    let private_value = if let Some(private_text) = &secret_text_guard {
        private_text.as_str()
    } else {
        let private_bytes = secret_bytes_guard
            .as_ref()
            .ok_or_else(|| Error::Internal("missing secret key export bytes".to_string()))?;
        std::str::from_utf8(private_bytes.as_ref()).map_err(|error| {
            Error::State(format!(
                "failed to render keypair private key as UTF-8: {error}"
            ))
        })?
    };

    let payload = KeypairJsonPayload {
        identity: &identity.name,
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        private_key: KeypairJsonField {
            format: private_format,
            encoding: private_encoding,
            value: private_value,
        },
        public_key: KeypairJsonField {
            format: public_format,
            encoding: public_encoding,
            value: &public_text,
        },
        address: address_text.as_deref().map(|value| KeypairJsonField {
            format: "eth",
            encoding: None,
            value,
        }),
    };

    let mut rendered = Zeroizing::new(Vec::new());
    serde_json::to_writer_pretty(&mut *rendered, &payload).map_err(crate::error::Error::from)?;
    rendered.push(b'\n');

    Ok(rendered)
}

fn export_format_name(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::SpkiDer => "spki-der",
        ExportFormat::SpkiPem => "spki-pem",
        ExportFormat::Sec1Der => "sec1-der",
        ExportFormat::Sec1Pem => "sec1-pem",
        ExportFormat::Pkcs8Der => "pkcs8-der",
        ExportFormat::Pkcs8Pem => "pkcs8-pem",
        ExportFormat::Openssh => "openssh",
        ExportFormat::Eth => "eth",
        ExportFormat::Hex => "hex",
        ExportFormat::Base64 => "base64",
        ExportFormat::Json => "json",
    }
}

pub(crate) fn enforce_secret_egress_policy(
    identity: &Identity,
    action: &str,
    subject: &str,
    confirm: bool,
    reason: Option<&str>,
) -> Result<()> {
    if !identity.uses.contains(&UseCase::ExportSecret) {
        return Err(Error::PolicyRefusal(format!(
            "identity '{}' is not configured with use=export-secret, which is required for {action}",
            identity.name
        )));
    }

    if !confirm {
        return Err(Error::Validation(format!(
            "{action} requires --confirm because {subject} leaves TPM-only protection",
        )));
    }

    let reason = reason.unwrap_or_default().trim();
    if reason.is_empty() {
        return Err(Error::Validation(format!(
            "{action} requires --reason to record why {subject} is leaving TPM-only protection",
        )));
    }

    Ok(())
}

fn enforce_secret_export_policy(
    identity: &Identity,
    request: &ExportRequest,
    kind: ExportKind,
) -> Result<()> {
    if identity.mode.resolved == Mode::Native {
        return Err(Error::PolicyRefusal(format!(
            "identity '{}' resolved to native mode; {:?} export is unavailable for native TPM-backed keys",
            identity.name, kind
        )));
    }

    enforce_secret_egress_policy(
        identity,
        &format!("{:?} export", kind),
        "secret key material",
        request.confirm,
        request.reason.as_deref(),
    )
}

fn resolve_secret_export_output_path(
    identity: &Identity,
    requested_output: Option<&Path>,
    suffix: &str,
) -> Result<PathBuf> {
    let path = match requested_output {
        Some(path) => path.to_path_buf(),
        None => identity
            .storage
            .state_layout
            .exports_dir
            .join(format!("{}.{}", identity.name, suffix)),
    };

    validate_secret_bearing_output_path(&path)?;
    Ok(path)
}

fn validate_secret_bearing_output_path(path: &Path) -> Result<()> {
    if path == Path::new("-") {
        return Err(Error::Validation(
            "secret-bearing export may not write to stdout; choose an explicit regular file path"
                .to_string(),
        ));
    }

    if path.is_dir() {
        return Err(Error::Validation(format!(
            "export output '{}' must be a file path, not a directory",
            path.display()
        )));
    }

    if let Ok(metadata) = fs::symlink_metadata(path) {
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(Error::Validation(format!(
                "export output '{}' must not be a symlink",
                path.display()
            )));
        }
        if !file_type.is_file() {
            return Err(Error::Validation(format!(
                "export output '{}' must be a regular file path",
                path.display()
            )));
        }
    }

    Ok(())
}

fn write_secret_output(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    fs::create_dir_all(parent).map_err(|error| {
        Error::State(format!(
            "failed to create export directory '{}': {error}",
            parent.display()
        ))
    })?;

    validate_secret_bearing_output_path(path)?;

    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("secret-export"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(&temp_path).map_err(|error| {
        Error::State(format!(
            "failed to create secret-bearing export temp file '{}': {error}",
            temp_path.display()
        ))
    })?;

    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            let _ = fs::remove_file(&temp_path);
            Error::State(format!(
                "failed to set permissions on '{}': {error}",
                temp_path.display()
            ))
        })?;

    if let Err(error) = file.write_all(bytes) {
        let _ = fs::remove_file(&temp_path);
        return Err(Error::State(format!(
            "failed to write secret-bearing export to '{}': {error}",
            temp_path.display()
        )));
    }
    drop(file);

    fs::rename(&temp_path, path).map_err(|error| {
        let _ = fs::remove_file(&temp_path);
        Error::State(format!(
            "failed to move secret-bearing export into place '{}' -> '{}': {error}",
            temp_path.display(),
            path.display()
        ))
    })?;

    Ok(())
}

fn export_seed_public_key_with_backend<B, D>(
    identity: &Identity,
    requested_output: Option<&Path>,
    format: Format,
    backend: &B,
    deriver: &D,
) -> Result<ExportResult>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_identity = seed_profile_from_profile(identity)?;
    let spec = seed_public_key_derivation_spec(identity)?;
    let derived = open_and_derive(
        backend,
        deriver,
        &SeedOpenRequest {
            identity: seed_identity,
            auth_source: SeedOpenAuthSource::None,
            output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
                output_bytes: usize::from(spec.output().length),
                spec,
            }),
            require_fresh_unseal: true,
            confirm_software_derivation: true,
        },
    )?;

    let public_key_der =
        crate::ops::keygen::public_key_spki_der_from_material(identity, derived.expose_secret())?;
    let (rendered_public_key, artifact_format) = render_derived_public_key_export(
        identity,
        format,
        &public_key_der,
        derived.expose_secret(),
    )?;
    let destination = resolve_public_key_output_path(identity, requested_output, format)?;
    write_public_key_output(&destination, &rendered_public_key)?;

    Ok(ExportResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        kind: ExportKind::PublicKey,
        artifact: ExportArtifact {
            format: artifact_format,
            path: destination,
            bytes_written: rendered_public_key.len(),
        },
    })
}

fn seed_public_key_derivation_spec(identity: &Identity) -> Result<DerivationSpec> {
    let effective =
        shared::resolve_effective_derivation_inputs(identity, &DerivationOverrides::default())?;
    shared::identity_key_spec(identity.algorithm, &effective)
}

fn seed_secret_bytes(identity: &Identity, derived_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let seed_bytes: [u8; 32] = derived_secret.try_into().map_err(|_| {
        Error::Internal(format!(
            "seed public-key derivation for identity '{}' unexpectedly produced {} bytes instead of 32",
            identity.name,
            derived_secret.len()
        ))
    })?;
    Ok(Zeroizing::new(seed_bytes))
}

fn seed_valid_ec_scalar_bytes<F>(
    identity: &Identity,
    derived_secret: &[u8],
    is_valid: F,
) -> Result<Zeroizing<[u8; 32]>>
where
    F: Fn(&[u8]) -> bool,
{
    let seed_bytes = seed_secret_bytes(identity, derived_secret)?;
    if is_valid(seed_bytes.as_ref()) {
        return Ok(seed_bytes);
    }

    for counter in 1..=SEED_SCALAR_RETRY_LIMIT {
        let candidate = seed_scalar_retry_bytes(&*seed_bytes, identity.algorithm, counter);
        if is_valid(&candidate) {
            return Ok(Zeroizing::new(candidate));
        }
    }

    Err(Error::Internal(format!(
        "seed public-key derivation could not produce a valid {:?} scalar for identity '{}' after {} retries",
        identity.algorithm, identity.name, SEED_SCALAR_RETRY_LIMIT
    )))
}

fn seed_scalar_retry_bytes(seed_bytes: &[u8], algorithm: Algorithm, counter: u32) -> [u8; 32] {
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

/// Standalone EC scalar validation that doesn't require a `Identity` reference.
/// Used by the CLI seed sign/verify paths.
pub fn seed_valid_ec_scalar_bytes_standalone(
    derived_secret: &[u8],
    algorithm: Algorithm,
) -> Result<Zeroizing<[u8; 32]>> {
    let seed_bytes: [u8; 32] = derived_secret.try_into().map_err(|_| {
        Error::Internal(format!(
            "seed derivation unexpectedly produced {} bytes instead of 32",
            derived_secret.len()
        ))
    })?;
    let seed_bytes = Zeroizing::new(seed_bytes);

    let is_valid: Box<dyn Fn(&[u8]) -> bool> = match algorithm {
        Algorithm::P256 => {
            Box::new(|candidate: &[u8]| p256::SecretKey::from_slice(candidate).is_ok())
        }
        Algorithm::Secp256k1 => {
            Box::new(|candidate: &[u8]| k256::SecretKey::from_slice(candidate).is_ok())
        }
        Algorithm::Ed25519 => return Ok(seed_bytes),
    };

    if is_valid(seed_bytes.as_ref()) {
        return Ok(seed_bytes);
    }

    for counter in 1..=SEED_SCALAR_RETRY_LIMIT {
        let candidate = seed_scalar_retry_bytes(seed_bytes.as_ref(), algorithm, counter);
        if is_valid(&candidate) {
            return Ok(Zeroizing::new(candidate));
        }
    }

    Err(Error::Internal(format!(
        "seed derivation could not produce a valid {algorithm:?} scalar after {SEED_SCALAR_RETRY_LIMIT} retries"
    )))
}

fn ensure_identity_does_not_exist(identity: &Identity) -> Result<()> {
    if identity.storage.identity_path.exists() {
        return Err(Error::State(format!(
            "identity '{}' already exists at '{}'; remove it before creating a replacement",
            identity.name,
            identity.storage.identity_path.display()
        )));
    }

    Ok(())
}

fn materialize_native_setup<R>(
    identity: &mut Identity,
    runner: &R,
) -> Result<MaterializedNativeSetup>
where
    R: CommandRunner,
{
    if identity.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native setup is currently wired only for P-256 identities, got {:?}",
            identity.algorithm
        )));
    }

    let allowed_uses = native_key_uses(identity)?;
    let key_id = native_key_id(identity);
    let native_dir = native_state_dir(identity);
    let handle_path = native_handle_path(identity);

    identity.storage.state_layout.ensure_dirs()?;
    fs::create_dir_all(&native_dir).map_err(|error| {
        Error::State(format!(
            "failed to create native setup directory '{}': {error}",
            native_dir.display()
        ))
    })?;

    let _allocation_guard = native_handle_allocation_lock()
        .lock()
        .expect("native handle allocation lock poisoned");

    for _attempt in 0..NATIVE_SETUP_HANDLE_RETRY_LIMIT {
        let persistent_handle = allocate_native_persistent_handle(runner)?;
        match materialize_native_setup_with_handle(
            identity,
            runner,
            &allowed_uses,
            &key_id,
            &native_dir,
            &handle_path,
            &persistent_handle,
        ) {
            Ok(materialized) => return Ok(materialized),
            Err(NativeSetupAttemptError::PersistentHandleCollision) => continue,
            Err(NativeSetupAttemptError::Fatal(error)) => return Err(error),
        }
    }

    Err(Error::State(format!(
        "native setup for identity '{}' exceeded {} persistent-handle allocation retries",
        identity.name, NATIVE_SETUP_HANDLE_RETRY_LIMIT
    )))
}

fn materialize_native_setup_with_handle<R>(
    identity: &mut Identity,
    runner: &R,
    allowed_uses: &[NativeKeyUse],
    key_id: &str,
    native_dir: &Path,
    handle_path: &Path,
    persistent_handle: &str,
) -> std::result::Result<MaterializedNativeSetup, NativeSetupAttemptError>
where
    R: CommandRunner,
{
    remove_path_if_present(handle_path);

    let scratch_dir = TempfileBuilder::new()
        .prefix("setup-")
        .tempdir_in(native_dir)
        .map_err(|error| {
            NativeSetupAttemptError::Fatal(Error::State(format!(
                "failed to create native setup workspace in '{}': {error}",
                native_dir.display()
            )))
        })?;

    let setup_request = NativeIdentityCreateRequest {
        identity: identity.name.clone(),
        key_label: Some(identity.name.clone()),
        algorithm: NativeAlgorithm::P256,
        curve: NativeCurve::NistP256,
        allowed_uses: allowed_uses.to_vec(),
        hardware_binding: NativeHardwareBinding::Required,
        private_key_policy: NativePrivateKeyPolicy::NonExportable,
    };
    let plan = plan_setup(
        &setup_request,
        &NativeSetupArtifacts {
            scratch_dir: scratch_dir.path().to_path_buf(),
            key_id: key_id.to_string(),
            persistent: NativePersistentHandle {
                handle: persistent_handle.to_string(),
                serialized_handle_path: handle_path.to_path_buf(),
            },
        },
    )
    .map_err(NativeSetupAttemptError::Fatal)?;

    let mut persisted = false;
    for command in &plan.commands {
        let output = runner.run(&crate::backend::CommandInvocation::new(
            &command.program,
            command.args.iter().cloned(),
        ));
        if output.error.is_some() || output.exit_code != Some(0) {
            if command.program == "tpm2_evictcontrol" {
                remove_path_if_present(handle_path);
                match persistent_handle_is_allocated(runner, persistent_handle) {
                    Ok(true) => return Err(NativeSetupAttemptError::PersistentHandleCollision),
                    Ok(false) => {}
                    Err(error) => return Err(NativeSetupAttemptError::Fatal(error)),
                }
            }

            return Err(NativeSetupAttemptError::Fatal(
                native_operation_command_error(command, &output, "native setup"),
            ));
        }

        if command.program == "tpm2_evictcontrol" {
            persisted = true;
        }
    }

    if !handle_path.is_file() {
        if persisted {
            let _ = rollback_native_persistent_handle(runner, persistent_handle);
        }
        return Err(NativeSetupAttemptError::Fatal(Error::State(format!(
            "native setup completed without creating serialized handle state '{}'; sign/export cannot locate the TPM object",
            handle_path.display()
        ))));
    }

    persist_native_metadata(identity, key_id, persistent_handle, handle_path);

    Ok(MaterializedNativeSetup {
        persistent_handle: persistent_handle.to_string(),
        handle_path: handle_path.to_path_buf(),
    })
}

fn export_native_public_key_with_runner<R>(
    identity: &Identity,
    requested_output: Option<&Path>,
    format: Format,
    runner: &R,
) -> Result<ExportResult>
where
    R: CommandRunner,
{
    if identity.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native public-key export is currently wired only for P-256 identities, got {:?}",
            identity.algorithm
        )));
    }

    identity.storage.state_layout.ensure_dirs()?;

    let locator = resolve_native_key_locator(identity)?;
    let tempdir = TempfileBuilder::new()
        .prefix("native-public-key-export-")
        .tempdir_in(&identity.storage.state_layout.exports_dir)
        .map_err(|error| {
            Error::State(format!(
                "failed to create native export workspace in '{}': {error}",
                identity.storage.state_layout.exports_dir.display()
            ))
        })?;

    let requested_encoding = native_public_key_encoding(format);
    let plan = plan_export_public_key(
        &NativePublicKeyExportRequest {
            key: NativeKeyRef {
                identity: identity.name.clone(),
                key_id: native_key_id(identity),
            },
            encodings: vec![requested_encoding],
        },
        &NativePublicKeyExportOptions {
            locator,
            output_dir: tempdir.path().to_path_buf(),
            file_stem: identity.name.clone(),
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
    let (rendered_public_key, artifact_format) =
        render_public_key_export_from_spki(identity, format, &exported_bytes)?;

    let destination = resolve_public_key_output_path(identity, requested_output, format)?;
    write_public_key_output(&destination, &rendered_public_key)?;

    Ok(ExportResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        kind: ExportKind::PublicKey,
        artifact: ExportArtifact {
            format: artifact_format,
            path: destination,
            bytes_written: rendered_public_key.len(),
        },
    })
}

const TPM_PERSISTENT_HANDLE_MIN: u32 = 0x8100_0000;
const TPM_PERSISTENT_HANDLE_MAX: u32 = 0x81ff_ffff;
const TPM_PERSISTENT_HANDLE_START: u32 = 0x8101_0000;
const NATIVE_SETUP_HANDLE_RETRY_LIMIT: usize = 32;
const TPM_OWNER_HIERARCHY: &str = "owner";

static NATIVE_HANDLE_ALLOCATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static NATIVE_SETUP_LOCKS: OnceLock<NativeSetupLocks> = OnceLock::new();

struct NativeSetupLocks {
    active: Mutex<BTreeSet<PathBuf>>,
    ready: Condvar,
}

impl NativeSetupLocks {
    fn global() -> &'static Self {
        NATIVE_SETUP_LOCKS.get_or_init(|| Self {
            active: Mutex::new(BTreeSet::new()),
            ready: Condvar::new(),
        })
    }
}

struct NativeSetupGuard {
    key: PathBuf,
}

impl Drop for NativeSetupGuard {
    fn drop(&mut self) {
        let locks = NativeSetupLocks::global();
        let mut active = locks.active.lock().expect("native setup lock poisoned");
        active.remove(&self.key);
        locks.ready.notify_all();
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct MaterializedNativeSetup {
    persistent_handle: String,
    handle_path: PathBuf,
}

enum NativeSetupAttemptError {
    PersistentHandleCollision,
    Fatal(Error),
}

fn acquire_native_setup_lock(identity: &Identity) -> NativeSetupGuard {
    let key = identity.storage.identity_path.clone();
    let locks = NativeSetupLocks::global();
    let mut active = locks.active.lock().expect("native setup lock poisoned");
    while active.contains(&key) {
        active = locks
            .ready
            .wait(active)
            .expect("native setup lock poisoned while waiting");
    }
    active.insert(key.clone());
    NativeSetupGuard { key }
}

fn native_handle_allocation_lock() -> &'static Mutex<()> {
    NATIVE_HANDLE_ALLOCATION_LOCK.get_or_init(|| Mutex::new(()))
}

pub(crate) fn resolve_native_key_locator(identity: &Identity) -> Result<NativeKeyLocator> {
    if let Some(path) = metadata_path(
        identity,
        &[
            "native.serialized_handle_path",
            "native.serialized-handle-path",
        ],
    ) {
        if path.is_file() {
            return Ok(NativeKeyLocator::SerializedHandle { path });
        }

        return Err(Error::State(format!(
            "identity '{}' resolved to native mode but serialized handle state '{}' is missing; recreate the identity instead of falling back to a raw persistent handle",
            identity.name,
            path.display()
        )));
    }

    let discovered_paths: Vec<_> = native_handle_path_candidates(identity)
        .into_iter()
        .filter(|path| path.is_file())
        .collect();
    if discovered_paths.len() == 1 {
        return Ok(NativeKeyLocator::SerializedHandle {
            path: discovered_paths[0].clone(),
        });
    }
    if discovered_paths.len() > 1 {
        return Err(Error::State(format!(
            "identity '{}' resolved to native mode but multiple serialized handle files were found: {}; remove stale native state so key location is unambiguous",
            identity.name,
            discovered_paths
                .iter()
                .map(|path| format!("'{}'", path.display()))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    Err(Error::State(format!(
        "identity '{}' resolved to native mode but no serialized handle state was found; checked {}",
        identity.name,
        native_handle_path_candidates(identity)
            .into_iter()
            .map(|path| format!("'{}'", path.display()))
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn native_key_uses(identity: &Identity) -> Result<Vec<NativeKeyUse>> {
    let mut uses: Vec<_> = identity
        .uses
        .iter()
        .map(|use_case| match use_case {
            UseCase::Sign => Ok(NativeKeyUse::Sign),
            UseCase::Verify => Ok(NativeKeyUse::Verify),
            unsupported => Err(Error::Unsupported(format!(
                "native setup is currently wired only for truthful sign/verify uses, but identity '{}' requested {:?}",
                identity.name, unsupported
            ))),
        })
        .collect::<Result<_>>()?;

    uses.sort();
    uses.dedup();

    if uses.is_empty() {
        return Err(Error::Validation(
            "native setup requires at least one sign/verify-backed use".to_string(),
        ));
    }

    Ok(uses)
}

fn allocate_native_persistent_handle<R>(runner: &R) -> Result<String>
where
    R: CommandRunner,
{
    let taken = discover_persistent_handles(runner)?;
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

fn discover_persistent_handles<R>(runner: &R) -> Result<BTreeSet<String>>
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

    parse_persistent_handles(&output.stdout)
}

fn persistent_handle_is_allocated<R>(runner: &R, handle: &str) -> Result<bool>
where
    R: CommandRunner,
{
    Ok(discover_persistent_handles(runner)?.contains(handle))
}

fn rollback_materialized_native_setup<R>(
    runner: &R,
    materialized: &MaterializedNativeSetup,
) -> Result<()>
where
    R: CommandRunner,
{
    remove_path_if_present(&materialized.handle_path);
    rollback_native_persistent_handle(runner, &materialized.persistent_handle)
}

fn rollback_native_persistent_handle<R>(runner: &R, handle: &str) -> Result<()>
where
    R: CommandRunner,
{
    let command = NativeCommandSpec::new(
        "tpm2_evictcontrol",
        ["-C", TPM_OWNER_HIERARCHY, "-c", handle],
    );
    run_native_command_for_operation(&command, runner, "native setup rollback")
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
    identity: &mut Identity,
    key_id: &str,
    persistent_handle: &str,
    handle_path: &Path,
) {
    identity
        .metadata
        .insert("native.backend".to_string(), "subprocess".to_string());
    identity
        .metadata
        .insert("native.key_id".to_string(), key_id.to_string());
    identity.metadata.insert(
        "native.locator_kind".to_string(),
        "serialized-handle".to_string(),
    );
    identity.metadata.insert(
        "native.serialized_handle_path".to_string(),
        path_for_metadata(&identity.storage.state_layout.root_dir, handle_path),
    );
    identity.metadata.insert(
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

fn native_state_dir(identity: &Identity) -> PathBuf {
    identity
        .storage
        .state_layout
        .objects_dir
        .join(&identity.name)
        .join("native")
}

fn native_handle_path(identity: &Identity) -> PathBuf {
    native_state_dir(identity).join(format!("{}.handle", native_key_id(identity)))
}

pub(crate) fn metadata_path(identity: &Identity, keys: &[&str]) -> Option<PathBuf> {
    let value = metadata_value(identity, keys)?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(identity.storage.state_layout.root_dir.join(path))
    }
}

pub(crate) fn metadata_value(identity: &Identity, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| identity.metadata.get(*key).cloned())
}

pub(crate) fn native_handle_path_candidates(identity: &Identity) -> Vec<PathBuf> {
    let objects_dir = &identity.storage.state_layout.objects_dir;
    vec![
        native_handle_path(identity),
        objects_dir.join(format!("{}.handle", identity.name)),
        objects_dir
            .join(&identity.name)
            .join(format!("{}.handle", identity.name)),
        objects_dir.join(&identity.name).join("key.handle"),
        objects_dir.join(&identity.name).join("persistent.handle"),
    ]
}

pub(crate) fn native_key_id(identity: &Identity) -> String {
    metadata_value(identity, &["native.key_id", "native.key-id"])
        .unwrap_or_else(|| format!("{}-signing-key", identity.name))
}

fn resolve_public_key_export_format(format: Option<Format>) -> Result<Format> {
    let format = format.unwrap_or(Format::Pem);
    Ok(format)
}

fn resolve_secret_key_export_format(format: Option<Format>) -> Result<Format> {
    let format = format.unwrap_or(Format::Pem);
    match format {
        Format::Der
        | Format::Pem
        | Format::Openssh
        | Format::Eth
        | Format::Hex
        | Format::Base64 => Ok(format),
    }
}

fn resolve_keypair_export_format(format: Option<Format>) -> Result<Format> {
    let format = format.unwrap_or(Format::Pem);
    match format {
        Format::Der
        | Format::Pem
        | Format::Openssh
        | Format::Eth
        | Format::Hex
        | Format::Base64 => Ok(format),
    }
}

fn resolve_public_key_output_path(
    identity: &Identity,
    requested_output: Option<&Path>,
    format: Format,
) -> Result<PathBuf> {
    match requested_output {
        Some(path) if path.is_dir() => Err(Error::Validation(format!(
            "export output '{}' must be a file path, not a directory",
            path.display()
        ))),
        Some(path) => Ok(path.to_path_buf()),
        None => Ok(identity.storage.state_layout.exports_dir.join(format!(
            "{}.{}",
            identity.name,
            public_key_export_default_suffix(format)
        ))),
    }
}

fn native_public_key_encoding(_format: Format) -> NativePublicKeyEncoding {
    NativePublicKeyEncoding::SpkiDer
}

fn render_public_key_export_from_spki(
    identity: &Identity,
    format: Format,
    spki_der: &[u8],
) -> Result<(Vec<u8>, ExportFormat)> {
    match format {
        Format::Der => Ok((spki_der.to_vec(), ExportFormat::SpkiDer)),
        Format::Pem => Ok((
            spki_der_to_pem(spki_der).into_bytes(),
            ExportFormat::SpkiPem,
        )),
        Format::Openssh => Ok((
            render_openssh_public_key(identity, spki_der)?.into_bytes(),
            ExportFormat::Openssh,
        )),
        Format::Eth => {
            ensure_ethereum_address_algorithm(identity)?;
            let raw_public = raw_public_key_bytes_from_spki(identity, spki_der)?;
            Ok((
                ethereum_address_from_raw_public_bytes(&raw_public)?.into_bytes(),
                ExportFormat::Eth,
            ))
        }
        Format::Hex => {
            let raw_public = raw_public_key_bytes_from_spki(identity, spki_der)?;
            Ok((hex_encode(&raw_public).into_bytes(), ExportFormat::Hex))
        }
        Format::Base64 => {
            let raw_public = raw_public_key_bytes_from_spki(identity, spki_der)?;
            Ok((
                shared::base64_encode(&raw_public).into_bytes(),
                ExportFormat::Base64,
            ))
        }
    }
}

fn render_derived_public_key_export(
    identity: &Identity,
    format: Format,
    spki_der: &[u8],
    material: &[u8],
) -> Result<(Vec<u8>, ExportFormat)> {
    match format {
        Format::Der => Ok((spki_der.to_vec(), ExportFormat::SpkiDer)),
        Format::Pem => Ok((
            spki_der_to_pem(spki_der).into_bytes(),
            ExportFormat::SpkiPem,
        )),
        Format::Openssh => Ok((
            crate::ops::ssh::openssh_public_key_from_material(identity, material)?.into_bytes(),
            ExportFormat::Openssh,
        )),
        Format::Eth => {
            ensure_ethereum_address_algorithm(identity)?;
            let raw_public = raw_public_key_bytes_from_material(identity, material)?;
            Ok((
                ethereum_address_from_raw_public_bytes(&raw_public)?.into_bytes(),
                ExportFormat::Eth,
            ))
        }
        Format::Hex => {
            let raw_public = raw_public_key_bytes_from_material(identity, material)?;
            Ok((hex_encode(&raw_public).into_bytes(), ExportFormat::Hex))
        }
        Format::Base64 => {
            let raw_public = raw_public_key_bytes_from_material(identity, material)?;
            Ok((
                shared::base64_encode(&raw_public).into_bytes(),
                ExportFormat::Base64,
            ))
        }
    }
}

fn raw_public_key_bytes_from_spki(identity: &Identity, spki_der: &[u8]) -> Result<Vec<u8>> {
    match identity.algorithm {
        Algorithm::P256 => {
            Ok(crate::ops::native::subprocess::extract_p256_sec1_from_spki_der(spki_der)?.to_vec())
        }
        Algorithm::Ed25519 | Algorithm::Secp256k1 => Err(Error::Unsupported(format!(
            "raw public-key export from SPKI DER is not wired for native {:?} identities",
            identity.algorithm
        ))),
    }
}

fn raw_public_key_bytes_from_material(identity: &Identity, material: &[u8]) -> Result<Vec<u8>> {
    let secret_key = crate::ops::keygen::normalized_secret_key_bytes(identity, material)?;
    match identity.algorithm {
        Algorithm::Ed25519 => {
            let signing_key = Ed25519SigningKey::from_bytes(&secret_key);
            Ok(signing_key.verifying_key().as_bytes().to_vec())
        }
        Algorithm::P256 => {
            let secret_key = p256::SecretKey::from_slice(secret_key.as_ref()).map_err(|error| {
                Error::Internal(format!(
                    "failed to materialize p256 public key for identity '{}': {error}",
                    identity.name
                ))
            })?;
            Ok(secret_key
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec())
        }
        Algorithm::Secp256k1 => {
            let secret_key = k256::SecretKey::from_slice(secret_key.as_ref()).map_err(|error| {
                Error::Internal(format!(
                    "failed to materialize secp256k1 public key for identity '{}': {error}",
                    identity.name
                ))
            })?;
            Ok(secret_key
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec())
        }
    }
}

fn ensure_ethereum_address_algorithm(identity: &Identity) -> Result<()> {
    if identity.algorithm != Algorithm::Secp256k1 {
        return Err(Error::Validation(
            "eth export is supported only for secp256k1 identities".to_string(),
        ));
    }

    Ok(())
}

fn ethereum_address_from_raw_public_bytes(raw_public_key: &[u8]) -> Result<String> {
    if raw_public_key.len() != 65 || raw_public_key.first().copied() != Some(0x04) {
        return Err(Error::Validation(
            "eth export requires an uncompressed 65-byte SEC1 public key".to_string(),
        ));
    }

    let digest = Keccak256::digest(&raw_public_key[1..]);
    let lower = hex_encode(&digest[12..]);
    let checksum_hash = Keccak256::digest(lower.as_bytes());
    let mut checksummed = String::with_capacity(lower.len());
    for (index, ch) in lower.chars().enumerate() {
        if ch.is_ascii_digit() {
            checksummed.push(ch);
            continue;
        }
        let nibble = if index % 2 == 0 {
            (checksum_hash[index / 2] >> 4) & 0x0f
        } else {
            checksum_hash[index / 2] & 0x0f
        };
        if nibble >= 8 {
            checksummed.push(ch.to_ascii_uppercase());
        } else {
            checksummed.push(ch);
        }
    }

    Ok(format!("0x{checksummed}"))
}

fn spki_der_to_pem(spki_der: &[u8]) -> String {
    pem_wrap("PUBLIC KEY", spki_der)
}

fn pem_wrap(label: &str, der_bytes: &[u8]) -> String {
    let base64 = base64_encode(der_bytes);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
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

fn render_openssh_public_key(identity: &Identity, spki_der: &[u8]) -> Result<String> {
    let sec1 = crate::ops::native::subprocess::extract_p256_sec1_from_spki_der(spki_der)?;
    let key_data = SshKeyData::Ecdsa(SshEcdsaPublicKey::from_sec1_bytes(&sec1).map_err(
        |error| {
            Error::State(format!(
                "failed to convert exported SPKI DER into an OpenSSH ECDSA public key for identity '{}': {error}",
                identity.name
            ))
        },
    )?);
    let public_key = SshPublicKey::new(key_data, identity.name.clone());

    public_key.to_openssh().map_err(|error| {
        Error::State(format!(
            "failed to render OpenSSH public key for identity '{}': {error}",
            identity.name
        ))
    })
}

fn public_key_export_default_suffix(format: Format) -> &'static str {
    match format {
        Format::Der => "public-key.der",
        Format::Pem => "public-key.pem",
        Format::Openssh => "public-key.openssh.pub",
        Format::Eth => "public-key.eth",
        Format::Hex => "public-key.hex",
        Format::Base64 => "public-key.base64",
    }
}

fn secret_key_export_default_suffix(format: Format) -> &'static str {
    match format {
        Format::Der => "secret-key.der",
        Format::Pem => "secret-key.pem",
        Format::Openssh => "secret-key.openssh",
        Format::Hex => "secret-key.hex",
        Format::Base64 => "secret-key.base64",
        Format::Eth => "secret-key.hex",
    }
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

    if output.error.is_some() || output.exit_code != Some(0) {
        return Err(native_operation_command_error(command, &output, operation));
    }

    Ok(())
}

fn native_operation_command_error(
    command: &NativeCommandSpec,
    output: &CommandOutput,
    operation: &str,
) -> Error {
    if output.error.is_some() {
        Error::TpmUnavailable(format!(
            "{operation} failed while running '{} {}': {}",
            command.program,
            command.args.join(" "),
            render_command_detail(output)
        ))
    } else {
        Error::CapabilityMismatch(format!(
            "{operation} failed while running '{} {}': {}",
            command.program,
            command.args.join(" "),
            render_command_detail(output)
        ))
    }
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

fn validate_profile_name(identity: &str) -> Result<()> {
    if identity.trim().is_empty() {
        return Err(Error::Validation(
            "identity name must not be empty".to_string(),
        ));
    }

    if !identity
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(Error::Validation(
            "identity name may contain only ASCII letters, numbers, '.', '-', and '_'".to_string(),
        ));
    }

    if identity.contains("..") {
        return Err(Error::Validation(
            "identity name must not contain '..'".to_string(),
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use std::time::Duration;

    use ed25519_dalek::pkcs8::EncodePublicKey as _;
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

    fn native_handle_path_for_test(root_dir: &Path, identity: &str) -> PathBuf {
        StateLayout::new(root_dir.to_path_buf())
            .objects_dir
            .join(identity)
            .join("native")
            .join(format!("{identity}-signing-key.handle"))
    }

    #[test]
    fn setup_persists_materialized_native_profile_when_not_dry_run() {
        let root_dir = unique_temp_path("setup-persist");
        let runner = FakeNativeSetupRunner::new();
        let request = IdentityCreateRequest {
            identity: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Verify, UseCase::Sign],
            requested_mode: ModePreference::Native,
            defaults: crate::model::DerivationOverrides::default(),
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };

        let result = resolve_identity_with_runner(&HeuristicProbe, &request, &runner)
            .expect("setup should succeed");
        let identity_path = root_dir.join("identities").join("prod-signer.json");
        let handle_path = root_dir
            .join("objects")
            .join("prod-signer")
            .join("native")
            .join("prod-signer-signing-key.handle");

        assert!(result.persisted);
        assert_eq!(result.identity.storage.identity_path, identity_path);
        assert!(identity_path.is_file());
        assert!(handle_path.is_file());
        assert_eq!(
            result.identity.metadata.get("native.key_id"),
            Some(&"prod-signer-signing-key".to_string())
        );
        assert_eq!(
            result
                .identity
                .metadata
                .get("native.serialized_handle_path"),
            Some(&"objects/prod-signer/native/prod-signer-signing-key.handle".to_string())
        );
        assert_eq!(
            result.identity.metadata.get("native.persistent_handle"),
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

        let loaded = load_identity("prod-signer", Some(root_dir.clone())).expect("identity loads");
        assert_eq!(loaded, result.identity);
        assert_eq!(runner.calls().len(), 5);

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn same_name_native_setup_is_serialized_and_second_request_fails() {
        let root_dir = unique_temp_path("setup-same-name-lock");
        let runner = SlowNativeSetupRunner::new(Duration::from_millis(100));
        let request = IdentityCreateRequest {
            identity: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Verify, UseCase::Sign],
            requested_mode: ModePreference::Native,
            defaults: crate::model::DerivationOverrides::default(),
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };
        let barrier = Arc::new(Barrier::new(2));

        let runner_one = runner.clone();
        let request_one = request.clone();
        let barrier_one = barrier.clone();
        let worker_one = thread::spawn(move || {
            barrier_one.wait();
            resolve_identity_with_runner(&HeuristicProbe, &request_one, &runner_one)
        });

        let runner_two = runner.clone();
        let request_two = request.clone();
        let barrier_two = barrier.clone();
        let worker_two = thread::spawn(move || {
            barrier_two.wait();
            resolve_identity_with_runner(&HeuristicProbe, &request_two, &runner_two)
        });

        let first = worker_one
            .join()
            .expect("first setup thread should not panic");
        let second = worker_two
            .join()
            .expect("second setup thread should not panic");
        let results = [first, second];

        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one setup should succeed"
        );
        assert_eq!(
            results.iter().filter(|result| result.is_err()).count(),
            1,
            "exactly one setup should fail"
        );
        assert!(results.iter().any(|result| {
            matches!(
                result,
                Err(Error::State(message)) if message.contains("already exists")
            )
        }));
        assert_eq!(runner.calls().len(), 5);
        assert!(
            root_dir
                .join("identities")
                .join("prod-signer.json")
                .is_file()
        );

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn setup_retries_persistent_handle_collisions_with_unique_workspaces() {
        let root_dir = unique_temp_path("setup-handle-collision");
        let runner = HandleCollisionNativeSetupRunner::new();
        let request = IdentityCreateRequest {
            identity: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Verify, UseCase::Sign],
            requested_mode: ModePreference::Native,
            defaults: crate::model::DerivationOverrides::default(),
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };

        let result = resolve_identity_with_runner(&HeuristicProbe, &request, &runner)
            .expect("setup should retry and succeed");
        assert_eq!(
            result.identity.metadata.get("native.persistent_handle"),
            Some(&"0x81010003".to_string())
        );

        let primary_contexts = runner.paths_for("tpm2_createprimary", "-c");
        assert_eq!(primary_contexts.len(), 2);
        assert_ne!(primary_contexts[0], primary_contexts[1]);
        assert_ne!(
            primary_contexts[0].parent(),
            primary_contexts[1].parent(),
            "retry attempts should use different native setup workspaces"
        );
        assert!(primary_contexts.iter().all(|path| !path.exists()));

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn setup_rolls_back_materialized_handle_when_identity_persist_fails() {
        let root_dir = unique_temp_path("setup-native-persist-failure");
        let identity_path = StateLayout::new(root_dir.clone()).identity_path("prod-signer");
        let runner = PersistFailureNativeSetupRunner::new(identity_path.clone());
        let request = IdentityCreateRequest {
            identity: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Verify, UseCase::Sign],
            requested_mode: ModePreference::Native,
            defaults: crate::model::DerivationOverrides::default(),
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };

        let error = resolve_identity_with_runner(&HeuristicProbe, &request, &runner)
            .expect_err("persist failure should roll back native state");
        assert!(matches!(error, Error::State(_)));
        assert!(!native_handle_path_for_test(&root_dir, "prod-signer").exists());
        assert!(runner.rollback_was_attempted());

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn resolve_native_key_locator_fails_closed_when_serialized_handle_metadata_is_missing() {
        let root_dir = unique_temp_path("native-locator-fail-closed");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let mut identity = Identity::new(
            "prod-signer".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign],
            IdentityModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            state_layout,
        );
        identity.metadata.insert(
            "native.serialized_handle_path".to_string(),
            "objects/prod-signer/native/missing.handle".to_string(),
        );
        identity.metadata.insert(
            "native.persistent_handle".to_string(),
            "0x81010002".to_string(),
        );

        let error = resolve_native_key_locator(&identity)
            .expect_err("missing serialized handle metadata should fail closed");
        assert!(
            matches!(error, Error::State(message) if message.contains("serialized handle state") && message.contains("raw persistent handle"))
        );

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn resolve_native_key_locator_rejects_ambiguous_serialized_handle_state() {
        let root_dir = unique_temp_path("native-locator-ambiguous");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let identity = Identity::new(
            "prod-signer".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign],
            IdentityModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            state_layout,
        );
        let primary_handle = native_handle_path(&identity);
        let alternate_handle = identity
            .storage
            .state_layout
            .objects_dir
            .join(&identity.name)
            .join("key.handle");
        fs::create_dir_all(primary_handle.parent().expect("primary handle parent"))
            .expect("primary handle dir");
        fs::create_dir_all(alternate_handle.parent().expect("alternate handle parent"))
            .expect("alternate handle dir");
        fs::write(&primary_handle, b"serialized-handle").expect("primary handle file");
        fs::write(&alternate_handle, b"serialized-handle").expect("alternate handle file");

        let error = resolve_native_key_locator(&identity)
            .expect_err("ambiguous serialized handles should fail closed");
        assert!(
            matches!(error, Error::State(message) if message.contains("multiple serialized handle files") && message.contains("unambiguous"))
        );

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn setup_dry_run_does_not_touch_state() {
        let root_dir = unique_temp_path("setup-dry-run");
        let runner = FakeNativeSetupRunner::new();
        let request = IdentityCreateRequest {
            identity: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign],
            requested_mode: ModePreference::Native,
            defaults: crate::model::DerivationOverrides::default(),
            state_dir: Some(root_dir.clone()),
            dry_run: true,
        };

        let result = resolve_identity_with_runner(&HeuristicProbe, &request, &runner)
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
        let request = IdentityCreateRequest {
            identity: "prf-default".to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Sign],
            requested_mode: ModePreference::Prf,
            defaults: crate::model::DerivationOverrides::default(),
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };
        let probe = StaticCapabilityProbe::prf();
        let runner = FakePrfSetupRunner::default();

        let result = resolve_identity_with_runner(&probe, &request, &runner)
            .expect("PRF setup should succeed");
        let object_dir = root_dir.join("objects").join("prf-default");

        assert!(result.persisted);
        assert!(object_dir.join("parent.ctx").is_file());
        assert!(object_dir.join("prf-root.pub").is_file());
        assert!(object_dir.join("prf-root.priv").is_file());
        assert_eq!(
            result
                .identity
                .metadata
                .get(PRF_PARENT_CONTEXT_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/parent.ctx")
        );
        assert_eq!(
            result
                .identity
                .metadata
                .get(PRF_PUBLIC_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/prf-root.pub")
        );
        assert_eq!(
            result
                .identity
                .metadata
                .get(PRF_PRIVATE_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/prf-root.priv")
        );
        assert!(
            result
                .identity
                .metadata
                .get(PRF_CONTEXT_PATH_METADATA_KEY)
                .is_none(),
            "PRF provisioning now persists loadable blobs and recreates transient contexts at use time"
        );

        let loaded = load_identity("prf-default", Some(root_dir.clone())).expect("identity loads");
        assert_eq!(loaded.metadata, result.identity.metadata);
        assert_eq!(
            runner.recorded_programs(),
            vec!["tpm2_createprimary", "tpm2_create"]
        );

        fs::remove_dir_all(root_dir).expect("temporary prf setup state should be removed");
    }

    #[test]
    fn setup_seed_persists_relative_metadata_and_records_backend_request() {
        let root_dir = unique_temp_path("setup-seed-provision");
        let request = IdentityCreateRequest {
            identity: "seed-default".to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Sign, UseCase::Sign, UseCase::Ssh],
            requested_mode: ModePreference::Seed,
            defaults: crate::model::DerivationOverrides::default(),
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };
        let probe = StaticCapabilityProbe::seed();
        let backend = RecordingSeedSetupBackend::new(root_dir.join("objects"));

        let result = resolve_identity_with_seed_backend(&probe, &request, &backend)
            .expect("seed setup should succeed");
        let object_dir = root_dir.join("objects").join("seed-default");

        assert!(result.persisted);
        assert!(object_dir.join("sealed.pub").is_file());
        assert!(object_dir.join("sealed.priv").is_file());
        assert_eq!(
            result
                .identity
                .metadata
                .get(SEED_OBJECT_LABEL_METADATA_KEY)
                .map(String::as_str),
            Some("seed-default")
        );
        assert_eq!(
            result
                .identity
                .metadata
                .get(SEED_PUBLIC_BLOB_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/seed-default/sealed.pub")
        );
        assert_eq!(
            result
                .identity
                .metadata
                .get(SEED_PRIVATE_BLOB_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/seed-default/sealed.priv")
        );
        assert_eq!(
            result
                .identity
                .metadata
                .get(SEED_STORAGE_KIND_METADATA_KEY)
                .map(String::as_str),
            Some("tpm-sealed")
        );
        assert_eq!(
            result
                .identity
                .metadata
                .get(SEED_DERIVATION_KDF_METADATA_KEY)
                .map(String::as_str),
            Some("hkdf-sha256-v1")
        );
        assert_eq!(
            result
                .identity
                .metadata
                .get(SEED_DERIVATION_DOMAIN_LABEL_METADATA_KEY)
                .map(String::as_str),
            Some("tpm2-derive.seed.software-derived")
        );
        assert_eq!(
            result
                .identity
                .metadata
                .get(SEED_SOFTWARE_DERIVED_AT_USE_TIME_METADATA_KEY)
                .map(String::as_str),
            Some("true")
        );

        let loaded = load_identity("seed-default", Some(root_dir.clone())).expect("identity loads");
        assert_eq!(loaded.metadata, result.identity.metadata);
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
    fn export_native_public_key_rejects_derivation_overrides() {
        let root_dir = unique_temp_path("export-native-derivation-rejected");
        let identity = Identity::new(
            "native-export".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Verify],
            IdentityModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            StateLayout::new(root_dir.clone()),
        );

        let error = export_public_key_with_runner(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::PublicKey,
                output: Some(root_dir.join("native.der")),
                format: Some(Format::Der),
                state_dir: Some(root_dir.clone()),
                reason: None,
                confirm: false,
                derivation: DerivationOverrides {
                    org: Some("com.example".to_string()),
                    purpose: None,
                    context: BTreeMap::new(),
                },
            },
            &ProcessCommandRunner,
        )
        .expect_err("native export should reject derivation overrides");

        assert!(
            matches!(error, Error::Validation(message) if message.contains("native identities reject derivation overrides"))
        );
        let _ = fs::remove_dir_all(root_dir);
    }

    #[test]
    fn export_loads_profile_and_writes_native_public_key() {
        let root_dir = unique_temp_path("export-native-public-key");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let mut identity = Identity {
            schema_version: crate::model::IDENTITY_SCHEMA_VERSION,
            name: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign, UseCase::Verify],
            mode: IdentityModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            defaults: crate::model::IdentityDerivationDefaults::default(),
            storage: crate::model::IdentityStorage {
                state_layout: state_layout.clone(),
                identity_path: state_layout.identity_path("prod-signer"),
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
            &mut identity,
            "prod-signer-signing-key",
            "0x81010002",
            &handle_path,
        );
        identity.persist().expect("persist identity");

        let output_path = root_dir.join("custom").join("prod-signer.der");
        let result = export_native_public_key_with_runner(
            &identity,
            Some(output_path.as_path()),
            Format::Der,
            &FakeNativeExportRunner::success(example_spki_der()),
        )
        .expect("native export should succeed");

        assert_eq!(result.identity, "prod-signer");
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

        let identity = Identity::new(
            "seed-ed25519".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::Ssh],
            IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout,
        );
        let seed = vec![0x11; 32];
        let output_path = root_dir.join("exports").join("seed-ed25519.der");

        let result = export_seed_public_key_with_backend(
            &identity,
            Some(output_path.as_path()),
            Format::Der,
            &FakeSeedExportBackend::new(seed.clone()),
            &HkdfSha256SeedDeriver,
        )
        .expect("seed ed25519 export should succeed");

        let expected = expected_seed_public_key_der(
            &seed,
            seed_public_key_derivation_spec(&identity).expect("seed ed25519 spec"),
            Algorithm::Ed25519,
        );

        assert_eq!(result.identity, "seed-ed25519");
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

        let identity = Identity::new(
            "seed-secp256k1".to_string(),
            Algorithm::Secp256k1,
            vec![UseCase::Sign],
            IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout,
        );
        let seed = vec![0x22; 32];
        let output_path = root_dir.join("exports").join("seed-secp256k1.der");

        let result = export_seed_public_key_with_backend(
            &identity,
            Some(output_path.as_path()),
            Format::Der,
            &FakeSeedExportBackend::new(seed.clone()),
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secp256k1 export should succeed");

        let expected = expected_seed_public_key_der(
            &seed,
            seed_public_key_derivation_spec(&identity).expect("secp256k1 export spec"),
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

        let identity = Identity::new(
            "seed-p256".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign],
            IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout,
        );
        let seed = vec![0x33; 32];
        let output_path = root_dir.join("exports").join("seed-p256.der");

        let result = export_seed_public_key_with_backend(
            &identity,
            Some(output_path.as_path()),
            Format::Der,
            &FakeSeedExportBackend::new(seed.clone()),
            &HkdfSha256SeedDeriver,
        )
        .expect("seed p256 export should succeed");

        let expected = expected_seed_public_key_der(
            &seed,
            seed_public_key_derivation_spec(&identity).expect("p256 export spec"),
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
    fn export_writes_seed_secp256k1_ethereum_address() {
        let root_dir = unique_temp_path("export-seed-secp256k1-eth");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let identity = Identity::new(
            "seed-secp256k1".to_string(),
            Algorithm::Secp256k1,
            vec![UseCase::Sign],
            IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout,
        );
        let seed = vec![0x22; 32];
        let output_path = root_dir.join("exports").join("seed-secp256k1.eth.txt");

        let result = export_seed_public_key_with_backend(
            &identity,
            Some(output_path.as_path()),
            Format::Eth,
            &FakeSeedExportBackend::new(seed.clone()),
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secp256k1 ethereum address export should succeed");

        let expected = expected_ethereum_address(
            &seed,
            seed_public_key_derivation_spec(&identity).expect("secp256k1 export spec"),
            Algorithm::Secp256k1,
        );

        assert_eq!(result.artifact.format, ExportFormat::Eth);
        assert_eq!(
            fs::read_to_string(&result.artifact.path).expect("ethereum address output"),
            expected
        );

        fs::remove_dir_all(root_dir).expect("temporary secp256k1 export state should be removed");
    }

    #[test]
    fn export_rejects_p256_ethereum_address() {
        let root_dir = unique_temp_path("export-seed-p256-eth-rejected");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let identity = Identity::new(
            "seed-p256".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign],
            IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout,
        );

        let error = export_seed_public_key_with_backend(
            &identity,
            Some(root_dir.join("exports").join("seed-p256.eth.txt").as_path()),
            Format::Eth,
            &FakeSeedExportBackend::new(vec![0x33; 32]),
            &HkdfSha256SeedDeriver,
        )
        .expect_err("p256 ethereum address export should fail");

        assert!(matches!(error, Error::Validation(message) if message.contains("secp256k1")));
        let _ = fs::remove_dir_all(root_dir);
    }

    #[test]
    fn export_native_public_key_supports_spki_pem_output() {
        let root_dir = unique_temp_path("export-native-public-key-pem");
        let (identity, _) = persisted_native_export_profile(&root_dir);

        let output_path = root_dir.join("custom").join("prod-signer.pem");
        let result = export_native_public_key_with_runner(
            &identity,
            Some(output_path.as_path()),
            Format::Pem,
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
        let (identity, _) = persisted_native_export_profile(&root_dir);

        let output_path = root_dir.join("custom").join("prod-signer.hex");
        let result = export_native_public_key_with_runner(
            &identity,
            Some(output_path.as_path()),
            Format::Hex,
            &FakeNativeExportRunner::success(example_spki_der()),
        )
        .expect("native hex export should succeed");

        assert_eq!(result.artifact.format, ExportFormat::Hex);
        let expected_raw =
            crate::ops::native::subprocess::extract_p256_sec1_from_spki_der(&example_spki_der())
                .expect("sec1 public bytes");
        assert_eq!(
            fs::read_to_string(&result.artifact.path).expect("hex output"),
            hex_encode(&expected_raw)
        );

        fs::remove_dir_all(root_dir).expect("temporary native export state should be removed");
    }

    #[test]
    fn export_native_public_key_supports_openssh_output() {
        let root_dir = unique_temp_path("export-native-public-key-openssh");
        let (identity, _) = persisted_native_export_profile(&root_dir);

        let result = export_native_public_key_with_runner(
            &identity,
            None,
            Format::Openssh,
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
    fn export_no_longer_rejects_prf_public_key_requests_on_policy_only() {
        let root_dir = unique_temp_path("export-prf-public-key");
        let identity = Identity::new(
            "prf-default".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Sign],
            IdentityModeResolution {
                requested: ModePreference::Prf,
                resolved: Mode::Prf,
                reasons: vec!["prf requested".to_string()],
            },
            StateLayout::new(root_dir.clone()),
        );
        identity.persist().expect("persist identity");

        let error = export(&ExportRequest {
            identity: "prf-default".to_string(),
            kind: ExportKind::PublicKey,
            output: None,
            format: None,
            state_dir: Some(root_dir.clone()),
            reason: None,
            confirm: false,
            derivation: DerivationOverrides::default(),
        })
        .expect_err("prf export still needs provisioned PRF root material in tests");

        assert!(
            !matches!(error, Error::PolicyRefusal(message) if message.contains("PRF mode")),
            "PRF public-key export should no longer be rejected just because the identity is PRF-backed"
        );

        fs::remove_dir_all(root_dir).expect("temporary prf export state should be removed");
    }

    #[test]
    fn export_prf_public_key_renders_derived_child_key() {
        let root_dir = unique_temp_path("export-prf-derived-public-key");
        let identity =
            persisted_prf_export_identity(&root_dir, Algorithm::P256, vec![UseCase::Sign]);
        let output_path = root_dir.join("exports").join("prf-box.spki.der");

        let result = export_public_key_with_runner(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::PublicKey,
                output: Some(output_path.clone()),
                format: Some(Format::Der),
                state_dir: Some(root_dir.clone()),
                reason: None,
                confirm: false,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"tpm-prf-material"),
        )
        .expect("prf public-key export");

        assert_eq!(result.mode, Mode::Prf);
        assert_eq!(result.kind, ExportKind::PublicKey);
        assert_eq!(result.artifact.path, output_path);
        assert!(
            !fs::read(&result.artifact.path)
                .expect("exported public key")
                .is_empty()
        );

        fs::remove_dir_all(root_dir).expect("cleanup");
    }

    #[test]
    fn export_secret_key_and_keypair_require_export_secret_confirm_and_reason() {
        let root_dir = unique_temp_path("export-prf-secret-policy");
        let base_identity =
            persisted_prf_export_identity(&root_dir, Algorithm::Ed25519, vec![UseCase::Sign]);
        let with_export_secret = persisted_prf_export_identity(
            &root_dir,
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::ExportSecret],
        );
        let runner = RecordingPrfRunner::new(b"tpm-prf-material");

        let missing_use = export_secret_key_with_runner(
            &base_identity,
            &ExportRequest {
                identity: base_identity.name.clone(),
                kind: ExportKind::SecretKey,
                output: None,
                format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("backup".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &runner,
        )
        .expect_err("missing export-secret should fail");
        assert!(
            matches!(missing_use, Error::PolicyRefusal(message) if message.contains("use=export-secret"))
        );

        let missing_confirm = export_secret_key_with_runner(
            &with_export_secret,
            &ExportRequest {
                identity: with_export_secret.name.clone(),
                kind: ExportKind::SecretKey,
                output: None,
                format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("backup".to_string()),
                confirm: false,
                derivation: DerivationOverrides::default(),
            },
            &runner,
        )
        .expect_err("missing confirm should fail");
        assert!(
            matches!(missing_confirm, Error::Validation(message) if message.contains("--confirm"))
        );

        let missing_reason = export_keypair_with_runner(
            &with_export_secret,
            &ExportRequest {
                identity: with_export_secret.name.clone(),
                kind: ExportKind::Keypair,
                output: None,
                format: None,
                state_dir: Some(root_dir.clone()),
                reason: None,
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &runner,
        )
        .expect_err("missing reason should fail");
        assert!(
            matches!(missing_reason, Error::Validation(message) if message.contains("--reason"))
        );

        fs::remove_dir_all(root_dir).expect("cleanup");
    }

    #[test]
    fn export_prf_secret_key_and_keypair_succeed_when_policy_requirements_are_met() {
        let root_dir = unique_temp_path("export-prf-secret-success");
        let identity = persisted_prf_export_identity(
            &root_dir,
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::ExportSecret],
        );
        let runner = RecordingPrfRunner::new(b"tpm-prf-material");

        let secret_result = export_secret_key_with_runner(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::SecretKey,
                output: None,
                format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("backup".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &runner,
        )
        .expect("secret-key export");
        assert_eq!(secret_result.kind, ExportKind::SecretKey);
        assert!(
            !fs::read_to_string(&secret_result.artifact.path)
                .expect("secret-key output")
                .trim()
                .is_empty()
        );

        let keypair_result = export_keypair_with_runner(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::Keypair,
                output: None,
                format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("hardware migration".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &runner,
        )
        .expect("keypair export");
        assert_eq!(keypair_result.kind, ExportKind::Keypair);
        let payload: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&keypair_result.artifact.path).expect("keypair output"),
        )
        .expect("parse keypair json");
        assert_eq!(payload["identity"], identity.name);
        assert_eq!(payload["private_key"]["format"], "pkcs8-pem");
        assert_eq!(payload["public_key"]["format"], "spki-pem");
        assert!(
            payload["private_key"]["value"]
                .as_str()
                .expect("secret pem")
                .contains("BEGIN PRIVATE KEY")
        );
        assert!(
            payload["public_key"]["value"]
                .as_str()
                .expect("public pem")
                .contains("BEGIN PUBLIC KEY")
        );

        fs::remove_dir_all(root_dir).expect("cleanup");
    }

    #[test]
    fn export_seed_secret_key_and_keypair_require_export_secret() {
        let root_dir = unique_temp_path("export-seed-secret-policy");
        let identity =
            persisted_seed_export_identity(&root_dir, Algorithm::Ed25519, vec![UseCase::Sign]);
        let backend = FakeSeedExportBackend::new(vec![0x33; 32]);
        let error = export_secret_key_with_dependencies(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::SecretKey,
                output: None,
                format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("backup".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect_err("seed secret export without use bit should fail");

        assert!(
            matches!(error, Error::PolicyRefusal(message) if message.contains("use=export-secret"))
        );
        fs::remove_dir_all(root_dir).expect("cleanup");
    }

    #[test]
    fn export_seed_secret_key_and_keypair_succeed_when_policy_requirements_are_met() {
        let root_dir = unique_temp_path("export-seed-secret-success");
        let identity = persisted_seed_export_identity(
            &root_dir,
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::ExportSecret],
        );
        let backend = FakeSeedExportBackend::new(vec![0x55; 32]);

        let secret_result = export_secret_key_with_dependencies(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::SecretKey,
                output: None,
                format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("backup".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secret-key export");
        assert_eq!(secret_result.kind, ExportKind::SecretKey);
        assert!(
            !fs::read_to_string(&secret_result.artifact.path)
                .expect("seed secret output")
                .trim()
                .is_empty()
        );

        let keypair_result = export_keypair_with_dependencies(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::Keypair,
                output: None,
                format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("hardware migration".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed keypair export");
        assert_eq!(keypair_result.kind, ExportKind::Keypair);
        let payload: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&keypair_result.artifact.path).expect("seed keypair output"),
        )
        .expect("parse seed keypair json");
        assert_eq!(payload["identity"], identity.name);

        fs::remove_dir_all(root_dir).expect("cleanup");
    }

    #[test]
    fn export_seed_eth_formats_behave_as_requested() {
        let root_dir = unique_temp_path("export-seed-eth-formats");
        let identity = persisted_seed_export_identity(
            &root_dir,
            Algorithm::Secp256k1,
            vec![UseCase::Sign, UseCase::ExportSecret],
        );
        let backend = FakeSeedExportBackend::new(vec![0x66; 32]);

        let secret_eth = export_secret_key_with_dependencies(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::SecretKey,
                output: Some(root_dir.join("exports").join("secret.eth.txt")),
                format: Some(Format::Eth),
                state_dir: Some(root_dir.clone()),
                reason: Some("backup".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secret-key eth export");
        let secret_hex = export_secret_key_with_dependencies(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::SecretKey,
                output: Some(root_dir.join("exports").join("secret.hex")),
                format: Some(Format::Hex),
                state_dir: Some(root_dir.clone()),
                reason: Some("backup".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secret-key hex export");
        assert_eq!(secret_eth.artifact.format, ExportFormat::Hex);
        assert_eq!(
            fs::read_to_string(&secret_eth.artifact.path).expect("eth secret output"),
            fs::read_to_string(&secret_hex.artifact.path).expect("hex secret output")
        );

        let keypair_result = export_keypair_with_dependencies(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::Keypair,
                output: Some(root_dir.join("exports").join("keypair.eth.json")),
                format: Some(Format::Eth),
                state_dir: Some(root_dir.clone()),
                reason: Some("migration".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed keypair eth export");

        let payload: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&keypair_result.artifact.path).expect("eth keypair output"),
        )
        .expect("parse eth keypair json");
        assert_eq!(payload["private_key"]["format"], "hex");
        assert_eq!(payload["public_key"]["format"], "hex");
        assert_eq!(payload["address"]["format"], "eth");

        let effective = crate::ops::shared::resolve_effective_derivation_inputs(
            &identity,
            &DerivationOverrides::default(),
        )
        .expect("effective derivation inputs");
        let expected_address = expected_ethereum_address(
            &[0x66; 32],
            crate::ops::shared::identity_key_spec(identity.algorithm, &effective)
                .expect("identity key spec"),
            Algorithm::Secp256k1,
        );
        assert_eq!(payload["address"]["value"], expected_address);

        fs::remove_dir_all(root_dir).expect("cleanup");
    }

    #[test]
    fn export_native_secret_key_remains_forbidden() {
        let root_dir = unique_temp_path("export-native-secret-key");
        let (identity, _) = persisted_native_export_profile(&root_dir);
        let error = export_secret_key_with_runner(
            &identity,
            &ExportRequest {
                identity: identity.name.clone(),
                kind: ExportKind::SecretKey,
                output: None,
                format: None,
                state_dir: Some(root_dir.clone()),
                reason: Some("backup".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
        )
        .expect_err("native secret export should fail");

        assert!(matches!(error, Error::PolicyRefusal(message) if message.contains("native mode")));
        fs::remove_dir_all(root_dir).expect("cleanup");
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

    #[derive(Clone)]
    struct SlowNativeSetupRunner {
        calls: Arc<Mutex<Vec<CommandInvocation>>>,
        createprimary_delay: Duration,
    }

    impl SlowNativeSetupRunner {
        fn new(createprimary_delay: Duration) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                createprimary_delay,
            }
        }

        fn calls(&self) -> Vec<CommandInvocation> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl CommandRunner for SlowNativeSetupRunner {
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
                    thread::sleep(self.createprimary_delay);
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

    #[derive(Clone)]
    struct HandleCollisionNativeSetupRunner {
        calls: Arc<Mutex<Vec<CommandInvocation>>>,
        handles: Arc<Mutex<BTreeSet<String>>>,
        collision_emitted: Arc<AtomicBool>,
    }

    impl HandleCollisionNativeSetupRunner {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                handles: Arc::new(Mutex::new(BTreeSet::from([
                    "0x81010000".to_string(),
                    "0x81010001".to_string(),
                ]))),
                collision_emitted: Arc::new(AtomicBool::new(false)),
            }
        }

        fn paths_for(&self, program: &str, flag: &str) -> Vec<PathBuf> {
            self.calls
                .lock()
                .expect("calls lock")
                .iter()
                .filter(|invocation| invocation.program == program)
                .map(|invocation| pathbuf_arg(invocation, flag))
                .collect()
        }
    }

    impl CommandRunner for HandleCollisionNativeSetupRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.calls
                .lock()
                .expect("calls lock")
                .push(invocation.clone());

            match invocation.program.as_str() {
                "tpm2_getcap" => CommandOutput {
                    exit_code: Some(0),
                    stdout: render_persistent_handles(&self.handles.lock().expect("handles lock")),
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
                    let persistent_handle = invocation
                        .args
                        .last()
                        .cloned()
                        .expect("persistent handle argument");
                    if !self.collision_emitted.swap(true, Ordering::SeqCst) {
                        self.handles
                            .lock()
                            .expect("handles lock")
                            .insert(persistent_handle);
                        return CommandOutput {
                            exit_code: Some(1),
                            stdout: String::new(),
                            stderr: "persistent handle collision".to_string(),
                            error: None,
                        };
                    }

                    self.handles
                        .lock()
                        .expect("handles lock")
                        .insert(persistent_handle);
                    write_output_flag(invocation, "-o", b"serialized-handle");
                    success_output()
                }
                other => panic!("unexpected command {other}"),
            }
        }
    }

    #[derive(Clone)]
    struct PersistFailureNativeSetupRunner {
        calls: Arc<Mutex<Vec<CommandInvocation>>>,
        identity_path: PathBuf,
        rollback_attempted: Arc<AtomicBool>,
    }

    impl PersistFailureNativeSetupRunner {
        fn new(identity_path: PathBuf) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                identity_path,
                rollback_attempted: Arc::new(AtomicBool::new(false)),
            }
        }

        fn rollback_was_attempted(&self) -> bool {
            self.rollback_attempted.load(Ordering::SeqCst)
        }
    }

    impl CommandRunner for PersistFailureNativeSetupRunner {
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
                    if invocation.args.iter().any(|arg| arg == "-o") {
                        write_output_flag(invocation, "-o", b"serialized-handle");
                        fs::create_dir_all(&self.identity_path)
                            .expect("create directory that blocks identity persistence");
                    } else {
                        self.rollback_attempted.store(true, Ordering::SeqCst);
                    }
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

    #[derive(Clone)]
    struct RecordingPrfRunner {
        raw_output: Vec<u8>,
    }

    impl RecordingPrfRunner {
        fn new(raw_output: &[u8]) -> Self {
            Self {
                raw_output: raw_output.to_vec(),
            }
        }
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

    impl CommandRunner for RecordingPrfRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            let output_path = pathbuf_arg(invocation, "-o");
            fs::write(output_path, &self.raw_output).expect("write fake prf output");

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
                    object_label: request.identity.storage.object_label.clone(),
                    bytes,
                });

            let object_dir = self
                .objects_dir
                .join(&request.identity.storage.object_label);
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
            _profile: &SeedIdentity,
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
            unreachable!("seed sealing is not used in secret export tests")
        }

        fn unseal_seed(
            &self,
            _profile: &crate::ops::seed::SeedIdentity,
            _auth_source: &crate::ops::seed::SeedOpenAuthSource,
        ) -> Result<crate::ops::seed::SeedMaterial> {
            Ok(secrecy::SecretBox::new(Box::new(self.seed.clone())))
        }
    }

    fn persisted_native_export_profile(root_dir: &Path) -> (Identity, PathBuf) {
        let state_layout = StateLayout::new(root_dir.to_path_buf());
        state_layout.ensure_dirs().expect("state dirs");

        let mut identity = Identity {
            schema_version: crate::model::IDENTITY_SCHEMA_VERSION,
            name: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign, UseCase::Verify],
            mode: IdentityModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            defaults: crate::model::IdentityDerivationDefaults::default(),
            storage: crate::model::IdentityStorage {
                state_layout: state_layout.clone(),
                identity_path: state_layout.identity_path("prod-signer"),
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
            &mut identity,
            "prod-signer-signing-key",
            "0x81010002",
            &handle_path,
        );
        identity.persist().expect("persist identity");

        (identity, handle_path)
    }

    fn persisted_prf_export_identity(
        root_dir: &Path,
        algorithm: Algorithm,
        uses: Vec<UseCase>,
    ) -> Identity {
        let state_layout = StateLayout::new(root_dir.to_path_buf());
        state_layout.ensure_dirs().expect("state dirs");

        let mut identity = Identity::new(
            "prf-box".to_string(),
            algorithm,
            uses,
            IdentityModeResolution {
                requested: ModePreference::Prf,
                resolved: Mode::Prf,
                reasons: vec!["prf requested".to_string()],
            },
            state_layout,
        );
        identity.metadata.insert(
            PRF_CONTEXT_PATH_METADATA_KEY.to_string(),
            format!("objects/{}/prf-root.ctx", identity.name),
        );
        identity.persist().expect("persist prf identity");
        identity
    }

    fn persisted_seed_export_identity(
        root_dir: &Path,
        algorithm: Algorithm,
        uses: Vec<UseCase>,
    ) -> Identity {
        let state_layout = StateLayout::new(root_dir.to_path_buf());
        state_layout.ensure_dirs().expect("state dirs");

        let identity = Identity::new(
            "seed-box".to_string(),
            algorithm,
            uses,
            IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            state_layout,
        );
        identity.persist().expect("persist seed identity");
        identity
    }

    fn assert_zeroizing_array(_: &Zeroizing<[u8; 32]>) {}

    fn assert_zeroizing_vec(_: &Zeroizing<Vec<u8>>) {}

    #[test]
    fn seed_valid_ec_scalar_bytes_standalone_retries_invalid_p256_seed_in_zeroizing_storage() {
        let invalid_scalar = [0_u8; 32];

        let scalar = seed_valid_ec_scalar_bytes_standalone(&invalid_scalar, Algorithm::P256)
            .expect("scalar should be retried");

        assert_zeroizing_array(&scalar);
        assert_ne!(scalar.as_ref(), &invalid_scalar);
        assert!(p256::SecretKey::from_slice(scalar.as_ref()).is_ok());
    }

    #[test]
    fn render_keypair_json_bytes_preserves_openssh_secret_and_public_formats() {
        let root_dir = unique_temp_path("render-keypair-json-openssh");
        let identity = persisted_seed_export_identity(
            &root_dir,
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::ExportSecret, UseCase::Ssh],
        );
        let material = [0x24_u8; 32];

        let payload = render_keypair_json_bytes(&identity, Format::Openssh, &material)
            .expect("rendered keypair json");

        assert_zeroizing_vec(&payload);
        let payload: serde_json::Value =
            serde_json::from_slice(payload.as_ref()).expect("parse keypair json");
        assert_eq!(
            payload["mode"],
            serde_json::Value::String("seed".to_string())
        );
        assert_eq!(
            payload["private_key"]["format"],
            serde_json::Value::String("openssh".to_string())
        );
        assert_eq!(
            payload["public_key"]["format"],
            serde_json::Value::String("openssh".to_string())
        );
        assert!(
            payload["private_key"]["value"]
                .as_str()
                .expect("private key")
                .contains("BEGIN OPENSSH PRIVATE KEY")
        );
        assert!(
            payload["public_key"]["value"]
                .as_str()
                .expect("public key")
                .starts_with("ssh-ed25519 ")
        );

        fs::remove_dir_all(root_dir).expect("cleanup");
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

    fn expected_ethereum_address(
        seed: &[u8],
        spec: DerivationSpec,
        algorithm: Algorithm,
    ) -> String {
        let derived = HkdfSha256SeedDeriver
            .derive(
                &secrecy::SecretBox::new(Box::new(seed.to_vec())),
                &SoftwareSeedDerivationRequest {
                    spec,
                    output_bytes: 32,
                },
            )
            .expect("seed derivation for expected ethereum address");
        let secret_bytes: [u8; 32] = derived
            .expose_secret()
            .as_slice()
            .try_into()
            .expect("expected 32-byte derived key material");

        let raw_public = match algorithm {
            Algorithm::Ed25519 => panic!("eth does not apply to ed25519"),
            Algorithm::Secp256k1 => k256::SecretKey::from_slice(&secret_bytes)
                .expect("valid secp256k1 scalar")
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            Algorithm::P256 => p256::SecretKey::from_slice(&secret_bytes)
                .expect("valid p256 scalar")
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        };

        ethereum_address_from_raw_public_bytes(&raw_public).expect("ethereum address")
    }

    fn render_persistent_handles(handles: &BTreeSet<String>) -> String {
        let mut output = String::new();
        for handle in handles {
            output.push_str("- ");
            output.push_str(handle);
            output.push('\n');
        }
        output
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
