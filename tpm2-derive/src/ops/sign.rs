use std::fs;
use std::path::PathBuf;

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::backend::{CommandInvocation, CommandRunner, ProcessCommandRunner};
#[cfg(test)]
use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, DerivationOverrides, Diagnostic, Identity, Mode, SignRequest, UseCase,
};
use crate::ops::keygen::{derive_identity_key_material_with_defaults, hex_encode};
use crate::ops::native::subprocess::{
    NativeAuthSource, NativeKeyLocator, NativePostProcessAction, NativeSignArtifacts,
    NativeSignOptions, NativeSignPlan, plan_sign,
};
use crate::ops::native::{
    DigestAlgorithm, NativeKeyRef, NativeSignRequest, NativeSignatureFormat, NativeSignatureScheme,
};
#[cfg(test)]
use crate::ops::seed::{
    SeedBackend, SeedIdentity, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, open_and_derive, plan_open,
    seed_profile_from_profile,
};
#[cfg(test)]
use secrecy::ExposeSecret;

use super::shared::{classify_native_command_failure, ensure_dir, load_input_bytes};

#[cfg(test)]
pub(crate) const SEED_SIGNING_KEY_NAMESPACE: &str = "tpm2-derive.sign";
#[cfg(test)]
pub(crate) const SEED_SIGNING_KEY_PATH: &str = "m/signature/default";

#[derive(Debug, Clone, Serialize)]
pub struct NativeSignOperationResult {
    pub identity: Identity,
    pub request: SignRequest,
    pub mode: Mode,
    pub state: String,
    pub digest_algorithm: DigestAlgorithm,
    pub input_bytes: usize,
    pub digest_path: PathBuf,
    pub output_path: PathBuf,
    pub signature_bytes_written: Option<usize>,
    pub plan: NativeSignPlan,
}

#[derive(Debug, Clone, Serialize)]
pub struct DerivedSignOperationResult {
    pub identity: Identity,
    pub request: SignRequest,
    pub mode: Mode,
    pub digest_algorithm: DigestAlgorithm,
    pub digest_hex: String,
    pub input_bytes: usize,
    pub signature_bytes: usize,
    pub signature_hex: String,
    pub signature_format: SeedSignatureFormat,
}

#[derive(Debug, Clone)]
pub enum SignOperationResult {
    Native(NativeSignOperationResult),
    Derived(DerivedSignOperationResult),
}

#[derive(Debug, Clone, Copy, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedSignatureFormat {
    Der,
    Raw,
}

#[derive(Debug, Clone)]
pub struct StagedNativeSign {
    pub digest_algorithm: DigestAlgorithm,
    pub input_bytes: usize,
    pub digest_path: PathBuf,
    pub output_path: PathBuf,
    pub plan: NativeSignPlan,
    pub ready_for_execution: bool,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn execute_with_defaults(
    identity: &Identity,
    request: &SignRequest,
    derivation: &DerivationOverrides,
) -> Result<(SignOperationResult, Vec<Diagnostic>)> {
    let runner = ProcessCommandRunner;
    execute_with_runner(identity, request, derivation, &runner)
}

pub fn execute_with_runner<R>(
    identity: &Identity,
    request: &SignRequest,
    derivation: &DerivationOverrides,
    runner: &R,
) -> Result<(SignOperationResult, Vec<Diagnostic>)>
where
    R: CommandRunner,
{
    match identity.mode.resolved {
        Mode::Native => {
            let staged = stage_native_sign(request, identity)?;
            let mut diagnostics = staged.diagnostics.clone();
            let signature_bytes_written = if staged.ready_for_execution {
                let bytes_written = execute_native_sign_plan_with_runner(&staged.plan, runner)?;
                diagnostics.push(Diagnostic::info(
                    "native-sign-executed",
                    format!(
                        "executed native sign and wrote {} bytes to '{}'",
                        bytes_written,
                        staged.output_path.display()
                    ),
                ));
                Some(bytes_written)
            } else {
                None
            };

            Ok((
                SignOperationResult::Native(NativeSignOperationResult {
                    identity: identity.clone(),
                    request: request.clone(),
                    mode: Mode::Native,
                    state: if signature_bytes_written.is_some() {
                        "executed".to_string()
                    } else {
                        "planned".to_string()
                    },
                    digest_algorithm: staged.digest_algorithm,
                    input_bytes: staged.input_bytes,
                    digest_path: staged.digest_path,
                    output_path: staged.output_path,
                    signature_bytes_written,
                    plan: staged.plan,
                }),
                diagnostics,
            ))
        }
        Mode::Seed | Mode::Prf => sign_derived_identity(request, identity, derivation, runner)
            .map(|(result, diagnostics)| (SignOperationResult::Derived(result), diagnostics)),
    }
}

fn sign_derived_identity<R>(
    request: &SignRequest,
    identity: &Identity,
    derivation: &DerivationOverrides,
    runner: &R,
) -> Result<(DerivedSignOperationResult, Vec<Diagnostic>)>
where
    R: CommandRunner,
{
    if !identity.uses.contains(&UseCase::Sign) {
        return Err(Error::Unsupported(format!(
            "identity '{}' is not configured with sign use",
            identity.name
        )));
    }

    let input_bytes = load_sign_input(&request.input)?;
    if input_bytes.is_empty() {
        return Err(Error::Validation(
            "sign input must not be empty".to_string(),
        ));
    }

    let derived = derive_identity_key_material_with_defaults(identity, derivation, runner)?;
    let digest = Sha256::digest(&input_bytes).to_vec();
    let diagnostics = vec![Diagnostic::info(
        "derived-signer-material",
        format!(
            "derived {} bytes of {:?} signing key material from {:?} backing using the effective derivation inputs",
            derived.len(),
            identity.algorithm,
            identity.mode.resolved,
        ),
    )];

    let (signature_bytes, signature_format) = match identity.algorithm {
        Algorithm::Ed25519 => sign_seed_ed25519(&input_bytes, &derived)?,
        Algorithm::P256 => sign_seed_p256(&input_bytes, &derived, identity)?,
        Algorithm::Secp256k1 => sign_seed_secp256k1(&input_bytes, &derived, identity)?,
    };

    Ok((
        DerivedSignOperationResult {
            identity: identity.clone(),
            request: request.clone(),
            mode: identity.mode.resolved,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest_hex: hex_encode(&digest),
            input_bytes: input_bytes.len(),
            signature_bytes: signature_bytes.len(),
            signature_hex: hex_encode(&signature_bytes),
            signature_format,
        },
        diagnostics,
    ))
}

#[cfg(test)]
pub(crate) fn sign_seed_with_backend<B, D>(
    request: &SignRequest,
    identity: &Identity,
    backend: &B,
    deriver: &D,
) -> Result<(DerivedSignOperationResult, Vec<Diagnostic>)>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    if !identity.uses.contains(&UseCase::Sign) {
        return Err(Error::Unsupported(format!(
            "identity '{}' is not configured with sign use",
            identity.name
        )));
    }

    let input_bytes = load_sign_input(&request.input)?;
    if input_bytes.is_empty() {
        return Err(Error::Validation(
            "sign input must not be empty".to_string(),
        ));
    }

    let seed_request = seed_sign_open_request(identity)?;
    let seed_plan = plan_open(&seed_request)?;
    let digest = Sha256::digest(&input_bytes).to_vec();
    let derived = open_and_derive(backend, deriver, &seed_request)?;
    let diagnostics =
        seed_sign_diagnostics(identity, &seed_plan.warnings, derived.expose_secret().len());

    let (signature_bytes, signature_format) = match identity.algorithm {
        Algorithm::Ed25519 => sign_seed_ed25519(&input_bytes, derived.expose_secret())?,
        Algorithm::P256 => sign_seed_p256(&input_bytes, derived.expose_secret(), identity)?,
        Algorithm::Secp256k1 => {
            sign_seed_secp256k1(&input_bytes, derived.expose_secret(), identity)?
        }
    };

    Ok((
        DerivedSignOperationResult {
            identity: identity.clone(),
            request: request.clone(),
            mode: Mode::Seed,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest_hex: hex_encode(&digest),
            input_bytes: input_bytes.len(),
            signature_bytes: signature_bytes.len(),
            signature_hex: hex_encode(&signature_bytes),
            signature_format,
        },
        diagnostics,
    ))
}

pub(crate) fn sign_seed_ed25519(
    input_bytes: &[u8],
    derived_seed: &[u8],
) -> Result<(Vec<u8>, SeedSignatureFormat)> {
    let seed_bytes: [u8; 32] = derived_seed.try_into().map_err(|_| {
        Error::Internal(
            "seed sign ed25519 derivation produced a non-32-byte seed unexpectedly".to_string(),
        )
    })?;
    let signing_key = Ed25519SigningKey::from_bytes(&seed_bytes);
    let signature = signing_key.sign(input_bytes);
    Ok((signature.to_bytes().to_vec(), SeedSignatureFormat::Raw))
}

pub(crate) fn sign_seed_p256(
    input_bytes: &[u8],
    derived_seed: &[u8],
    identity: &Identity,
) -> Result<(Vec<u8>, SeedSignatureFormat)> {
    let scalar_bytes =
        crate::ops::seed_valid_ec_scalar_bytes_standalone(derived_seed, identity.algorithm)?;
    let signing_key = P256SigningKey::from_bytes((&scalar_bytes).into()).map_err(|error| {
        Error::Internal(format!(
            "failed to materialize p256 seed signing key for identity '{}': {error}",
            identity.name
        ))
    })?;
    let signature: P256Signature = <P256SigningKey as p256::ecdsa::signature::Signer<
        P256Signature,
    >>::sign(&signing_key, input_bytes);
    Ok((
        signature.to_der().as_bytes().to_vec(),
        SeedSignatureFormat::Der,
    ))
}

pub(crate) fn sign_seed_secp256k1(
    input_bytes: &[u8],
    derived_seed: &[u8],
    identity: &Identity,
) -> Result<(Vec<u8>, SeedSignatureFormat)> {
    let scalar_bytes =
        crate::ops::seed_valid_ec_scalar_bytes_standalone(derived_seed, identity.algorithm)?;
    let signing_key = K256SigningKey::from_bytes((&scalar_bytes).into()).map_err(|error| {
        Error::Internal(format!(
            "failed to materialize secp256k1 seed signing key for identity '{}': {error}",
            identity.name
        ))
    })?;
    let signature: K256Signature = <K256SigningKey as k256::ecdsa::signature::Signer<
        K256Signature,
    >>::sign(&signing_key, input_bytes);
    Ok((
        signature.to_der().as_bytes().to_vec(),
        SeedSignatureFormat::Der,
    ))
}

#[cfg(test)]
pub(crate) fn seed_sign_open_request(identity: &Identity) -> Result<SeedOpenRequest> {
    Ok(SeedOpenRequest {
        identity: seed_sign_profile(identity)?,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
            spec: seed_sign_derivation_spec(identity.algorithm)?,
            output_bytes: 32,
        }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    })
}

#[cfg(test)]
fn seed_sign_profile(identity: &Identity) -> Result<SeedIdentity> {
    if identity.mode.resolved != Mode::Seed {
        return Err(Error::Unsupported(format!(
            "identity '{}' did not resolve to seed mode",
            identity.name
        )));
    }

    seed_profile_from_profile(identity)
}

#[cfg(test)]
fn seed_sign_derivation_spec(algorithm: Algorithm) -> Result<DerivationSpec> {
    seed_signing_key_derivation_spec(algorithm)
}

#[cfg(test)]
fn seed_sign_diagnostics(
    identity: &Identity,
    warnings: &[Diagnostic],
    derived_bytes: usize,
) -> Vec<Diagnostic> {
    let mut diagnostics = warnings.to_vec();
    diagnostics.push(Diagnostic::info(
        "seed-signer-derived",
        format!(
            "derived {} bytes of {:?} signer material from sealed seed using {} {}",
            derived_bytes, identity.algorithm, SEED_SIGNING_KEY_NAMESPACE, SEED_SIGNING_KEY_PATH,
        ),
    ));
    diagnostics
}

#[cfg(test)]
pub(crate) fn seed_signing_key_derivation_spec(algorithm: Algorithm) -> Result<DerivationSpec> {
    let (algo_name, output_kind) = match algorithm {
        Algorithm::Ed25519 => ("ed25519", OutputKind::Ed25519Seed),
        Algorithm::P256 => ("p256", OutputKind::P256Scalar),
        Algorithm::Secp256k1 => ("secp256k1", OutputKind::Secp256k1Scalar),
    };

    Ok(DerivationSpec::V1(DerivationSpecV1::software_child_key(
        SEED_SIGNING_KEY_NAMESPACE,
        algo_name,
        SEED_SIGNING_KEY_PATH,
        output_kind,
    )?))
}

pub(crate) fn stage_native_sign(
    request: &SignRequest,
    identity: &Identity,
) -> Result<StagedNativeSign> {
    if identity.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native sign is currently wired only for p256 identities, found {:?}",
            identity.algorithm
        )));
    }

    if !identity.uses.contains(&UseCase::Sign) {
        return Err(Error::Unsupported(format!(
            "identity '{}' is not configured with sign use",
            identity.name
        )));
    }

    identity.storage.state_layout.ensure_dirs()?;

    let runtime_dir = identity
        .storage
        .state_layout
        .objects_dir
        .join(&identity.name)
        .join("native-sign");
    let output_dir = identity
        .storage
        .state_layout
        .exports_dir
        .join(&identity.name)
        .join("signatures");

    ensure_dir(&runtime_dir, "native sign runtime")?;
    ensure_dir(&output_dir, "native sign output")?;

    let input_bytes = load_sign_input(&request.input)?;
    if input_bytes.is_empty() {
        return Err(Error::Validation(
            "sign input must not be empty".to_string(),
        ));
    }

    let digest = Sha256::digest(&input_bytes).to_vec();
    let digest_path = runtime_dir.join("sha256.digest.bin");
    let plain_signature_path = runtime_dir.join("signature.p1363.bin");
    let output_path = output_dir.join("signature.der");
    fs::write(&digest_path, &digest).map_err(|error| {
        Error::State(format!(
            "failed to write staged sign digest '{}': {error}",
            digest_path.display()
        ))
    })?;

    let (locator, ready_for_execution, locator_diagnostics) = resolve_native_sign_locator(identity);
    let plan = plan_sign(
        &NativeSignRequest {
            key: NativeKeyRef {
                identity: identity.name.clone(),
                key_id: crate::ops::native_key_id(identity),
            },
            scheme: NativeSignatureScheme::Ecdsa,
            format: NativeSignatureFormat::Der,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest,
        },
        &NativeSignOptions {
            locator,
            auth: NativeAuthSource::Empty,
            artifacts: NativeSignArtifacts {
                digest_path: digest_path.clone(),
                signature_path: output_path.clone(),
                plain_signature_path: Some(plain_signature_path),
            },
        },
    )?;

    let mut diagnostics = plan.warnings.clone();
    diagnostics.extend(locator_diagnostics);

    Ok(StagedNativeSign {
        digest_algorithm: DigestAlgorithm::Sha256,
        input_bytes: input_bytes.len(),
        digest_path,
        output_path,
        plan,
        ready_for_execution,
        diagnostics,
    })
}

fn resolve_native_sign_locator(identity: &Identity) -> (NativeKeyLocator, bool, Vec<Diagnostic>) {
    if let Some(path) = crate::ops::metadata_path(
        identity,
        &[
            "native.serialized_handle_path",
            "native.serialized-handle-path",
        ],
    ) {
        if path.is_file() {
            return (
                NativeKeyLocator::SerializedHandle { path },
                true,
                Vec::new(),
            );
        }
    }

    if let Some(handle) = crate::ops::metadata_value(
        identity,
        &["native.persistent_handle", "native.persistent-handle"],
    ) {
        return (
            NativeKeyLocator::PersistentHandle { handle },
            true,
            Vec::new(),
        );
    }

    for path in crate::ops::native_handle_path_candidates(identity) {
        if path.is_file() {
            return (
                NativeKeyLocator::SerializedHandle { path },
                true,
                Vec::new(),
            );
        }
    }

    let missing_handle_path = crate::ops::metadata_path(
        identity,
        &[
            "native.serialized_handle_path",
            "native.serialized-handle-path",
        ],
    )
    .or_else(|| {
        crate::ops::native_handle_path_candidates(identity)
            .into_iter()
            .next()
    })
    .unwrap_or_else(|| {
        identity
            .storage
            .state_layout
            .objects_dir
            .join(format!("{}.handle", identity.name))
    });

    (
        NativeKeyLocator::SerializedHandle {
            path: missing_handle_path.clone(),
        },
        false,
        vec![Diagnostic::warning(
            "native-key-handle-missing",
            format!(
                "serialized native key handle '{}' is not present yet; sign returns a concrete plan and staged digest, and will execute once native setup material is present",
                missing_handle_path.display()
            ),
        )],
    )
}

pub(crate) fn execute_native_sign_plan_with_runner<R>(
    plan: &NativeSignPlan,
    runner: &R,
) -> Result<usize>
where
    R: CommandRunner,
{
    let output = runner.run(&CommandInvocation::new(
        &plan.command.program,
        plan.command.args.iter().cloned(),
    ));
    if output.error.is_some() || output.exit_code != Some(0) {
        return Err(classify_native_command_failure(
            &plan.command.program,
            &output,
        ));
    }

    let signature = finalize_native_signature_output(plan)?;
    Ok(signature.len())
}

fn finalize_native_signature_output(plan: &NativeSignPlan) -> Result<Vec<u8>> {
    match &plan.post_process {
        Some(NativePostProcessAction::P256PlainToDer {
            input_path,
            output_path,
        }) => {
            let plain_signature = fs::read(input_path).map_err(|error| {
                Error::State(format!(
                    "native sign completed but intermediate signature '{}' could not be read: {error}",
                    input_path.display()
                ))
            })?;
            let der_signature = crate::ops::native::subprocess::finalize_p256_signature(
                NativeSignatureFormat::Der,
                &plain_signature,
            )?;
            fs::write(output_path, &der_signature).map_err(|error| {
                Error::State(format!(
                    "failed to write DER signature '{}': {error}",
                    output_path.display()
                ))
            })?;
            let _ = fs::remove_file(input_path);
            Ok(der_signature)
        }
        Some(other) => Err(Error::Unsupported(format!(
            "native sign post-process action '{other:?}' is not wired for CLI execution"
        ))),
        None => fs::read(&plan.output_path).map_err(|error| {
            Error::State(format!(
                "native sign completed but output '{}' could not be read: {error}",
                plan.output_path.display()
            ))
        }),
    }
}

fn load_sign_input(input: &crate::model::InputSource) -> Result<Vec<u8>> {
    load_input_bytes(input, "sign input")
}
