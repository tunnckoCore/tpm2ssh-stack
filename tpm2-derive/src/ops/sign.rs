use std::fs;
use std::path::PathBuf;

use tempfile::{Builder as TempfileBuilder, TempDir};

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
    Algorithm, DerivationOverrides, Diagnostic, Format, Identity, Mode, SignRequest, UseCase,
};
use crate::ops::keygen::{derive_identity_key_material_with_defaults, hex_encode};
use crate::ops::native::subprocess::{
    NativeAuthSource, NativePostProcessAction, NativeSignArtifacts, NativeSignOptions,
    NativeSignPlan, plan_sign,
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

use super::shared::{
    BUFFERED_MESSAGE_INPUT_BYTES_LIMIT, classify_native_command_failure,
    encode_textual_output_bytes, ensure_derivation_overrides_allowed, ensure_dir,
    load_input_bytes_with_limit, write_output_file,
};

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
    pub output_format: Format,
    pub output_path: Option<PathBuf>,
    pub signature_bytes: Option<usize>,
    pub signature: Option<String>,
    pub signature_format: SeedSignatureFormat,
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
    pub output_format: Format,
    pub output_path: Option<PathBuf>,
    pub signature_bytes: usize,
    pub signature: Option<String>,
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

#[derive(Debug)]
pub struct StagedNativeSign {
    _workspace_dir: TempDir,
    pub digest_algorithm: DigestAlgorithm,
    pub input_bytes: usize,
    pub digest_path: PathBuf,
    pub artifact_path: PathBuf,
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
    ensure_derivation_overrides_allowed(identity, derivation)?;
    validate_sign_output_format(identity, request.format, request.output.as_deref())?;

    match identity.mode.resolved {
        Mode::Native => {
            let staged = stage_native_sign(request, identity)?;
            let mut diagnostics = staged.diagnostics.clone();
            let (signature_bytes, output_path, signature) = if staged.ready_for_execution {
                let signature_bytes = execute_native_sign_plan_with_runner(&staged.plan, runner)?;
                let (output_path, signature) = persist_formatted_signature(
                    identity,
                    request,
                    &signature_bytes,
                    Some(staged.artifact_path.as_path()),
                )?;
                diagnostics.push(Diagnostic::info(
                    "native-sign-executed",
                    format!(
                        "executed native sign and produced {} signature bytes",
                        signature_bytes.len()
                    ),
                ));
                (Some(signature_bytes.len()), output_path, signature)
            } else {
                (None, None, None)
            };

            Ok((
                SignOperationResult::Native(NativeSignOperationResult {
                    identity: identity.clone(),
                    request: request.clone(),
                    mode: Mode::Native,
                    state: if signature_bytes.is_some() {
                        "executed".to_string()
                    } else {
                        "planned".to_string()
                    },
                    digest_algorithm: staged.digest_algorithm,
                    input_bytes: staged.input_bytes,
                    digest_path: staged.digest_path,
                    output_format: request.format,
                    output_path,
                    signature_bytes,
                    signature,
                    signature_format: SeedSignatureFormat::Der,
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

    validate_sign_output_format(identity, request.format, request.output.as_deref())?;

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

    let (output_path, signature) =
        persist_formatted_signature(identity, request, &signature_bytes, None)?;

    Ok((
        DerivedSignOperationResult {
            identity: identity.clone(),
            request: request.clone(),
            mode: identity.mode.resolved,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest_hex: hex_encode(&digest),
            input_bytes: input_bytes.len(),
            output_format: request.format,
            output_path,
            signature_bytes: signature_bytes.len(),
            signature,
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

    validate_sign_output_format(identity, request.format, request.output.as_deref())?;

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

    let (output_path, signature) =
        persist_formatted_signature(identity, request, &signature_bytes, None)?;

    Ok((
        DerivedSignOperationResult {
            identity: identity.clone(),
            request: request.clone(),
            mode: Mode::Seed,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest_hex: hex_encode(&digest),
            input_bytes: input_bytes.len(),
            output_format: request.format,
            output_path,
            signature_bytes: signature_bytes.len(),
            signature,
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
    ensure_dir(&runtime_dir, "native sign runtime")?;
    let workspace_dir = TempfileBuilder::new()
        .prefix("request-")
        .tempdir_in(&runtime_dir)
        .map_err(|error| {
            Error::State(format!(
                "failed to create native sign workspace in '{}': {error}",
                runtime_dir.display()
            ))
        })?;

    let input_bytes = load_sign_input(&request.input)?;
    if input_bytes.is_empty() {
        return Err(Error::Validation(
            "sign input must not be empty".to_string(),
        ));
    }

    let digest = Sha256::digest(&input_bytes).to_vec();
    let digest_path = workspace_dir.path().join("sha256.digest.bin");
    let plain_signature_path = workspace_dir.path().join("signature.p1363.bin");
    let artifact_path = workspace_dir.path().join("signature.der");
    fs::write(&digest_path, &digest).map_err(|error| {
        Error::State(format!(
            "failed to write staged sign digest '{}': {error}",
            digest_path.display()
        ))
    })?;

    let locator = crate::ops::resolve_native_key_locator(identity)?;
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
                signature_path: artifact_path.clone(),
                plain_signature_path: Some(plain_signature_path),
            },
        },
    )?;
    let diagnostics = plan.warnings.clone();

    Ok(StagedNativeSign {
        _workspace_dir: workspace_dir,
        digest_algorithm: DigestAlgorithm::Sha256,
        input_bytes: input_bytes.len(),
        digest_path,
        artifact_path,
        plan,
        ready_for_execution: true,
        diagnostics,
    })
}

pub(crate) fn execute_native_sign_plan_with_runner<R>(
    plan: &NativeSignPlan,
    runner: &R,
) -> Result<Vec<u8>>
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

    finalize_native_signature_output(plan)
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

fn persist_formatted_signature(
    identity: &Identity,
    request: &SignRequest,
    signature_bytes: &[u8],
    cleanup_path: Option<&std::path::Path>,
) -> Result<(Option<PathBuf>, Option<String>)> {
    let result = match request.format {
        Format::Der => match request.output.as_deref() {
            Some(path) => {
                write_output_file(path, signature_bytes).map(|()| (Some(path.to_path_buf()), None))
            }
            None => Err(Error::Validation(
                "sign --format der requires --output because DER signature output is binary"
                    .to_string(),
            )),
        },
        Format::Hex | Format::Base64 => {
            let encoded = encode_textual_output_bytes(request.format, signature_bytes)?;
            match request.output.as_deref() {
                Some(path) => {
                    write_output_file(path, &encoded).map(|()| (Some(path.to_path_buf()), None))
                }
                None => String::from_utf8(encoded)
                    .map(|text| (None, Some(text)))
                    .map_err(|error| {
                        Error::State(format!(
                            "formatted sign output for identity '{}' could not be rendered as text: {error}",
                            identity.name
                        ))
                    }),
            }
        }
        Format::Pem | Format::Openssh | Format::Eth => Err(Error::Validation(
            "sign formats are: der, hex, base64".to_string(),
        )),
    };

    if let Some(path) = cleanup_path {
        let _ = fs::remove_file(path);
    }

    result
}

fn validate_sign_output_format(
    identity: &Identity,
    format: Format,
    output: Option<&std::path::Path>,
) -> Result<()> {
    match format {
        Format::Hex | Format::Base64 => Ok(()),
        Format::Der => {
            if identity.algorithm == Algorithm::Ed25519 {
                return Err(Error::Validation(
                    "sign --format der is not supported for ed25519 signatures; use hex or base64"
                        .to_string(),
                ));
            }
            if output.is_none() {
                return Err(Error::Validation(
                    "sign --format der requires --output because DER signature output is binary"
                        .to_string(),
                ));
            }
            Ok(())
        }
        Format::Pem | Format::Openssh | Format::Eth => Err(Error::Validation(
            "sign formats are: der, hex, base64".to_string(),
        )),
    }
}

fn load_sign_input(input: &crate::model::InputSource) -> Result<Vec<u8>> {
    load_input_bytes_with_limit(input, "sign input", BUFFERED_MESSAGE_INPUT_BYTES_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;

    use tempfile::tempdir;

    use crate::backend::{CommandInvocation, CommandOutput};
    use crate::model::{IdentityModeResolution, InputSource, ModePreference, StateLayout};

    struct DigestEchoNativeSignRunner {
        invocations: Mutex<Vec<CommandInvocation>>,
    }

    impl DigestEchoNativeSignRunner {
        fn new() -> Self {
            Self {
                invocations: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for DigestEchoNativeSignRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.invocations
                .lock()
                .expect("native sign invocations")
                .push(invocation.clone());
            let digest_path = invocation
                .args
                .windows(2)
                .find(|pair| pair[0] == "-d")
                .map(|pair| Path::new(&pair[1]).to_path_buf())
                .expect("digest path");
            let output_path = invocation
                .args
                .windows(2)
                .find(|pair| pair[0] == "-o")
                .map(|pair| Path::new(&pair[1]).to_path_buf())
                .expect("output path");
            let digest = fs::read(digest_path).expect("read digest");
            fs::write(output_path, plain_signature_from_digest(&digest)).expect("write signature");

            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    fn plain_signature_from_digest(digest: &[u8]) -> Vec<u8> {
        (0..64).map(|index| digest[index % digest.len()]).collect()
    }

    fn signing_identity(root: &Path, mode: Mode, algorithm: Algorithm) -> Identity {
        Identity::new(
            format!("{mode:?}-signer").to_lowercase(),
            algorithm,
            vec![UseCase::Sign, UseCase::Verify],
            IdentityModeResolution {
                requested: match mode {
                    Mode::Native => ModePreference::Native,
                    Mode::Prf => ModePreference::Prf,
                    Mode::Seed => ModePreference::Seed,
                },
                resolved: mode,
                reasons: vec![format!("{mode:?} requested")],
            },
            StateLayout::new(root.to_path_buf()),
        )
    }

    fn native_identity(root: &Path) -> Identity {
        signing_identity(root, Mode::Native, Algorithm::P256)
    }

    #[test]
    fn native_sign_rejects_oversized_buffered_input() {
        let state_root = tempdir().expect("state root");
        let identity = signing_identity(state_root.path(), Mode::Native, Algorithm::P256);
        let input_path = state_root.path().join("oversized.bin");
        let file = fs::File::create(&input_path).expect("oversized input file");
        file.set_len((BUFFERED_MESSAGE_INPUT_BYTES_LIMIT + 1) as u64)
            .expect("oversized sign input");

        let error = execute_with_defaults(
            &identity,
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                format: Format::Hex,
                output: None,
            },
            &DerivationOverrides::default(),
        )
        .expect_err("oversized buffered sign input should fail");

        assert!(
            matches!(error, Error::Validation(message) if message.contains("sign input") && message.contains("byte limit"))
        );
    }

    fn write_default_handle(identity: &Identity) {
        let handle_path = identity
            .storage
            .state_layout
            .objects_dir
            .join(format!("{}.handle", identity.name));
        fs::create_dir_all(handle_path.parent().expect("handle parent")).expect("handle dir");
        fs::write(handle_path, b"serialized-handle").expect("handle file");
    }

    #[test]
    fn seed_ed25519_sign_rejects_oversized_buffered_input() {
        let state_root = tempdir().expect("state root");
        let identity = signing_identity(state_root.path(), Mode::Seed, Algorithm::Ed25519);
        let input_path = state_root.path().join("oversized.bin");
        let file = fs::File::create(&input_path).expect("oversized input file");
        file.set_len((BUFFERED_MESSAGE_INPUT_BYTES_LIMIT + 1) as u64)
            .expect("oversized sign input");

        let error = execute_with_defaults(
            &identity,
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                format: Format::Hex,
                output: None,
            },
            &DerivationOverrides::default(),
        )
        .expect_err("oversized buffered sign input should fail for seed ed25519");

        assert!(
            matches!(error, Error::Validation(message) if message.contains("sign input") && message.contains("byte limit"))
        );
    }

    #[test]
    fn native_sign_rejects_derivation_overrides() {
        let state_root = tempdir().expect("state root");
        let identity = native_identity(state_root.path());
        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, b"hello native sign").expect("input file");

        let error = execute_with_defaults(
            &identity,
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                format: Format::Hex,
                output: None,
            },
            &DerivationOverrides {
                org: Some("com.example".to_string()),
                purpose: None,
                context: Default::default(),
            },
        )
        .expect_err("native sign should reject derivation overrides");

        assert!(
            matches!(error, Error::Validation(message) if message.contains("native identities reject derivation overrides"))
        );
    }

    #[test]
    fn native_sign_uses_unique_workspace_per_request() {
        let state_root = tempdir().expect("state root");
        let identity = native_identity(state_root.path());
        write_default_handle(&identity);

        let input_one = state_root.path().join("one.bin");
        let input_two = state_root.path().join("two.bin");
        fs::write(&input_one, b"first native message").expect("first input");
        fs::write(&input_two, b"second native message").expect("second input");

        let staged_one = stage_native_sign(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path {
                    path: input_one.clone(),
                },
                format: Format::Hex,
                output: None,
            },
            &identity,
        )
        .expect("first staged sign");
        let staged_two = stage_native_sign(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path {
                    path: input_two.clone(),
                },
                format: Format::Hex,
                output: None,
            },
            &identity,
        )
        .expect("second staged sign");

        assert_ne!(staged_one.digest_path, staged_two.digest_path);
        assert_ne!(staged_one.artifact_path, staged_two.artifact_path);
        assert_ne!(
            staged_one.digest_path.parent(),
            staged_two.digest_path.parent(),
            "native sign requests should stage in different workspace directories"
        );

        let workspace_one = staged_one
            .digest_path
            .parent()
            .expect("first workspace")
            .to_path_buf();
        let workspace_two = staged_two
            .digest_path
            .parent()
            .expect("second workspace")
            .to_path_buf();

        let runner = DigestEchoNativeSignRunner::new();
        let signature_one = execute_native_sign_plan_with_runner(&staged_one.plan, &runner)
            .expect("execute first staged sign");
        let signature_two = execute_native_sign_plan_with_runner(&staged_two.plan, &runner)
            .expect("execute second staged sign");

        let expected_one = crate::ops::native::subprocess::finalize_p256_signature(
            NativeSignatureFormat::Der,
            &plain_signature_from_digest(&Sha256::digest(b"first native message")),
        )
        .expect("first expected signature");
        let expected_two = crate::ops::native::subprocess::finalize_p256_signature(
            NativeSignatureFormat::Der,
            &plain_signature_from_digest(&Sha256::digest(b"second native message")),
        )
        .expect("second expected signature");

        assert_eq!(signature_one, expected_one);
        assert_eq!(signature_two, expected_two);
        assert_ne!(signature_one, signature_two);

        drop(staged_one);
        drop(staged_two);
        assert!(!workspace_one.exists());
        assert!(!workspace_two.exists());
    }
}
