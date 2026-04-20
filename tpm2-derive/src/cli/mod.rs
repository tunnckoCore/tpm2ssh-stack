mod args;
mod render;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use tempfile::Builder as TempfileBuilder;

use args::{
    AlgorithmArg, DecryptArgs, DeriveArgs, EncryptArgs, ExportArgs, ExportKindArg, InspectArgs,
    ImportArgs, ModeArg, PublicKeyExportFormatArg, SetupArgs,
    SignArgs, SshAgentAddArgs, SshAgentCommand, SshCommand, UseArg, VerifyArgs,
};
pub use args::{Cli, Command};
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey as Ed25519SigningKey};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use render::{failure, success, success_with_diagnostics};
use secrecy::ExposeSecret;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::backend::{
    default_probe, CapabilityProbe, CommandInvocation, CommandOutput, CommandRunner,
    ProcessCommandRunner,
};
use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, CommandPath, DecryptRequest, DerivationContext, DeriveRequest, EncryptRequest,
    ErrorEnvelope, ExportKind, ExportRequest, InputSource, InspectRequest, Mode, ModePreference,
    PendingOperation, Profile, PublicKeyExportFormat, RecoveryImportRequest, SetupRequest,
    SignRequest, SshAgentAddRequest, UseCase, VerifyRequest,
};
use crate::ops;
use crate::ops::native::subprocess::{
    plan_sign, NativeAuthSource, NativeKeyLocator, NativePostProcessAction, NativeSignArtifacts,
    NativeSignOptions, NativeSignPlan,
};
use crate::ops::native::{
    DigestAlgorithm, NativeKeyRef, NativeSignRequest, NativeSignatureFormat, NativeSignatureScheme,
};
use crate::ops::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedProfile, SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive, plan_open,
    seed_profile_from_profile,
};

const SEED_VERIFY_CHILD_KEY_NAMESPACE: &str = "tpm2-derive.verify";
const SEED_VERIFY_CHILD_KEY_PATH: &str = "m/signature/default";

impl From<AlgorithmArg> for Algorithm {
    fn from(value: AlgorithmArg) -> Self {
        match value {
            AlgorithmArg::P256 => Self::P256,
            AlgorithmArg::Ed25519 => Self::Ed25519,
            AlgorithmArg::Secp256k1 => Self::Secp256k1,
        }
    }
}

impl From<UseArg> for UseCase {
    fn from(value: UseArg) -> Self {
        match value {
            UseArg::Sign => Self::Sign,
            UseArg::Verify => Self::Verify,
            UseArg::Derive => Self::Derive,
            UseArg::Ssh => Self::Ssh,
            UseArg::SshAgent => Self::SshAgent,
            UseArg::Ethereum => Self::Ethereum,
            UseArg::Encrypt => Self::Encrypt,
            UseArg::Decrypt => Self::Decrypt,
        }
    }
}

impl From<ModeArg> for ModePreference {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Auto => Self::Auto,
            ModeArg::Native => Self::Native,
            ModeArg::Prf => Self::Prf,
            ModeArg::Seed => Self::Seed,
        }
    }
}

impl From<ExportKindArg> for ExportKind {
    fn from(value: ExportKindArg) -> Self {
        match value {
            ExportKindArg::PublicKey => Self::PublicKey,
            ExportKindArg::RecoveryBundle => Self::RecoveryBundle,
        }
    }
}

impl From<PublicKeyExportFormatArg> for PublicKeyExportFormat {
    fn from(value: PublicKeyExportFormatArg) -> Self {
        match value {
            PublicKeyExportFormatArg::SpkiDer => Self::SpkiDer,
            PublicKeyExportFormatArg::SpkiPem => Self::SpkiPem,
            PublicKeyExportFormatArg::SpkiHex => Self::SpkiHex,
            PublicKeyExportFormatArg::Openssh => Self::Openssh,
        }
    }
}

pub fn run(cli: Cli) -> Result<String> {
    let probe = default_probe();

    match cli.command {
        Command::Inspect(args) => run_inspect(cli.json, &probe, args),
        Command::Setup(args) => run_setup(cli.json, &probe, args),
        Command::Derive(args) => run_derive(cli.json, args),
        Command::Sign(args) => run_sign(cli.json, args),
        Command::Verify(args) => run_verify(cli.json, args),
        Command::Encrypt(args) => run_placeholder(
            cli.json,
            CommandPath::from_segments(["encrypt"]),
            args.profile.clone(),
            "encrypt",
            encrypt_summary(&args),
        ),
        Command::Decrypt(args) => run_placeholder(
            cli.json,
            CommandPath::from_segments(["decrypt"]),
            args.profile.clone(),
            "decrypt",
            decrypt_summary(&args),
        ),
        Command::Export(args) => run_export(cli.json, args),
        Command::Import(args) => run_import(cli.json, args),
        Command::Ssh(SshCommand::Agent(SshAgentCommand::Add(args))) => {
            run_ssh_agent_add(cli.json, args)
        }
    }
}

fn run_inspect(json: bool, probe: &dyn CapabilityProbe, args: InspectArgs) -> Result<String> {
    let request = InspectRequest {
        algorithm: args.algorithm.map(Into::into),
        uses: args.uses.into_iter().map(Into::into).collect(),
    };

    let report = ops::inspect(probe, &request);
    success(json, CommandPath::from_segments(["inspect"]), report)
}

fn run_setup(json: bool, probe: &dyn CapabilityProbe, args: SetupArgs) -> Result<String> {
    let request = SetupRequest {
        profile: args.profile,
        algorithm: args.algorithm.into(),
        uses: args.uses.into_iter().map(Into::into).collect(),
        requested_mode: args.mode.into(),
        state_dir: args.state_dir,
        dry_run: args.dry_run,
    };

    match ops::resolve_profile(probe, &request) {
        Ok(result) => success(json, CommandPath::from_segments(["setup"]), result),
        Err(error) => failure(
            json,
            CommandPath::from_segments(["setup"]),
            ErrorEnvelope {
                code: error.code().as_str().to_string(),
                message: error.to_string(),
            },
            Vec::new(),
        ),
    }
}

fn run_derive(json: bool, args: DeriveArgs) -> Result<String> {
    let command = CommandPath::from_segments(["derive"]);
    let request = DeriveRequest {
        profile: args.profile.clone(),
        context: DerivationContext {
            version: 1,
            purpose: args.purpose,
            namespace: args.namespace,
            label: args.label,
            context: args.context.into_iter().collect(),
        },
        length: args.length,
    };

    match ops::load_profile(&request.profile, args.state_dir) {
        Ok(profile) => {
            let runner = ProcessCommandRunner;
            match ops::derive::execute_with_defaults(&profile, &request, &runner) {
                Ok(result) => success(json, command, result),
                Err(error) => failure(
                    json,
                    command,
                    ErrorEnvelope {
                        code: error.code().as_str().to_string(),
                        message: error.to_string(),
                    },
                    Vec::new(),
                ),
            }
        }
        Err(error) => failure(
            json,
            command,
            ErrorEnvelope {
                code: error.code().as_str().to_string(),
                message: error.to_string(),
            },
            Vec::new(),
        ),
    }
}

fn run_export(json: bool, args: ExportArgs) -> Result<String> {
    let command = export_command_path(args.kind.into());
    let request = ExportRequest {
        profile: args.profile,
        kind: args.kind.into(),
        output: args.output,
        public_key_format: args.public_key_format.map(Into::into),
        state_dir: args.state_dir,
        reason: args.reason,
        confirm: args.confirm,
        confirm_phrase: args.confirm_phrase,
    };

    match ops::export(&request) {
        Ok(result) => success(json, command, result),
        Err(error) => failure(
            json,
            command,
            ErrorEnvelope {
                code: error.code().as_str().to_string(),
                message: error.to_string(),
            },
            Vec::new(),
        ),
    }
}

fn run_import(json: bool, args: ImportArgs) -> Result<String> {
    let command = CommandPath::from_segments(["import"]);

    if !args.confirm {
        let error = Error::Validation(
            "import requires --confirm because the bundle contains exported seed material until it is resealed into TPM-backed state"
                .to_string(),
        );
        return failure(
            json,
            command,
            ErrorEnvelope {
                code: error.code().as_str().to_string(),
                message: error.to_string(),
            },
            Vec::new(),
        );
    }

    let request = RecoveryImportRequest {
        bundle_path: args.bundle,
        profile: args.profile,
        state_dir: args.state_dir,
        overwrite_existing: args.overwrite_existing,
    };

    match ops::import_recovery_bundle(&request) {
        Ok(result) => success(json, command, result),
        Err(error) => failure(
            json,
            command,
            ErrorEnvelope {
                code: error.code().as_str().to_string(),
                message: error.to_string(),
            },
            Vec::new(),
        ),
    }
}

fn run_ssh_agent_add(json: bool, args: SshAgentAddArgs) -> Result<String> {
    let command = CommandPath::from_segments(["ssh-agent", "add"]);
    let request = SshAgentAddRequest {
        profile: args.profile.clone(),
        comment: args.comment.clone(),
        socket: args.socket.clone(),
        state_dir: args.state_dir.clone(),
    };

    let profile = match ops::load_profile(&args.profile, args.state_dir.clone()) {
        Ok(profile) => profile,
        Err(error) => {
            return failure(
                json,
                command,
                ErrorEnvelope {
                    code: error.code().as_str().to_string(),
                    message: error.to_string(),
                },
                Vec::new(),
            );
        }
    };

    match ops::ssh::add_with_defaults(&profile, &request) {
        Ok(result) => success(json, command, result),
        Err(error) => failure(
            json,
            command,
            ErrorEnvelope {
                code: error.code().as_str().to_string(),
                message: error.to_string(),
            },
            Vec::new(),
        ),
    }
}

fn run_sign(json: bool, args: SignArgs) -> Result<String> {
    let request = SignRequest {
        profile: args.profile.clone(),
        input: parse_input_source(&args.input),
    };
    let command = CommandPath::from_segments(["sign"]);

    let profile = match ops::load_profile(&args.profile, args.state_dir.clone()) {
        Ok(profile) => profile,
        Err(error) => {
            return failure(
                json,
                command,
                ErrorEnvelope {
                    code: error.code().as_str().to_string(),
                    message: error.to_string(),
                },
                Vec::new(),
            );
        }
    };

    let mut diagnostics = vec![
        crate::model::Diagnostic::info(
            "loaded-profile",
            format!(
                "loaded profile '{}' from '{}'",
                profile.name,
                profile.storage.profile_path.display()
            ),
        ),
        crate::model::Diagnostic::info(
            "profile-mode",
            format!(
                "sign request is bound to resolved mode {:?}",
                profile.mode.resolved
            ),
        ),
    ];

    match profile.mode.resolved {
        Mode::Native => match stage_native_sign(&request, &profile) {
            Ok(staged) => {
                diagnostics.extend(staged.diagnostics.clone());

                let signature_bytes_written = if staged.ready_for_execution {
                    match execute_native_sign_plan_with_runner(&staged.plan, &ProcessCommandRunner)
                    {
                        Ok(bytes_written) => {
                            diagnostics.push(crate::model::Diagnostic::info(
                                "native-sign-executed",
                                format!(
                                    "executed native sign and wrote {} bytes to '{}'",
                                    bytes_written,
                                    staged.output_path.display()
                                ),
                            ));
                            Some(bytes_written)
                        }
                        Err(error) => {
                            return failure(
                                json,
                                command,
                                ErrorEnvelope {
                                    code: error.code().as_str().to_string(),
                                    message: error.to_string(),
                                },
                                diagnostics,
                            );
                        }
                    }
                } else {
                    None
                };

                success_with_diagnostics(
                    json,
                    command,
                    SignOperationResult {
                        profile,
                        request,
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
                    },
                    diagnostics,
                )
            }
            Err(error) => failure(
                json,
                command,
                ErrorEnvelope {
                    code: error.code().as_str().to_string(),
                    message: error.to_string(),
                },
                diagnostics,
            ),
        },
        Mode::Prf => unsupported_mode_operation(
            json,
            command,
            profile.mode.resolved,
            diagnostics,
            "sign is not wired for PRF-mode profiles yet",
        ),
        Mode::Seed => unsupported_mode_operation(
            json,
            command,
            profile.mode.resolved,
            diagnostics,
            "sign is not wired for seed-mode profiles yet",
        ),
    }
}

fn run_verify(json: bool, args: VerifyArgs) -> Result<String> {
    run_verify_with_runner(json, args, &ProcessCommandRunner)
}

fn run_verify_with_runner<R>(json: bool, args: VerifyArgs, runner: &R) -> Result<String>
where
    R: CommandRunner,
{
    let request = VerifyRequest {
        profile: args.profile.clone(),
        input: parse_input_source(&args.input),
        signature: parse_input_source(&args.signature),
    };
    let command = CommandPath::from_segments(["verify"]);

    let profile = match ops::load_profile(&args.profile, args.state_dir.clone()) {
        Ok(profile) => profile,
        Err(error) => {
            return failure(
                json,
                command,
                ErrorEnvelope {
                    code: error.code().as_str().to_string(),
                    message: error.to_string(),
                },
                Vec::new(),
            );
        }
    };

    let mut diagnostics = vec![
        crate::model::Diagnostic::info(
            "loaded-profile",
            format!(
                "loaded profile '{}' from '{}'",
                profile.name,
                profile.storage.profile_path.display()
            ),
        ),
        crate::model::Diagnostic::info(
            "profile-mode",
            format!(
                "verify request is bound to resolved mode {:?}",
                profile.mode.resolved
            ),
        ),
    ];

    let verification = match profile.mode.resolved {
        Mode::Native => verify_native_with_runner(&request, &profile, runner),
        Mode::Seed => {
            let backend =
                SubprocessSeedBackend::new(profile.storage.state_layout.objects_dir.clone());
            verify_seed_with_backend(&request, &profile, &backend, &HkdfSha256SeedDeriver)
        }
        Mode::Prf => {
            return unsupported_mode_operation(
                json,
                command,
                profile.mode.resolved,
                diagnostics,
                "verify is not wired for PRF-mode profiles yet; PRF roots can derive child key material, but the CLI verify flow does not yet derive and use a profile-bound public key",
            );
        }
    };

    match verification {
        Ok((result, verify_diagnostics)) => {
            diagnostics.extend(verify_diagnostics);
            success_with_diagnostics(json, command, result, diagnostics)
        }
        Err(error) => failure(
            json,
            command,
            ErrorEnvelope {
                code: error.code().as_str().to_string(),
                message: error.to_string(),
            },
            diagnostics,
        ),
    }
}

fn verify_native_with_runner<R>(
    request: &VerifyRequest,
    profile: &Profile,
    runner: &R,
) -> Result<(VerifyOperationResult, Vec<crate::model::Diagnostic>)>
where
    R: CommandRunner,
{
    if profile.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native verify is currently wired only for p256 profiles, found {:?}",
            profile.algorithm
        )));
    }

    if !profile.uses.contains(&UseCase::Verify) {
        return Err(Error::Unsupported(format!(
            "profile '{}' is not configured with verify use",
            profile.name
        )));
    }

    if matches!(request.input, InputSource::Stdin)
        && matches!(request.signature, InputSource::Stdin)
    {
        return Err(Error::Validation(
            "verify cannot read both --input and --signature from stdin at the same time"
                .to_string(),
        ));
    }

    let input_bytes = load_input_bytes(&request.input, "verify input")?;
    let signature_bytes = load_input_bytes(&request.signature, "verify signature")?;
    if signature_bytes.is_empty() {
        return Err(Error::Validation(
            "verify signature must not be empty".to_string(),
        ));
    }

    let digest = Sha256::digest(&input_bytes).to_vec();
    let public_key_der = export_native_public_key_der_with_runner(profile, runner)?;
    let verifying_key = load_p256_verifying_key(&public_key_der)?;
    let (signature, signature_format) = parse_p256_verify_signature(&signature_bytes)?;
    let verified = verifying_key.verify(&input_bytes, &signature).is_ok();

    Ok((
        VerifyOperationResult {
            profile: profile.clone(),
            request: request.clone(),
            mode: Mode::Native,
            verified,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest_hex: hex_encode(&digest),
            input_bytes: input_bytes.len(),
            signature_bytes: signature_bytes.len(),
            signature_format,
        },
        vec![crate::model::Diagnostic::info(
            "native-public-key-exported",
            format!(
                "exported {} bytes of SPKI DER public key material from native TPM state for verify",
                public_key_der.len()
            ),
        )],
    ))
}

fn verify_seed_with_backend<B, D>(
    request: &VerifyRequest,
    profile: &Profile,
    backend: &B,
    deriver: &D,
) -> Result<(VerifyOperationResult, Vec<crate::model::Diagnostic>)>
where
    B: SeedBackend,
    D: crate::ops::seed::SeedSoftwareDeriver,
{
    if !profile.uses.contains(&UseCase::Verify) {
        return Err(Error::Unsupported(format!(
            "profile '{}' is not configured with verify use",
            profile.name
        )));
    }

    if matches!(request.input, InputSource::Stdin)
        && matches!(request.signature, InputSource::Stdin)
    {
        return Err(Error::Validation(
            "verify cannot read both --input and --signature from stdin at the same time"
                .to_string(),
        ));
    }

    ensure_seed_verify_algorithm_supported(profile.algorithm)?;

    let input_bytes = load_input_bytes(&request.input, "verify input")?;
    let signature_bytes = load_input_bytes(&request.signature, "verify signature")?;
    if signature_bytes.is_empty() {
        return Err(Error::Validation(
            "verify signature must not be empty".to_string(),
        ));
    }

    let seed_request = seed_verify_open_request(profile)?;
    let seed_plan = plan_open(&seed_request)?;
    let digest = Sha256::digest(&input_bytes).to_vec();
    let derived = open_and_derive(backend, deriver, &seed_request)?;
    let diagnostics =
        seed_verify_diagnostics(profile, &seed_plan.warnings, derived.expose_secret().len());

    verify_seed_ed25519(
        request,
        profile,
        &input_bytes,
        &signature_bytes,
        &digest,
        derived.expose_secret(),
        diagnostics,
    )
}

fn verify_seed_ed25519(
    request: &VerifyRequest,
    profile: &Profile,
    input_bytes: &[u8],
    signature_bytes: &[u8],
    digest: &[u8],
    derived_seed: &[u8],
    diagnostics: Vec<crate::model::Diagnostic>,
) -> Result<(VerifyOperationResult, Vec<crate::model::Diagnostic>)> {
    let seed_bytes: [u8; 32] = derived_seed.try_into().map_err(|_| {
        Error::Internal(
            "seed verify ed25519 derivation produced a non-32-byte seed unexpectedly".to_string(),
        )
    })?;
    let signing_key = Ed25519SigningKey::from_bytes(&seed_bytes);
    let (signature, signature_format) = parse_ed25519_verify_signature(signature_bytes)?;
    let verified = signing_key
        .verifying_key()
        .verify_strict(input_bytes, &signature)
        .is_ok();

    Ok((
        VerifyOperationResult {
            profile: profile.clone(),
            request: request.clone(),
            mode: Mode::Seed,
            verified,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest_hex: hex_encode(digest),
            input_bytes: input_bytes.len(),
            signature_bytes: signature_bytes.len(),
            signature_format,
        },
        diagnostics,
    ))
}

fn seed_verify_open_request(profile: &Profile) -> Result<SeedOpenRequest> {
    Ok(SeedOpenRequest {
        profile: seed_verify_profile(profile)?,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
            spec: seed_verify_derivation_spec(profile.algorithm)?,
            output_bytes: 32,
        }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    })
}

fn seed_verify_profile(profile: &Profile) -> Result<SeedProfile> {
    if profile.mode.resolved != Mode::Seed {
        return Err(Error::Unsupported(format!(
            "profile '{}' did not resolve to seed mode",
            profile.name
        )));
    }

    seed_profile_from_profile(profile)
}

fn ensure_seed_verify_algorithm_supported(algorithm: Algorithm) -> Result<()> {
    match algorithm {
        Algorithm::Ed25519 => Ok(()),
        Algorithm::P256 => Err(Error::Unsupported(
            "seed verify is not wired for p256 profiles yet; native mode remains the preferred path for p256 sign/verify workloads"
                .to_string(),
        )),
        Algorithm::Secp256k1 => Err(Error::Unsupported(
            "seed verify is not wired for secp256k1 profiles yet".to_string(),
        )),
    }
}

fn seed_verify_derivation_spec(algorithm: Algorithm) -> Result<DerivationSpec> {
    ensure_seed_verify_algorithm_supported(algorithm)?;

    Ok(DerivationSpec::V1(DerivationSpecV1::software_child_key(
        SEED_VERIFY_CHILD_KEY_NAMESPACE,
        "ed25519",
        SEED_VERIFY_CHILD_KEY_PATH,
        OutputKind::Ed25519Seed,
    )?))
}

fn seed_verify_diagnostics(
    profile: &Profile,
    warnings: &[crate::model::Diagnostic],
    derived_bytes: usize,
) -> Vec<crate::model::Diagnostic> {
    let mut diagnostics = warnings.to_vec();
    diagnostics.push(crate::model::Diagnostic::info(
        "seed-verifier-derived",
        format!(
            "derived {} bytes of {:?} verifier material from sealed seed using {} {}",
            derived_bytes,
            profile.algorithm,
            SEED_VERIFY_CHILD_KEY_NAMESPACE,
            SEED_VERIFY_CHILD_KEY_PATH,
        ),
    ));
    diagnostics
}

fn export_command_path(kind: ExportKind) -> CommandPath {
    match kind {
        ExportKind::PublicKey => CommandPath::from_segments(["export", "public-key"]),
        ExportKind::RecoveryBundle => CommandPath::from_segments(["export", "recovery-bundle"]),
    }
}

fn run_placeholder(
    json: bool,
    command: CommandPath,
    profile: String,
    operation: &str,
    summary: String,
) -> Result<String> {
    let _request_marker = build_placeholder_request(operation, profile);

    failure(
        json,
        command,
        ErrorEnvelope {
            code: Error::Unsupported(format!("{operation} is not implemented yet"))
                .code()
                .as_str()
                .to_string(),
            message: format!("{operation} is not implemented yet"),
        },
        vec![crate::model::Diagnostic::info("planned-command", summary)],
    )
}

#[derive(Debug, Clone, Serialize)]
struct SignOperationResult {
    profile: Profile,
    request: SignRequest,
    mode: Mode,
    state: String,
    digest_algorithm: DigestAlgorithm,
    input_bytes: usize,
    digest_path: PathBuf,
    output_path: PathBuf,
    signature_bytes_written: Option<usize>,
    plan: NativeSignPlan,
}

#[derive(Debug, Clone, Copy, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum VerifySignatureFormat {
    Der,
    P1363,
    Raw,
}

#[derive(Debug, Clone, Serialize)]
struct VerifyOperationResult {
    profile: Profile,
    request: VerifyRequest,
    mode: Mode,
    verified: bool,
    digest_algorithm: DigestAlgorithm,
    digest_hex: String,
    input_bytes: usize,
    signature_bytes: usize,
    signature_format: VerifySignatureFormat,
}

#[derive(Debug, Clone)]
struct StagedNativeSign {
    digest_algorithm: DigestAlgorithm,
    input_bytes: usize,
    digest_path: PathBuf,
    output_path: PathBuf,
    plan: NativeSignPlan,
    ready_for_execution: bool,
    diagnostics: Vec<crate::model::Diagnostic>,
}

fn unsupported_mode_operation(
    json: bool,
    command: CommandPath,
    mode: Mode,
    diagnostics: Vec<crate::model::Diagnostic>,
    message: &str,
) -> Result<String> {
    failure(
        json,
        command,
        ErrorEnvelope {
            code: Error::Unsupported(message.to_string())
                .code()
                .as_str()
                .to_string(),
            message: format!("{message} (resolved mode: {})", mode_name(mode)),
        },
        diagnostics,
    )
}

fn stage_native_sign(request: &SignRequest, profile: &Profile) -> Result<StagedNativeSign> {
    if profile.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native sign is currently wired only for p256 profiles, found {:?}",
            profile.algorithm
        )));
    }

    if !profile.uses.contains(&UseCase::Sign) {
        return Err(Error::Unsupported(format!(
            "profile '{}' is not configured with sign use",
            profile.name
        )));
    }

    profile.storage.state_layout.ensure_dirs()?;

    let runtime_dir = profile
        .storage
        .state_layout
        .objects_dir
        .join(&profile.name)
        .join("native-sign");
    let output_dir = profile
        .storage
        .state_layout
        .exports_dir
        .join(&profile.name)
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

    let (locator, ready_for_execution, locator_diagnostics) = resolve_native_sign_locator(profile);
    let plan = plan_sign(
        &NativeSignRequest {
            key: NativeKeyRef {
                profile: profile.name.clone(),
                key_id: ops::native_key_id(profile),
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

fn resolve_native_sign_locator(
    profile: &Profile,
) -> (NativeKeyLocator, bool, Vec<crate::model::Diagnostic>) {
    if let Some(path) = ops::metadata_path(
        profile,
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

    if let Some(handle) = ops::metadata_value(
        profile,
        &["native.persistent_handle", "native.persistent-handle"],
    ) {
        return (
            NativeKeyLocator::PersistentHandle { handle },
            true,
            Vec::new(),
        );
    }

    for path in ops::native_handle_path_candidates(profile) {
        if path.is_file() {
            return (
                NativeKeyLocator::SerializedHandle { path },
                true,
                Vec::new(),
            );
        }
    }

    let missing_handle_path = ops::metadata_path(
        profile,
        &[
            "native.serialized_handle_path",
            "native.serialized-handle-path",
        ],
    )
    .or_else(|| {
        ops::native_handle_path_candidates(profile)
            .into_iter()
            .next()
    })
    .unwrap_or_else(|| {
        profile
            .storage
            .state_layout
            .objects_dir
            .join(format!("{}.handle", profile.name))
    });

    (
        NativeKeyLocator::SerializedHandle {
            path: missing_handle_path.clone(),
        },
        false,
        vec![crate::model::Diagnostic::warning(
            "native-key-handle-missing",
            format!(
                "serialized native key handle '{}' is not present yet; sign returns a concrete plan and staged digest, and will execute once native setup material is present",
                missing_handle_path.display()
            ),
        )],
    )
}

fn execute_native_sign_plan_with_runner<R>(plan: &NativeSignPlan, runner: &R) -> Result<usize>
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

fn classify_native_command_failure(program: &str, output: &CommandOutput) -> Error {
    let detail = render_command_failure_detail(output);
    let lower = detail.to_ascii_lowercase();
    let message = format!(
        "native TPM command '{}' failed{}{}",
        program,
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
    } else if output.error.is_some()
        || lower.contains("tcti")
        || lower.contains("/dev/tpm")
        || lower.contains("no standard tcti")
        || lower.contains("connection refused")
    {
        Error::TpmUnavailable(message)
    } else if lower.contains("no such file")
        || lower.contains("could not open")
        || lower.contains("cannot open")
        || lower.contains("context")
        || lower.contains("handle")
    {
        Error::State(message)
    } else {
        Error::CapabilityMismatch(message)
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

fn parse_input_source(input: &str) -> InputSource {
    if input == "-" {
        InputSource::Stdin
    } else {
        InputSource::Path {
            path: PathBuf::from(input),
        }
    }
}

fn load_sign_input(input: &InputSource) -> Result<Vec<u8>> {
    load_input_bytes(input, "sign input")
}

fn load_input_bytes(input: &InputSource, label: &str) -> Result<Vec<u8>> {
    match input {
        InputSource::Stdin => {
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer).map_err(|error| {
                Error::State(format!("failed to read {label} from stdin: {error}"))
            })?;
            Ok(buffer)
        }
        InputSource::Path { path } => fs::read(path).map_err(|error| {
            Error::State(format!(
                "failed to read {label} '{}': {error}",
                path.display()
            ))
        }),
    }
}

fn export_native_public_key_der_with_runner<R>(profile: &Profile, runner: &R) -> Result<Vec<u8>>
where
    R: CommandRunner,
{
    if profile.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native public-key export is currently wired only for p256 profiles, got {:?}",
            profile.algorithm
        )));
    }

    profile.storage.state_layout.ensure_dirs()?;

    let locator = ops::resolve_native_key_locator(profile)?;
    let tempdir = TempfileBuilder::new()
        .prefix("native-verify-public-key-")
        .tempdir_in(&profile.storage.state_layout.exports_dir)
        .map_err(|error| {
            Error::State(format!(
                "failed to create native verify workspace in '{}': {error}",
                profile.storage.state_layout.exports_dir.display()
            ))
        })?;

    let plan = crate::ops::native::subprocess::plan_export_public_key(
        &crate::ops::native::NativePublicKeyExportRequest {
            key: NativeKeyRef {
                profile: profile.name.clone(),
                key_id: ops::native_key_id(profile),
            },
            encodings: vec![crate::ops::native::NativePublicKeyEncoding::SpkiDer],
        },
        &crate::ops::native::subprocess::NativePublicKeyExportOptions {
            locator,
            output_dir: tempdir.path().to_path_buf(),
            file_stem: profile.name.clone(),
        },
    )?;

    for command in &plan.commands {
        let output = runner.run(&CommandInvocation::new(
            &command.program,
            command.args.iter().cloned(),
        ));
        if output.error.is_some() || output.exit_code != Some(0) {
            return Err(classify_native_command_failure(&command.program, &output));
        }
    }

    let exported = plan
        .outputs
        .iter()
        .find(|output| output.encoding == crate::ops::native::NativePublicKeyEncoding::SpkiDer)
        .ok_or_else(|| {
            Error::Internal(
                "native verify export plan did not produce the expected SPKI DER artifact"
                    .to_string(),
            )
        })?;

    fs::read(&exported.path).map_err(|error| {
        Error::State(format!(
            "failed to read native verify public key from '{}': {error}",
            exported.path.display()
        ))
    })
}

fn load_p256_verifying_key(public_key_der: &[u8]) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_der(public_key_der).map_err(|error| {
        Error::State(format!(
            "native verify exported malformed SPKI DER public key material: {error}"
        ))
    })
}

fn parse_p256_verify_signature(
    signature_bytes: &[u8],
) -> Result<(P256Signature, VerifySignatureFormat)> {
    if let Ok(signature) = P256Signature::from_der(signature_bytes) {
        return Ok((signature, VerifySignatureFormat::Der));
    }

    if let Ok(signature) = P256Signature::from_slice(signature_bytes) {
        return Ok((signature, VerifySignatureFormat::P1363));
    }

    Err(Error::Validation(
        "verify signature must be either ASN.1 DER ECDSA or 64-byte P1363 for p256".to_string(),
    ))
}

fn parse_ed25519_verify_signature(
    signature_bytes: &[u8],
) -> Result<(Ed25519Signature, VerifySignatureFormat)> {
    let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        Error::Validation("verify signature for ed25519 must be exactly 64 raw bytes".to_string())
    })?;

    Ok((
        Ed25519Signature::from_bytes(&signature_bytes),
        VerifySignatureFormat::Raw,
    ))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn ensure_dir(path: &Path, label: &str) -> Result<()> {
    fs::create_dir_all(path).map_err(|error| {
        Error::State(format!(
            "failed to create {label} directory '{}': {error}",
            path.display()
        ))
    })
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Native => "native",
        Mode::Prf => "prf",
        Mode::Seed => "seed",
    }
}

fn build_placeholder_request(operation: &str, profile: String) -> serde_json::Value {
    match operation {
        "derive" => serde_json::to_value(DeriveRequest {
            profile,
            context: DerivationContext {
                version: 1,
                purpose: "planned".to_string(),
                namespace: "planned".to_string(),
                label: None,
                context: BTreeMap::new(),
            },
            length: 32,
        })
        .unwrap_or_default(),
        "sign" => serde_json::to_value(SignRequest {
            profile,
            input: InputSource::Stdin,
        })
        .unwrap_or_default(),
        "verify" => serde_json::to_value(VerifyRequest {
            profile,
            input: InputSource::Stdin,
            signature: InputSource::Stdin,
        })
        .unwrap_or_default(),
        "encrypt" => serde_json::to_value(EncryptRequest {
            profile,
            input: InputSource::Stdin,
        })
        .unwrap_or_default(),
        "decrypt" => serde_json::to_value(DecryptRequest {
            profile,
            input: InputSource::Stdin,
        })
        .unwrap_or_default(),
        "export" => serde_json::to_value(ExportRequest {
            profile,
            kind: ExportKind::PublicKey,
            output: None,
            public_key_format: None,
            state_dir: None,
            reason: None,
            confirm: false,
            confirm_phrase: None,
        })
        .unwrap_or_default(),
        "ssh-agent add" => serde_json::to_value(SshAgentAddRequest {
            profile,
            comment: None,
            socket: None,
            state_dir: None,
        })
        .unwrap_or_default(),
        _ => serde_json::to_value(PendingOperation {
            implemented: false,
            operation: operation.to_string(),
            profile: Some(profile),
            summary: "planned command".to_string(),
        })
        .unwrap_or_default(),
    }
}

fn encrypt_summary(args: &EncryptArgs) -> String {
    format!(
        "profile={} input={} state=planned",
        args.profile, args.input
    )
}

fn decrypt_summary(args: &DecryptArgs) -> String {
    format!(
        "profile={} input={} state=planned",
        args.profile, args.input
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;

    use clap::Parser as _;
    use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;
    use p256::pkcs8::EncodePublicKey as _;
    use secrecy::SecretBox;
    use serde_json::Value;
    use tempfile::tempdir;

    use crate::model::{ModeResolution, StateLayout};
    use crate::ops::seed::{SeedCreateRequest, SeedMaterial, SeedSoftwareDeriver};

    struct RecordingNativeSignRunner {
        invocations: RefCell<Vec<CommandInvocation>>,
        output: CommandOutput,
        plain_signature: Vec<u8>,
    }

    impl RecordingNativeSignRunner {
        fn success(plain_signature: Vec<u8>) -> Self {
            Self {
                invocations: RefCell::new(Vec::new()),
                output: CommandOutput {
                    exit_code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                    error: None,
                },
                plain_signature,
            }
        }

        fn invocations(&self) -> Vec<CommandInvocation> {
            self.invocations.borrow().clone()
        }
    }

    impl CommandRunner for RecordingNativeSignRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.invocations.borrow_mut().push(invocation.clone());

            if self.output.error.is_none() && self.output.exit_code == Some(0) {
                let output_path = invocation
                    .args
                    .windows(2)
                    .find(|pair| pair[0] == "-o")
                    .map(|pair| PathBuf::from(&pair[1]))
                    .expect("native sign output path");
                fs::write(output_path, &self.plain_signature).expect("write fake signature");
            }

            self.output.clone()
        }
    }

    struct RecordingNativePublicKeyRunner {
        invocations: RefCell<Vec<CommandInvocation>>,
        public_key_der: Vec<u8>,
    }

    impl RecordingNativePublicKeyRunner {
        fn success(public_key_der: Vec<u8>) -> Self {
            Self {
                invocations: RefCell::new(Vec::new()),
                public_key_der,
            }
        }

        fn invocations(&self) -> Vec<CommandInvocation> {
            self.invocations.borrow().clone()
        }
    }

    impl CommandRunner for RecordingNativePublicKeyRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.invocations.borrow_mut().push(invocation.clone());
            assert_eq!(invocation.program, "tpm2_readpublic");

            let output_path = invocation
                .args
                .windows(2)
                .find(|pair| pair[0] == "-o")
                .map(|pair| PathBuf::from(&pair[1]))
                .expect("native public-key output path");
            fs::write(output_path, &self.public_key_der).expect("write fake public key");

            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    fn native_profile(root: &Path, mode: Mode, uses: Vec<UseCase>) -> Profile {
        Profile::new(
            "prod-signer".to_string(),
            Algorithm::P256,
            uses,
            ModeResolution {
                requested: ModePreference::Native,
                resolved: mode,
                reasons: vec![format!("{mode:?} requested")],
            },
            StateLayout::new(root.to_path_buf()),
        )
    }

    struct FakeSeedBackend {
        seed: Vec<u8>,
    }

    impl FakeSeedBackend {
        fn new(seed: &[u8]) -> Self {
            Self {
                seed: seed.to_vec(),
            }
        }
    }

    impl SeedBackend for FakeSeedBackend {
        fn seal_seed(&self, _request: &SeedCreateRequest) -> Result<()> {
            Ok(())
        }

        fn unseal_seed(
            &self,
            _profile: &SeedProfile,
            _auth_source: &SeedOpenAuthSource,
        ) -> Result<SeedMaterial> {
            Ok(SecretBox::new(Box::new(self.seed.clone())))
        }
    }

    fn seed_profile(root: &Path, algorithm: Algorithm, uses: Vec<UseCase>) -> Profile {
        Profile::new(
            "seed-verifier".to_string(),
            algorithm,
            uses,
            ModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            StateLayout::new(root.to_path_buf()),
        )
    }

    fn example_verify_material() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let message = b"hello from native verify".to_vec();
        let signing_key = P256SigningKey::from_bytes((&[7u8; 32]).into()).expect("signing key");
        let signature: P256Signature = signing_key.sign(&message);
        let public_key_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("public key der")
            .as_bytes()
            .to_vec();

        (
            message,
            signature.to_der().as_bytes().to_vec(),
            public_key_der,
        )
    }

    #[test]
    fn import_requires_explicit_confirmation() {
        let output = run(Cli {
            json: false,
            command: Command::Import(ImportArgs {
                bundle: PathBuf::from("backup.json"),
                profile: Some("restored-user".to_string()),
                state_dir: None,
                overwrite_existing: false,
                confirm: false,
            }),
        })
        .expect("cli output");
        let value: Value = serde_json::from_str(&output).expect("json output");

        assert_eq!(value["ok"], Value::Bool(false));
        assert_eq!(
            value["command"]["segments"],
            Value::Array(vec![
                Value::String("import".to_string()),
            ])
        );
        assert_eq!(
            value["error"]["code"],
            Value::String("validation".to_string())
        );
        assert!(value["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("--confirm"));
    }

    #[test]
    fn import_parses_confirm_flag() {
        let cli = Cli::try_parse_from([
            "tpm2-derive",
            "import",
            "--bundle",
            "backup.json",
            "--confirm",
        ])
        .expect("import should parse");

        let Command::Import(args) = cli.command else {
            panic!("expected import command");
        };
        assert_eq!(args.bundle, PathBuf::from("backup.json"));
        assert!(args.confirm);
        assert!(!args.overwrite_existing);
    }

    #[test]
    fn native_sign_executes_when_serialized_handle_exists() {
        let state_root = tempdir().expect("state root");
        let profile = native_profile(state_root.path(), Mode::Native, vec![UseCase::Sign]);
        profile
            .storage
            .state_layout
            .ensure_dirs()
            .expect("state dirs should exist");

        let handle_path = profile
            .storage
            .state_layout
            .objects_dir
            .join("prod-signer.handle");
        fs::write(&handle_path, b"serialized-handle").expect("handle file");

        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, b"hello from native sign").expect("input file");

        let plain_signature = vec![0x11; 64];
        let runner = RecordingNativeSignRunner::success(plain_signature.clone());
        let staged = stage_native_sign(
            &SignRequest {
                profile: profile.name.clone(),
                input: InputSource::Path {
                    path: input_path.clone(),
                },
            },
            &profile,
        )
        .expect("staged native sign");

        assert!(staged.ready_for_execution);

        let bytes_written =
            execute_native_sign_plan_with_runner(&staged.plan, &runner).expect("execute sign");
        let expected = crate::ops::native::subprocess::finalize_p256_signature(
            NativeSignatureFormat::Der,
            &plain_signature,
        )
        .expect("expected der");

        assert_eq!(bytes_written, expected.len());
        assert_eq!(
            fs::read(&staged.output_path).expect("output signature"),
            expected
        );
        assert!(!staged.digest_path.as_os_str().is_empty());
        assert_eq!(runner.invocations().len(), 1);
        assert!(!profile
            .storage
            .state_layout
            .objects_dir
            .join(&profile.name)
            .join("native-sign")
            .join("signature.p1363.bin")
            .exists());
    }

    #[test]
    fn native_sign_stays_planned_when_setup_material_is_missing() {
        let state_root = tempdir().expect("state root");
        let profile = native_profile(state_root.path(), Mode::Native, vec![UseCase::Sign]);
        let runner = RecordingNativeSignRunner::success(vec![0x22; 64]);

        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, b"plan only").expect("input file");

        let staged = stage_native_sign(
            &SignRequest {
                profile: profile.name.clone(),
                input: InputSource::Path { path: input_path },
            },
            &profile,
        )
        .expect("staged native sign");

        assert!(!staged.ready_for_execution);
        assert!(staged.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "native-key-handle-missing"
                && diagnostic
                    .message
                    .contains("will execute once native setup material is present")
        }));
        assert!(runner.invocations().is_empty());
    }

    #[test]
    fn native_verify_succeeds_for_valid_signature() {
        let state_root = tempdir().expect("state root");
        let profile = native_profile(
            state_root.path(),
            Mode::Native,
            vec![UseCase::Sign, UseCase::Verify],
        );
        profile.persist().expect("persist profile");

        let handle_path = profile
            .storage
            .state_layout
            .objects_dir
            .join("prod-signer.handle");
        fs::create_dir_all(handle_path.parent().expect("handle parent")).expect("handle dir");
        fs::write(&handle_path, b"serialized-handle").expect("handle file");

        let (message, signature_der, public_key_der) = example_verify_material();
        let input_path = state_root.path().join("input.bin");
        let signature_path = state_root.path().join("signature.der");
        fs::write(&input_path, &message).expect("input file");
        fs::write(&signature_path, &signature_der).expect("signature file");

        let output = run_verify_with_runner(
            true,
            VerifyArgs {
                profile: profile.name.clone(),
                input: input_path.display().to_string(),
                signature: signature_path.display().to_string(),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &RecordingNativePublicKeyRunner::success(public_key_der),
        )
        .expect("verify output");
        let value: Value = serde_json::from_str(&output).expect("json output");

        assert_eq!(value["ok"], Value::Bool(true));
        assert_eq!(value["result"]["verified"], Value::Bool(true));
        assert_eq!(
            value["result"]["signature_format"],
            Value::String("der".to_string())
        );
    }

    #[test]
    fn native_verify_returns_false_for_signature_mismatch() {
        let state_root = tempdir().expect("state root");
        let profile = native_profile(
            state_root.path(),
            Mode::Native,
            vec![UseCase::Sign, UseCase::Verify],
        );
        profile.persist().expect("persist profile");

        let handle_path = profile
            .storage
            .state_layout
            .objects_dir
            .join("prod-signer.handle");
        fs::create_dir_all(handle_path.parent().expect("handle parent")).expect("handle dir");
        fs::write(&handle_path, b"serialized-handle").expect("handle file");

        let (_message, signature_der, public_key_der) = example_verify_material();
        let input_path = state_root.path().join("input.bin");
        let signature_path = state_root.path().join("signature.der");
        fs::write(&input_path, b"wrong message").expect("input file");
        fs::write(&signature_path, &signature_der).expect("signature file");

        let runner = RecordingNativePublicKeyRunner::success(public_key_der);
        let output = run_verify_with_runner(
            true,
            VerifyArgs {
                profile: profile.name.clone(),
                input: input_path.display().to_string(),
                signature: signature_path.display().to_string(),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &runner,
        )
        .expect("verify output");
        let value: Value = serde_json::from_str(&output).expect("json output");

        assert_eq!(value["ok"], Value::Bool(true));
        assert_eq!(value["result"]["verified"], Value::Bool(false));
        assert_eq!(runner.invocations().len(), 1);
    }

    #[test]
    fn verify_rejects_double_stdin_before_reading() {
        let state_root = tempdir().expect("state root");
        let profile = native_profile(state_root.path(), Mode::Native, vec![UseCase::Verify]);

        let error = verify_native_with_runner(
            &VerifyRequest {
                profile: profile.name.clone(),
                input: InputSource::Stdin,
                signature: InputSource::Stdin,
            },
            &profile,
            &RecordingNativePublicKeyRunner::success(Vec::new()),
        )
        .expect_err("double stdin should fail");

        assert!(
            matches!(error, Error::Validation(message) if message.contains("both --input and --signature from stdin"))
        );
    }

    #[test]
    fn seed_verify_supports_ed25519_profiles() {
        let state_root = tempdir().expect("state root");
        let profile = seed_profile(state_root.path(), Algorithm::Ed25519, vec![UseCase::Verify]);
        let backend = FakeSeedBackend::new(&[0x42; 32]);
        let seed_request = seed_verify_open_request(&profile).expect("seed verify request");
        let derivation = match &seed_request.output {
            SeedOpenOutput::DerivedBytes(request) => request.clone(),
            SeedOpenOutput::RawSeed => unreachable!("seed verify uses derived bytes"),
        };
        let derived = HkdfSha256SeedDeriver
            .derive(&SecretBox::new(Box::new(vec![0x42; 32])), &derivation)
            .expect("derived seed");
        let derived_bytes: [u8; 32] = derived
            .expose_secret()
            .as_slice()
            .try_into()
            .expect("ed25519 seed bytes");
        let signing_key = Ed25519SigningKey::from_bytes(&derived_bytes);
        let message = b"hello from seed verify".to_vec();
        let signature = signing_key.sign(&message).to_bytes().to_vec();

        let input_path = state_root.path().join("input.bin");
        let signature_path = state_root.path().join("signature.raw");
        fs::write(&input_path, &message).expect("input file");
        fs::write(&signature_path, &signature).expect("signature file");

        let (result, diagnostics) = verify_seed_with_backend(
            &VerifyRequest {
                profile: profile.name.clone(),
                input: InputSource::Path { path: input_path },
                signature: InputSource::Path {
                    path: signature_path,
                },
            },
            &profile,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed verify result");

        assert!(result.verified);
        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.signature_format, VerifySignatureFormat::Raw);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "SEED_SOFTWARE_DERIVATION"
                && diagnostic.message.contains("software derivation")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "seed-verifier-derived"
                && diagnostic.message.contains(SEED_VERIFY_CHILD_KEY_NAMESPACE)
        }));
    }

    #[test]
    fn seed_verify_keeps_p256_error_explicit() {
        let state_root = tempdir().expect("state root");
        let profile = seed_profile(state_root.path(), Algorithm::P256, vec![UseCase::Verify]);
        let error = verify_seed_with_backend(
            &VerifyRequest {
                profile: profile.name.clone(),
                input: InputSource::Path {
                    path: state_root.path().join("input.bin"),
                },
                signature: InputSource::Path {
                    path: state_root.path().join("signature.bin"),
                },
            },
            &profile,
            &FakeSeedBackend::new(&[0x55; 32]),
            &HkdfSha256SeedDeriver,
        )
        .expect_err("seed p256 should stay explicit unsupported");

        assert!(
            matches!(error, Error::Unsupported(message) if message.contains("native mode remains the preferred path"))
        );
    }

    #[test]
    fn sign_keeps_explicit_unsupported_result_for_seed_mode() {
        let state_root = tempdir().expect("state root");
        let profile = native_profile(state_root.path(), Mode::Seed, vec![UseCase::Sign]);
        profile.persist().expect("persist profile");

        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, b"seed sign").expect("input file");

        let output = run(Cli {
            json: false,
            command: Command::Sign(SignArgs {
                profile: profile.name.clone(),
                input: input_path.display().to_string(),
                state_dir: Some(state_root.path().to_path_buf()),
            }),
        })
        .expect("cli output");
        let value: Value = serde_json::from_str(&output).expect("json output");

        assert_eq!(value["ok"], Value::Bool(false));
        assert_eq!(
            value["error"]["code"],
            Value::String("unsupported".to_string())
        );
        assert!(value["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("seed-mode profiles"));
    }
}
