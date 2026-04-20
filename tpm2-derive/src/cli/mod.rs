mod args;
mod render;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub use args::{Cli, Command};
use args::{
    AlgorithmArg, DecryptArgs, DeriveArgs, EncryptArgs, ExportArgs, ExportKindArg, InspectArgs,
    ModeArg, SetupArgs, SignArgs, SshAgentAddArgs, SshAgentCommand, SshCommand, UseArg,
    VerifyArgs,
};
use render::{failure, success, success_with_diagnostics};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::backend::{CapabilityProbe, ProcessCommandRunner, default_probe};
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, CommandPath, DecryptRequest, DerivationContext, DeriveRequest, EncryptRequest,
    ErrorEnvelope, ExportKind, ExportRequest, InputSource, InspectRequest, Mode, ModePreference,
    PendingOperation, Profile, SetupRequest, SignRequest, SshAgentAddRequest, UseCase,
    VerifyRequest,
};
use crate::ops;
use crate::ops::native::subprocess::{
    NativeAuthSource, NativeKeyLocator, NativeSignArtifacts, NativeSignOptions, NativeSignPlan,
    plan_sign,
};
use crate::ops::native::{
    DigestAlgorithm, NativeKeyRef, NativeSignRequest, NativeSignatureFormat,
    NativeSignatureScheme,
};

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

pub fn run(cli: Cli) -> Result<String> {
    let probe = default_probe();

    match cli.command {
        Command::Inspect(args) => run_inspect(cli.json, &probe, args),
        Command::Setup(args) => run_setup(cli.json, &probe, args),
        Command::Derive(args) => run_derive(cli.json, args),
        Command::Sign(args) => run_sign(cli.json, args),
        Command::Verify(args) => run_placeholder(
            cli.json,
            CommandPath::from_segments(["verify"]),
            args.profile.clone(),
            "verify",
            verify_summary(&args),
        ),
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
        Command::Export(args) => run_placeholder(
            cli.json,
            CommandPath::from_segments(["export"]),
            args.profile.clone(),
            "export",
            export_summary(&args),
        ),
        Command::Ssh(SshCommand::Agent(SshAgentCommand::Add(args))) => run_placeholder(
            cli.json,
            CommandPath::from_segments(["ssh-agent", "add"]),
            args.profile.clone(),
            "ssh-agent add",
            ssh_agent_add_summary(&args),
        ),
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
            format!("sign request is bound to resolved mode {:?}", profile.mode.resolved),
        ),
    ];

    match profile.mode.resolved {
        Mode::Native => match stage_native_sign(&request, &profile) {
            Ok(staged) => {
                diagnostics.extend(staged.diagnostics.clone());
                success_with_diagnostics(
                    json,
                    command,
                    SignPlanResult {
                        profile,
                        request,
                        mode: Mode::Native,
                        state: "planned".to_string(),
                        digest_algorithm: staged.digest_algorithm,
                        input_bytes: staged.input_bytes,
                        digest_path: staged.digest_path,
                        output_path: staged.output_path,
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
        Mode::Prf => unsupported_sign_mode(
            json,
            command,
            profile.mode.resolved,
            diagnostics,
            "sign is not wired for PRF-mode profiles yet",
        ),
        Mode::Seed => unsupported_sign_mode(
            json,
            command,
            profile.mode.resolved,
            diagnostics,
            "sign is not wired for seed-mode profiles yet",
        ),
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
struct SignPlanResult {
    profile: Profile,
    request: SignRequest,
    mode: Mode,
    state: String,
    digest_algorithm: DigestAlgorithm,
    input_bytes: usize,
    digest_path: PathBuf,
    output_path: PathBuf,
    plan: NativeSignPlan,
}

#[derive(Debug, Clone)]
struct StagedNativeSign {
    digest_algorithm: DigestAlgorithm,
    input_bytes: usize,
    digest_path: PathBuf,
    output_path: PathBuf,
    plan: NativeSignPlan,
    diagnostics: Vec<crate::model::Diagnostic>,
}

fn unsupported_sign_mode(
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

    let runtime_dir = profile.storage.state_layout.objects_dir.join(&profile.name).join("native-sign");
    let native_dir = profile.storage.state_layout.objects_dir.join(&profile.name).join("native");
    let output_dir = profile.storage.state_layout.exports_dir.join(&profile.name).join("signatures");

    ensure_dir(&runtime_dir, "native sign runtime")?;
    ensure_dir(&native_dir, "native sign locator")?;
    ensure_dir(&output_dir, "native sign output")?;

    let input_bytes = load_sign_input(&request.input)?;
    if input_bytes.is_empty() {
        return Err(Error::Validation("sign input must not be empty".to_string()));
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

    let key_id = format!("{}-signing-key", profile.name);
    let handle_path = native_dir.join(format!("{key_id}.handle"));
    let plan = plan_sign(
        &NativeSignRequest {
            key: NativeKeyRef {
                profile: profile.name.clone(),
                key_id: key_id.clone(),
            },
            scheme: NativeSignatureScheme::Ecdsa,
            format: NativeSignatureFormat::Der,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest,
        },
        &NativeSignOptions {
            locator: NativeKeyLocator::SerializedHandle {
                path: handle_path.clone(),
            },
            auth: NativeAuthSource::Empty,
            artifacts: NativeSignArtifacts {
                digest_path: digest_path.clone(),
                signature_path: output_path.clone(),
                plain_signature_path: Some(plain_signature_path),
            },
        },
    )?;

    let mut diagnostics = plan.warnings.clone();
    if !handle_path.is_file() {
        diagnostics.push(crate::model::Diagnostic::warning(
            "native-key-handle-missing",
            format!(
                "serialized native key handle '{}' is not present yet; sign currently returns a concrete plan and staged digest, but execution still depends on setup materializing that handle",
                handle_path.display()
            ),
        ));
    }

    Ok(StagedNativeSign {
        digest_algorithm: DigestAlgorithm::Sha256,
        input_bytes: input_bytes.len(),
        digest_path,
        output_path,
        plan,
        diagnostics,
    })
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
    match input {
        InputSource::Stdin => {
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer).map_err(|error| {
                Error::State(format!("failed to read sign input from stdin: {error}"))
            })?;
            Ok(buffer)
        }
        InputSource::Path { path } => fs::read(path).map_err(|error| {
            Error::State(format!("failed to read sign input '{}': {error}", path.display()))
        }),
    }
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
        })
        .unwrap_or_default(),
        "ssh-agent add" => serde_json::to_value(SshAgentAddRequest {
            profile,
            comment: None,
            socket: None,
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

fn derive_summary(args: &DeriveArgs) -> String {
    format!(
        "profile={} purpose={} namespace={} length={} state=planned",
        args.profile, args.purpose, args.namespace, args.length
    )
}

fn verify_summary(args: &VerifyArgs) -> String {
    format!(
        "profile={} input={} signature={} state=planned",
        args.profile, args.input, args.signature
    )
}

fn encrypt_summary(args: &EncryptArgs) -> String {
    format!("profile={} input={} state=planned", args.profile, args.input)
}

fn decrypt_summary(args: &DecryptArgs) -> String {
    format!("profile={} input={} state=planned", args.profile, args.input)
}

fn export_summary(args: &ExportArgs) -> String {
    format!(
        "profile={} kind={:?} output={} state=planned",
        args.profile,
        args.kind,
        args.output
            .as_ref()
            .map(|path| path.as_path().display().to_string())
            .unwrap_or_else(|| "stdout".to_string())
    )
}

fn ssh_agent_add_summary(args: &SshAgentAddArgs) -> String {
    format!(
        "profile={} socket={} state=planned",
        args.profile,
        args.socket
            .as_ref()
            .map(|path| path.as_path().display().to_string())
            .unwrap_or_else(|| "SSH_AUTH_SOCK".to_string())
    )
}
