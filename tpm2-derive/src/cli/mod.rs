mod args;
mod render;

use std::collections::BTreeMap;

pub use args::{Cli, Command};
use args::{
    AlgorithmArg, DecryptArgs, DeriveArgs, EncryptArgs, ExportArgs, ExportKindArg, InspectArgs,
    ModeArg, SetupArgs, SignArgs, SshAgentAddArgs, SshAgentCommand, SshCommand, UseArg,
    VerifyArgs,
};
use render::{failure, success};

use crate::backend::HeuristicProbe;
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, CommandPath, DecryptRequest, DerivationContext, DeriveRequest, EncryptRequest,
    ErrorEnvelope, ExportKind, ExportRequest, InputSource, InspectRequest, ModePreference,
    PendingOperation, SetupRequest, SignRequest, SshAgentAddRequest, UseCase, VerifyRequest,
};
use crate::ops;

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
    let probe = HeuristicProbe;

    match cli.command {
        Command::Inspect(args) => run_inspect(cli.json, &probe, args),
        Command::Setup(args) => run_setup(cli.json, &probe, args),
        Command::Derive(args) => run_placeholder(
            cli.json,
            CommandPath::from_segments(["derive"]),
            args.profile.clone(),
            "derive",
            derive_summary(&args),
        ),
        Command::Sign(args) => run_placeholder(
            cli.json,
            CommandPath::from_segments(["sign"]),
            args.profile.clone(),
            "sign",
            sign_summary(&args),
        ),
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

fn run_inspect(json: bool, probe: &HeuristicProbe, args: InspectArgs) -> Result<String> {
    let request = InspectRequest {
        algorithm: args.algorithm.map(Into::into),
        uses: args.uses.into_iter().map(Into::into).collect(),
    };

    let report = ops::inspect(probe, &request);
    success(json, CommandPath::from_segments(["inspect"]), report)
}

fn run_setup(json: bool, probe: &HeuristicProbe, args: SetupArgs) -> Result<String> {
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

fn run_placeholder(
    json: bool,
    command: CommandPath,
    profile: String,
    operation: &str,
    summary: String,
) -> Result<String> {
    let _request_marker = build_placeholder_request(operation, profile.clone());

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

fn sign_summary(args: &SignArgs) -> String {
    format!("profile={} input={} state=planned", args.profile, args.input)
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
