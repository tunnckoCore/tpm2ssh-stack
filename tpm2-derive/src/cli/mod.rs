mod args;
mod render;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use args::{
    AlgorithmArg, DecryptArgs, DeriveArgs, DeriveFormatArg, EncryptArgs, ExportArgs,
    ExportFormatArg, ExportKindArg, IdentityArgs, InspectArgs, ModeArg, SignArgs, SignFormatArg,
    SshAddArgs, UseArg, VerifyArgs, VerifyFormatArg,
};
pub use args::{Cli, Command};
use render::{failure, success, success_with_diagnostics};

use crate::backend::{CapabilityProbe, CommandRunner, ProcessCommandRunner, default_probe};
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, CommandPath, DecryptRequest, DerivationOverrides, DeriveRequest, EncryptRequest,
    ErrorEnvelope, ExportKind, ExportRequest, Format, IdentityCreateRequest, InputFormat,
    InputSource, InspectRequest, ModePreference, PendingOperation, SignRequest, SshAddRequest,
    UseCase, VerifyRequest,
};
use crate::ops;
use crate::ops::sign::SignOperationResult;

#[cfg(test)]
use crate::model::{Identity, Mode};
#[cfg(test)]
use crate::ops::sign::{
    SEED_SIGNING_KEY_NAMESPACE, SeedSignatureFormat, execute_native_sign_plan_with_runner,
    seed_sign_open_request, sign_seed_p256, sign_seed_secp256k1, sign_seed_with_backend,
    stage_native_sign,
};
#[cfg(test)]
use crate::ops::verify::{
    VerifySignatureFormat, seed_verify_open_request, verify_native_with_runner,
    verify_seed_with_backend,
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
            UseArg::All => Self::All,
            UseArg::Sign => Self::Sign,
            UseArg::Verify => Self::Verify,
            UseArg::Derive => Self::Derive,
            UseArg::Ssh => Self::Ssh,
            UseArg::Encrypt => Self::Encrypt,
            UseArg::Decrypt => Self::Decrypt,
            UseArg::ExportSecret => Self::ExportSecret,
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
            ExportKindArg::SecretKey => Self::SecretKey,
            ExportKindArg::Keypair => Self::Keypair,
        }
    }
}

impl From<DeriveFormatArg> for Format {
    fn from(value: DeriveFormatArg) -> Self {
        match value {
            DeriveFormatArg::Hex => Self::Hex,
            DeriveFormatArg::Base64 => Self::Base64,
        }
    }
}

impl From<SignFormatArg> for Format {
    fn from(value: SignFormatArg) -> Self {
        match value {
            SignFormatArg::Der => Self::Der,
            SignFormatArg::Hex => Self::Hex,
            SignFormatArg::Base64 => Self::Base64,
        }
    }
}

impl From<VerifyFormatArg> for InputFormat {
    fn from(value: VerifyFormatArg) -> Self {
        match value {
            VerifyFormatArg::Auto => Self::Auto,
            VerifyFormatArg::Der => Self::Der,
            VerifyFormatArg::Hex => Self::Hex,
            VerifyFormatArg::Base64 => Self::Base64,
        }
    }
}

impl From<ExportFormatArg> for Format {
    fn from(value: ExportFormatArg) -> Self {
        match value {
            ExportFormatArg::Der => Self::Der,
            ExportFormatArg::Pem => Self::Pem,
            ExportFormatArg::Openssh => Self::Openssh,
            ExportFormatArg::EthereumAddress => Self::EthereumAddress,
            ExportFormatArg::Hex => Self::Hex,
            ExportFormatArg::Base64 => Self::Base64,
        }
    }
}

fn derivation_overrides(args: args::DerivationInputArgs) -> DerivationOverrides {
    DerivationOverrides {
        org: args.org,
        purpose: args.purpose,
        context: args.context.into_iter().collect(),
    }
}

fn identity_create_uses(uses: Vec<UseArg>) -> Vec<UseCase> {
    let mut resolved: Vec<_> = uses.into_iter().map(Into::into).collect();
    resolved.sort();
    resolved.dedup();
    resolved
}

pub fn run(cli: Cli) -> Result<String> {
    let probe = default_probe();

    match cli.command {
        Command::Inspect(args) => run_inspect(cli.json, &probe, args),
        Command::Identity(args) => run_identity(cli.json, &probe, args),
        Command::Derive(args) => run_derive(cli.json, args),
        Command::Sign(args) => run_sign(cli.json, args),
        Command::Verify(args) => run_verify(cli.json, args),
        Command::Encrypt(args) => run_encrypt(cli.json, args),
        Command::Decrypt(args) => run_decrypt(cli.json, args),
        Command::Export(args) => run_export(cli.json, args),
        Command::SshAdd(args) => run_ssh_add(cli.json, args),
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

fn run_identity(json: bool, probe: &dyn CapabilityProbe, args: IdentityArgs) -> Result<String> {
    let request = IdentityCreateRequest {
        identity: args.identity,
        algorithm: args.algorithm.into(),
        uses: identity_create_uses(args.uses),
        requested_mode: args.mode.into(),
        defaults: derivation_overrides(args.defaults),
        state_dir: args.state_dir,
        dry_run: args.dry_run,
    };

    match ops::resolve_identity(probe, &request) {
        Ok(result) => success(json, CommandPath::from_segments(["identity"]), result),
        Err(error) => failure(
            json,
            CommandPath::from_segments(["identity"]),
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
        identity: args.identity.clone(),
        derivation: derivation_overrides(args.derivation),
        length: args.length,
        format: args.format.into(),
        output: args.output,
    };

    match ops::load_identity(&request.identity, args.state_dir.clone()) {
        Ok(identity) => {
            let runner = ProcessCommandRunner;
            match ops::derive::execute_with_defaults(&identity, &request, &runner) {
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
        identity: args.identity,
        kind: args.kind.into(),
        output: args.output,
        format: args.format.map(Into::into),
        state_dir: args.state_dir,
        reason: args.reason,
        confirm: args.confirm,
        derivation: derivation_overrides(args.derivation),
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

fn run_ssh_add(json: bool, args: SshAddArgs) -> Result<String> {
    let command = CommandPath::from_segments(["ssh-add"]);
    let request = SshAddRequest {
        identity: args.identity.clone(),
        comment: args.comment.clone(),
        socket: args.socket.clone(),
        state_dir: args.state_dir.clone(),
        derivation: derivation_overrides(args.derivation.clone()),
    };

    let identity = match ops::load_identity(&args.identity, args.state_dir.clone()) {
        Ok(identity) => identity,
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

    match ops::ssh::add_with_defaults(&identity, &request) {
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

fn run_encrypt(json: bool, args: EncryptArgs) -> Result<String> {
    let command = CommandPath::from_segments(["encrypt"]);
    let identity = match ops::load_identity(&args.identity, args.state_dir.clone()) {
        Ok(identity) => identity,
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

    let input_bytes = load_input_bytes(&parse_input_source(&args.input), "encrypt input")?;
    let derivation = derivation_overrides(args.derivation.clone());
    let runner = ProcessCommandRunner;
    match ops::encrypt::encrypt_with_defaults(&identity, &input_bytes, &derivation, &runner) {
        Ok(mut result) => {
            if let Some(ref output) = args.output {
                let ct = result
                    .ciphertext
                    .as_ref()
                    .map(|h| hex_decode_bytes(h))
                    .unwrap_or_default();
                write_output_file(output, &ct)?;
                result.output_path = Some(output.clone());
                result.ciphertext = None;
            }
            success(json, command, result)
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

fn run_decrypt(json: bool, args: DecryptArgs) -> Result<String> {
    let command = CommandPath::from_segments(["decrypt"]);
    let identity = match ops::load_identity(&args.identity, args.state_dir.clone()) {
        Ok(identity) => identity,
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

    let raw_input = load_input_bytes(&parse_input_source(&args.input), "decrypt input")?;
    // Try to interpret as hex first (the format we emit), otherwise use raw bytes.
    let ciphertext = try_hex_decode(&raw_input).unwrap_or(raw_input);
    let derivation = derivation_overrides(args.derivation.clone());
    let runner = ProcessCommandRunner;
    match ops::encrypt::decrypt_with_defaults(&identity, &ciphertext, &derivation, &runner) {
        Ok(mut result) => {
            if let Some(ref output) = args.output {
                let pt = result
                    .plaintext
                    .as_ref()
                    .map(|h| hex_decode_bytes(h))
                    .unwrap_or_default();
                write_output_file(output, &pt)?;
                result.output_path = Some(output.clone());
                result.plaintext = None;
            }
            success(json, command, result)
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
        identity: args.identity.clone(),
        input: parse_input_source(&args.input),
        format: args.format.into(),
        output: args.output,
    };
    let derivation = derivation_overrides(args.derivation.clone());
    let command = CommandPath::from_segments(["sign"]);

    let identity = match ops::load_identity(&args.identity, args.state_dir.clone()) {
        Ok(identity) => identity,
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
            "loaded-identity",
            format!(
                "loaded identity '{}' from '{}'",
                identity.name,
                identity.storage.identity_path.display()
            ),
        ),
        crate::model::Diagnostic::info(
            "identity-mode",
            format!(
                "sign request is bound to resolved mode {:?}",
                identity.mode.resolved
            ),
        ),
    ];

    match ops::sign::execute_with_defaults(&identity, &request, &derivation) {
        Ok((result, sign_diagnostics)) => {
            diagnostics.extend(sign_diagnostics);
            match result {
                SignOperationResult::Native(result) => {
                    success_with_diagnostics(json, command, result, diagnostics)
                }
                SignOperationResult::Derived(result) => {
                    success_with_diagnostics(json, command, result, diagnostics)
                }
            }
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

fn run_verify(json: bool, args: VerifyArgs) -> Result<String> {
    run_verify_with_runner(json, args, &ProcessCommandRunner)
}

fn run_verify_with_runner<R>(json: bool, args: VerifyArgs, runner: &R) -> Result<String>
where
    R: CommandRunner,
{
    let request = VerifyRequest {
        identity: args.identity.clone(),
        input: parse_input_source(&args.input),
        signature: parse_input_source(&args.signature),
        format: args.format.into(),
    };
    let derivation = derivation_overrides(args.derivation.clone());
    let command = CommandPath::from_segments(["verify"]);

    let identity = match ops::load_identity(&args.identity, args.state_dir.clone()) {
        Ok(identity) => identity,
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
            "loaded-identity",
            format!(
                "loaded identity '{}' from '{}'",
                identity.name,
                identity.storage.identity_path.display()
            ),
        ),
        crate::model::Diagnostic::info(
            "identity-mode",
            format!(
                "verify request is bound to resolved mode {:?}",
                identity.mode.resolved
            ),
        ),
    ];

    match ops::verify::execute_with_runner(&identity, &request, &derivation, runner) {
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

fn export_command_path(kind: ExportKind) -> CommandPath {
    match kind {
        ExportKind::PublicKey => CommandPath::from_segments(["export", "public-key"]),
        ExportKind::SecretKey => CommandPath::from_segments(["export", "secret-key"]),
        ExportKind::Keypair => CommandPath::from_segments(["export", "keypair"]),
    }
}

#[allow(dead_code)]
fn run_placeholder(
    json: bool,
    command: CommandPath,
    identity: String,
    operation: &str,
    summary: String,
) -> Result<String> {
    let _request_marker = build_placeholder_request(operation, identity);

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

fn parse_input_source(input: &str) -> InputSource {
    if input == "-" {
        InputSource::Stdin
    } else {
        InputSource::Path {
            path: PathBuf::from(input),
        }
    }
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

fn hex_decode_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            hex.get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect()
}

fn try_hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(input).ok()?.trim();
    if s.is_empty() || s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex_decode_bytes(s))
}

fn write_output_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    fs::create_dir_all(parent).map_err(|e| {
        Error::State(format!(
            "failed to create output directory '{}': {e}",
            parent.display()
        ))
    })?;

    if let Ok(metadata) = fs::symlink_metadata(path) {
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(Error::Validation(format!(
                "output '{}' must not be a symlink",
                path.display()
            )));
        }
        if !file_type.is_file() {
            return Err(Error::Validation(format!(
                "output '{}' must be a regular file path",
                path.display()
            )));
        }
    }

    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("output"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(&temp_path).map_err(|e| {
        Error::State(format!(
            "failed to create temp output file '{}': {e}",
            temp_path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                let _ = fs::remove_file(&temp_path);
                Error::State(format!(
                    "failed to harden temp output permissions '{}': {e}",
                    temp_path.display()
                ))
            })?;
    }
    use std::io::Write as _;
    if let Err(e) = file.write_all(data) {
        let _ = fs::remove_file(&temp_path);
        return Err(Error::State(format!(
            "failed to write output to '{}': {e}",
            temp_path.display()
        )));
    }
    drop(file);

    fs::rename(&temp_path, path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        Error::State(format!(
            "failed to move output into place '{}' -> '{}': {e}",
            temp_path.display(),
            path.display()
        ))
    })
}

#[allow(dead_code)]
fn build_placeholder_request(operation: &str, identity: String) -> serde_json::Value {
    match operation {
        "derive" => serde_json::to_value(DeriveRequest {
            identity,
            derivation: DerivationOverrides {
                org: Some("planned".to_string()),
                purpose: Some("planned".to_string()),
                context: BTreeMap::new(),
            },
            length: 32,
            format: Format::Hex,
            output: None,
        })
        .unwrap_or_default(),
        "sign" => serde_json::to_value(SignRequest {
            identity,
            input: InputSource::Stdin,
            format: Format::Hex,
            output: None,
        })
        .unwrap_or_default(),
        "verify" => serde_json::to_value(VerifyRequest {
            identity,
            input: InputSource::Stdin,
            signature: InputSource::Stdin,
            format: InputFormat::Auto,
        })
        .unwrap_or_default(),
        "encrypt" => serde_json::to_value(EncryptRequest {
            identity,
            input: InputSource::Stdin,
            output: None,
        })
        .unwrap_or_default(),
        "decrypt" => serde_json::to_value(DecryptRequest {
            identity,
            input: InputSource::Stdin,
            output: None,
        })
        .unwrap_or_default(),
        "export" => serde_json::to_value(ExportRequest {
            identity,
            kind: ExportKind::PublicKey,
            output: None,
            format: None,
            state_dir: None,
            reason: None,
            confirm: false,
            derivation: DerivationOverrides::default(),
        })
        .unwrap_or_default(),
        "ssh-add" => serde_json::to_value(SshAddRequest {
            identity,
            comment: None,
            socket: None,
            state_dir: None,
            derivation: DerivationOverrides::default(),
        })
        .unwrap_or_default(),
        _ => serde_json::to_value(PendingOperation {
            implemented: false,
            operation: operation.to_string(),
            identity: Some(identity),
            summary: "planned command".to_string(),
        })
        .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::path::Path;

    use crate::backend::{CommandInvocation, CommandOutput};
    use crate::ops::native::NativeSignatureFormat;
    use crate::ops::seed::{
        HkdfSha256SeedDeriver, SeedBackend, SeedIdentity, SeedOpenAuthSource, SeedOpenOutput,
    };
    use clap::Parser as _;
    use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
    use p256::pkcs8::EncodePublicKey as _;
    use secrecy::ExposeSecret;
    use secrecy::SecretBox;
    use serde_json::Value;
    use tempfile::tempdir;

    use crate::model::{IdentityModeResolution, StateLayout};
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

    fn native_profile(root: &Path, mode: Mode, uses: Vec<UseCase>) -> Identity {
        Identity::new(
            "prod-signer".to_string(),
            Algorithm::P256,
            uses,
            IdentityModeResolution {
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
            _profile: &SeedIdentity,
            _auth_source: &SeedOpenAuthSource,
        ) -> Result<SeedMaterial> {
            Ok(SecretBox::new(Box::new(self.seed.clone())))
        }
    }

    fn seed_profile(root: &Path, algorithm: Algorithm, uses: Vec<UseCase>) -> Identity {
        Identity::new(
            "seed-verifier".to_string(),
            algorithm,
            uses,
            IdentityModeResolution {
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
    fn identity_create_uses_preserves_all_until_mode_resolution() {
        let uses = identity_create_uses(vec![UseArg::All, UseArg::Sign]);
        assert!(uses.contains(&UseCase::All));
        assert!(uses.contains(&UseCase::Sign));
    }

    #[test]
    fn native_sign_executes_when_serialized_handle_exists() {
        let state_root = tempdir().expect("state root");
        let identity = native_profile(state_root.path(), Mode::Native, vec![UseCase::Sign]);
        identity
            .storage
            .state_layout
            .ensure_dirs()
            .expect("state dirs should exist");

        let handle_path = identity
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
                identity: identity.name.clone(),
                input: InputSource::Path {
                    path: input_path.clone(),
                },
                format: Format::Hex,
                output: None,
            },
            &identity,
        )
        .expect("staged native sign");

        assert!(staged.ready_for_execution);

        let signature_bytes =
            execute_native_sign_plan_with_runner(&staged.plan, &runner).expect("execute sign");
        let expected = crate::ops::native::subprocess::finalize_p256_signature(
            NativeSignatureFormat::Der,
            &plain_signature,
        )
        .expect("expected der");

        assert_eq!(signature_bytes, expected);
        assert_eq!(
            fs::read(&staged.plan.output_path).expect("output signature"),
            signature_bytes
        );
        assert!(!staged.digest_path.as_os_str().is_empty());
        assert_eq!(runner.invocations().len(), 1);
        assert!(
            !identity
                .storage
                .state_layout
                .objects_dir
                .join(&identity.name)
                .join("native-sign")
                .join("signature.p1363.bin")
                .exists()
        );
    }

    #[test]
    fn native_sign_stays_planned_when_setup_material_is_missing() {
        let state_root = tempdir().expect("state root");
        let identity = native_profile(state_root.path(), Mode::Native, vec![UseCase::Sign]);
        let runner = RecordingNativeSignRunner::success(vec![0x22; 64]);

        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, b"plan only").expect("input file");

        let staged = stage_native_sign(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                format: Format::Hex,
                output: None,
            },
            &identity,
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
        let identity = native_profile(
            state_root.path(),
            Mode::Native,
            vec![UseCase::Sign, UseCase::Verify],
        );
        identity.persist().expect("persist identity");

        let handle_path = identity
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
                identity: identity.name.clone(),
                derivation: Default::default(),
                input: input_path.display().to_string(),
                signature: signature_path.display().to_string(),
                state_dir: Some(state_root.path().to_path_buf()),
                format: VerifyFormatArg::Auto,
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
        let identity = native_profile(
            state_root.path(),
            Mode::Native,
            vec![UseCase::Sign, UseCase::Verify],
        );
        identity.persist().expect("persist identity");

        let handle_path = identity
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
                identity: identity.name.clone(),
                derivation: Default::default(),
                input: input_path.display().to_string(),
                signature: signature_path.display().to_string(),
                state_dir: Some(state_root.path().to_path_buf()),
                format: VerifyFormatArg::Auto,
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
        let identity = native_profile(state_root.path(), Mode::Native, vec![UseCase::Verify]);

        let error = verify_native_with_runner(
            &VerifyRequest {
                identity: identity.name.clone(),
                input: InputSource::Stdin,
                signature: InputSource::Stdin,
                format: InputFormat::Auto,
            },
            &identity,
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
        let identity = seed_profile(state_root.path(), Algorithm::Ed25519, vec![UseCase::Verify]);
        let backend = FakeSeedBackend::new(&[0x42; 32]);
        let seed_request = seed_verify_open_request(&identity).expect("seed verify request");
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
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                signature: InputSource::Path {
                    path: signature_path,
                },
                format: InputFormat::Auto,
            },
            &identity,
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
                && diagnostic.message.contains(SEED_SIGNING_KEY_NAMESPACE)
        }));
    }

    #[test]
    fn seed_verify_supports_p256_profiles() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Verify],
        );
        let backend = FakeSeedBackend::new(&[0x55; 32]);

        // Sign a message first to get valid signature material
        let message = b"hello from seed p256 verify".to_vec();
        let seed_request = seed_sign_open_request(&identity).expect("seed sign request");
        let derivation = match &seed_request.output {
            SeedOpenOutput::DerivedBytes(request) => request.clone(),
            SeedOpenOutput::RawSeed => unreachable!("seed sign uses derived bytes"),
        };
        let derived = HkdfSha256SeedDeriver
            .derive(&SecretBox::new(Box::new(vec![0x55; 32])), &derivation)
            .expect("derived seed");
        let (signature, _format) =
            sign_seed_p256(&message, derived.expose_secret(), &identity).expect("seed p256 sign");

        let input_path = state_root.path().join("input.bin");
        let signature_path = state_root.path().join("signature.der");
        fs::write(&input_path, &message).expect("input file");
        fs::write(&signature_path, &signature).expect("signature file");

        let (result, diagnostics) = verify_seed_with_backend(
            &VerifyRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                signature: InputSource::Path {
                    path: signature_path,
                },
                format: InputFormat::Auto,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed p256 verify result");

        assert!(result.verified);
        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.signature_format, VerifySignatureFormat::Der);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "seed-verifier-derived"
                && diagnostic.message.contains(SEED_SIGNING_KEY_NAMESPACE)
        }));
    }

    #[test]
    fn seed_sign_succeeds_for_ed25519_profiles() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(state_root.path(), Algorithm::Ed25519, vec![UseCase::Sign]);
        let backend = FakeSeedBackend::new(&[0x42; 32]);

        let message = b"hello from seed ed25519 sign".to_vec();
        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, &message).expect("input file");

        let (result, diagnostics) = sign_seed_with_backend(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                format: Format::Hex,
                output: None,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed ed25519 sign result");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.signature_format, SeedSignatureFormat::Raw);
        assert_eq!(result.signature_bytes, 64);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "seed-signer-derived"
                && diagnostic.message.contains(SEED_SIGNING_KEY_NAMESPACE)
        }));
    }

    #[test]
    fn seed_sign_succeeds_for_p256_profiles() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(state_root.path(), Algorithm::P256, vec![UseCase::Sign]);
        let backend = FakeSeedBackend::new(&[0x42; 32]);

        let message = b"hello from seed p256 sign".to_vec();
        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, &message).expect("input file");

        let (result, _diagnostics) = sign_seed_with_backend(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                format: Format::Hex,
                output: None,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed p256 sign result");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.signature_format, SeedSignatureFormat::Der);
        assert!(result.signature_bytes > 0);
    }

    #[test]
    fn seed_sign_succeeds_for_secp256k1_profiles() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(state_root.path(), Algorithm::Secp256k1, vec![UseCase::Sign]);
        let backend = FakeSeedBackend::new(&[0x42; 32]);

        let message = b"hello from seed secp256k1 sign".to_vec();
        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, &message).expect("input file");

        let (result, _diagnostics) = sign_seed_with_backend(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                format: Format::Hex,
                output: None,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secp256k1 sign result");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.signature_format, SeedSignatureFormat::Der);
        assert!(result.signature_bytes > 0);
    }

    #[test]
    fn seed_sign_rejects_profiles_without_sign_use() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(state_root.path(), Algorithm::Ed25519, vec![UseCase::Verify]);
        let backend = FakeSeedBackend::new(&[0x42; 32]);

        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, b"test").expect("input file");

        let error = sign_seed_with_backend(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                format: Format::Hex,
                output: None,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect_err("seed sign without sign use should fail");

        assert!(matches!(error, Error::Unsupported(message) if message.contains("sign use")));
    }

    #[test]
    fn seed_sign_then_verify_round_trip_ed25519() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::Verify],
        );
        let backend = FakeSeedBackend::new(&[0x77; 32]);
        let message = b"round-trip ed25519 test".to_vec();

        // Sign
        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, &message).expect("input file");
        let (sign_result, _) = sign_seed_with_backend(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path {
                    path: input_path.clone(),
                },
                format: Format::Hex,
                output: None,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed ed25519 sign");

        // Decode hex signature
        let sig_bytes = hex_decode_test(sign_result.signature.as_deref().expect("signature"));
        let signature_path = state_root.path().join("signature.raw");
        fs::write(&signature_path, &sig_bytes).expect("signature file");

        // Verify
        let (verify_result, _) = verify_seed_with_backend(
            &VerifyRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                signature: InputSource::Path {
                    path: signature_path,
                },
                format: InputFormat::Auto,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed ed25519 verify");

        assert!(verify_result.verified);
    }

    #[test]
    fn seed_sign_then_verify_round_trip_p256() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Verify],
        );
        let backend = FakeSeedBackend::new(&[0x77; 32]);
        let message = b"round-trip p256 test".to_vec();

        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, &message).expect("input file");
        let (sign_result, _) = sign_seed_with_backend(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path {
                    path: input_path.clone(),
                },
                format: Format::Hex,
                output: None,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed p256 sign");

        let sig_bytes = hex_decode_test(sign_result.signature.as_deref().expect("signature"));
        let signature_path = state_root.path().join("signature.der");
        fs::write(&signature_path, &sig_bytes).expect("signature file");

        let (verify_result, _) = verify_seed_with_backend(
            &VerifyRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                signature: InputSource::Path {
                    path: signature_path,
                },
                format: InputFormat::Auto,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed p256 verify");

        assert!(verify_result.verified);
    }

    #[test]
    fn seed_sign_then_verify_round_trip_secp256k1() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Algorithm::Secp256k1,
            vec![UseCase::Sign, UseCase::Verify],
        );
        let backend = FakeSeedBackend::new(&[0x77; 32]);
        let message = b"round-trip secp256k1 test".to_vec();

        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, &message).expect("input file");
        let (sign_result, _) = sign_seed_with_backend(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path {
                    path: input_path.clone(),
                },
                format: Format::Hex,
                output: None,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secp256k1 sign");

        let sig_bytes = hex_decode_test(sign_result.signature.as_deref().expect("signature"));
        let signature_path = state_root.path().join("signature.der");
        fs::write(&signature_path, &sig_bytes).expect("signature file");

        let (verify_result, _) = verify_seed_with_backend(
            &VerifyRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                signature: InputSource::Path {
                    path: signature_path,
                },
                format: InputFormat::Auto,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secp256k1 verify");

        assert!(verify_result.verified);
    }

    #[test]
    fn seed_verify_rejects_wrong_message_p256() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Verify],
        );
        let backend = FakeSeedBackend::new(&[0x77; 32]);

        let input_path = state_root.path().join("input.bin");
        fs::write(&input_path, b"original message").expect("input file");
        let (sign_result, _) = sign_seed_with_backend(
            &SignRequest {
                identity: identity.name.clone(),
                input: InputSource::Path {
                    path: input_path.clone(),
                },
                format: Format::Hex,
                output: None,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed p256 sign");

        let sig_bytes = hex_decode_test(sign_result.signature.as_deref().expect("signature"));
        let signature_path = state_root.path().join("signature.der");
        fs::write(&signature_path, &sig_bytes).expect("signature file");

        // Write a different message
        fs::write(&input_path, b"tampered message").expect("tampered input");

        let (verify_result, _) = verify_seed_with_backend(
            &VerifyRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                signature: InputSource::Path {
                    path: signature_path,
                },
                format: InputFormat::Auto,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed p256 verify");

        assert!(!verify_result.verified);
    }

    #[test]
    fn seed_verify_supports_secp256k1_profiles() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Algorithm::Secp256k1,
            vec![UseCase::Sign, UseCase::Verify],
        );
        let backend = FakeSeedBackend::new(&[0x55; 32]);

        let message = b"hello from seed secp256k1 verify".to_vec();
        let seed_request = seed_sign_open_request(&identity).expect("seed sign request");
        let derivation = match &seed_request.output {
            SeedOpenOutput::DerivedBytes(request) => request.clone(),
            SeedOpenOutput::RawSeed => unreachable!("seed sign uses derived bytes"),
        };
        let derived = HkdfSha256SeedDeriver
            .derive(&SecretBox::new(Box::new(vec![0x55; 32])), &derivation)
            .expect("derived seed");
        let (signature, _format) =
            sign_seed_secp256k1(&message, derived.expose_secret(), &identity)
                .expect("seed secp256k1 sign");

        let input_path = state_root.path().join("input.bin");
        let signature_path = state_root.path().join("signature.der");
        fs::write(&input_path, &message).expect("input file");
        fs::write(&signature_path, &signature).expect("signature file");

        let (result, diagnostics) = verify_seed_with_backend(
            &VerifyRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                signature: InputSource::Path {
                    path: signature_path,
                },
                format: InputFormat::Auto,
            },
            &identity,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed secp256k1 verify result");

        assert!(result.verified);
        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.signature_format, VerifySignatureFormat::Der);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "seed-verifier-derived"
                && diagnostic.message.contains(SEED_SIGNING_KEY_NAMESPACE)
        }));
    }

    fn hex_decode_test(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
