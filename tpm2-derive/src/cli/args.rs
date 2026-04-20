use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "tpm2-derive",
    version,
    about = "TPM-backed key operations with native, PRF, and seed modes"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Inspect(InspectArgs),
    Setup(SetupArgs),
    Derive(DeriveArgs),
    Sign(SignArgs),
    Verify(VerifyArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Export(ExportArgs),
    #[command(subcommand)]
    Ssh(SshCommand),
}

#[derive(Debug, Subcommand)]
pub enum SshCommand {
    #[command(name = "agent", subcommand)]
    Agent(SshAgentCommand),
}

#[derive(Debug, Subcommand)]
pub enum SshAgentCommand {
    Add(SshAgentAddArgs),
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    #[arg(long, value_enum)]
    pub algorithm: Option<AlgorithmArg>,
    #[arg(long = "use", value_enum)]
    pub uses: Vec<UseArg>,
}

#[derive(Debug, Args)]
pub struct SetupArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long, value_enum)]
    pub algorithm: AlgorithmArg,
    #[arg(long = "use", value_enum)]
    pub uses: Vec<UseArg>,
    #[arg(long, value_enum, default_value_t = ModeArg::Auto)]
    pub mode: ModeArg,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DeriveArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long)]
    pub purpose: String,
    #[arg(long)]
    pub namespace: String,
    #[arg(long)]
    pub label: Option<String>,
    #[arg(long = "context", value_parser = parse_key_value)]
    pub context: Vec<(String, String)>,
    #[arg(long, default_value_t = 32)]
    pub length: u16,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long, default_value = "-")]
    pub input: String,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long, default_value = "-")]
    pub input: String,
    #[arg(long)]
    pub signature: String,
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long, default_value = "-")]
    pub input: String,
}

#[derive(Debug, Args)]
pub struct DecryptArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long, default_value = "-")]
    pub input: String,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long, value_enum)]
    pub kind: ExportKindArg,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub reason: Option<String>,
    #[arg(long)]
    pub confirm_recovery_export: bool,
    #[arg(long)]
    pub confirm_sealed_at_rest_boundary: bool,
    #[arg(long)]
    pub confirmation_phrase: Option<String>,
}

#[derive(Debug, Args)]
pub struct SshAgentAddArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AlgorithmArg {
    P256,
    Ed25519,
    Secp256k1,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum UseArg {
    Sign,
    Verify,
    Derive,
    Ssh,
    SshAgent,
    Ethereum,
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum ModeArg {
    #[default]
    Auto,
    Native,
    Prf,
    Seed,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportKindArg {
    PublicKey,
    RecoveryBundle,
}

pub fn parse_key_value(value: &str) -> Result<(String, String), String> {
    let Some((key, value)) = value.split_once('=') else {
        return Err("context values must use key=value format".to_string());
    };

    if key.is_empty() {
        return Err("context keys must not be empty".to_string());
    }

    Ok((key.to_string(), value.to_string()))
}
