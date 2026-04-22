use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "tpm2-derive",
    version,
    about = "TPM-backed key operations with native, PRF, and seed modes",
    long_about = "TPM-backed key operations with native, PRF, and seed modes.\n\nUse 'inspect' to see what the local TPM can do, 'setup' to provision persistent state, 'import' to reseal an exported seed bundle into fresh TPM-backed state, and the operational subcommands ('derive', 'sign', 'verify', 'export', 'ssh agent add') to use an existing profile.\n\nImportant: SSH in this project does not imply Ed25519 only. P-256 is also a valid SSH/OpenSSH identity algorithm here. The direct 'tpm2-derive ssh agent add' path currently supports seed Ed25519 and seed P-256 profiles, while higher-level wrappers such as 'tpm2ssh' can provide broader user-facing SSH/Git flows.",
    after_help = "Examples:\n  tpm2-derive inspect --algorithm p256 --use sign --use verify\n  tpm2-derive setup --profile prod-signer --algorithm p256 --mode native --use sign --use verify\n  tpm2-derive sign --profile prod-signer --input message.bin\n  tpm2-derive derive --profile app-prf --purpose session --namespace com.example\n  tpm2-derive ssh agent add --profile seed-user\n  tpm2-derive export --profile prod-signer --kind public-key --format spki-pem --output prod-signer.pem\n  tpm2-derive export --profile seed-user --kind recovery-bundle --output backup.json --reason 'hardware migration' --confirm --confirm-phrase 'I understand this export weakens TPM-only protection'\n  tpm2-derive import --bundle backup.json --profile restored-user --confirm\n\nSSH quick guide:\n  - Want a direct tpm2-derive ssh-agent flow today? Use a seed/ed25519 or seed/p256 profile.\n  - Want a TPM-native signer? Use p256 + native for sign/verify."
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        help = "Emit structured JSON instead of plain output"
    )]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Probe TPM/tooling capabilities and recommended mode selection.
    Inspect(InspectArgs),
    /// Create or update a profile and materialize backend state unless --dry-run is used.
    Setup(SetupArgs),
    /// Derive deterministic bytes from a persisted PRF or seed profile.
    Derive(DeriveArgs),
    /// Sign input with a persisted profile; native P-256 is the main wired signing path today.
    Sign(SignArgs),
    /// Verify a signature against a persisted profile; native P-256 is the main wired verify path today.
    Verify(VerifyArgs),
    /// Encrypt data using a derived symmetric key from a persisted profile.
    Encrypt(EncryptArgs),
    /// Decrypt data previously encrypted with the encrypt command.
    Decrypt(DecryptArgs),
    /// Derive a keypair (secret key + public key) from a persisted profile.
    Keygen(KeygenArgs),
    /// Export public material or recovery artifacts from a persisted profile.
    Export(ExportArgs),
    /// Import a break-glass recovery bundle and reseal it into TPM-backed state.
    Import(ImportArgs),
    #[command(subcommand)]
    /// SSH-oriented operations.
    Ssh(SshCommand),
}

#[derive(Debug, Subcommand)]
pub enum SshCommand {
    #[command(
        name = "agent",
        subcommand,
        about = "Interact with an ssh-agent using a persisted profile"
    )]
    Agent(SshAgentCommand),
}

#[derive(Debug, Subcommand)]
pub enum SshAgentCommand {
    /// Add a derived private key to ssh-agent; this direct CLI path currently supports seed ed25519 and seed p256 profiles.
    Add(SshAgentAddArgs),
}

#[derive(Debug, Args)]
#[command(about = "Probe local TPM/tool availability and mode recommendations")]
pub struct InspectArgs {
    #[arg(long, value_enum, help = "Limit the probe to an algorithm of interest")]
    pub algorithm: Option<AlgorithmArg>,
    #[arg(
        long = "use",
        value_enum,
        help = "Requested operation(s) to evaluate during recommendation"
    )]
    pub uses: Vec<UseArg>,
}

#[derive(Debug, Args)]
#[command(about = "Create or update a profile and provision TPM-backed state")]
pub struct SetupArgs {
    #[arg(long, help = "Profile name used to persist metadata and backend state")]
    pub profile: String,
    #[arg(long, value_enum, help = "Algorithm the profile is centered on")]
    pub algorithm: AlgorithmArg,
    #[arg(
        long = "use",
        value_enum,
        help = "Allowed use(s) for the profile; repeat as needed"
    )]
    pub uses: Vec<UseArg>,
    #[arg(long, value_enum, default_value_t = ModeArg::Auto, help = "Force a mode or let the tool auto-resolve one")]
    pub mode: ModeArg,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Validate and resolve the profile without provisioning TPM state"
    )]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
#[command(about = "Derive deterministic bytes from a persisted profile")]
pub struct DeriveArgs {
    #[arg(long, help = "Existing profile name to use for derivation")]
    pub profile: String,
    #[arg(long, help = "High-level purpose string used for domain separation")]
    pub purpose: String,
    #[arg(
        long,
        help = "Application or domain namespace used for domain separation"
    )]
    pub namespace: String,
    #[arg(long, help = "Optional label to further distinguish this derivation")]
    pub label: Option<String>,
    #[arg(long = "context", value_parser = parse_key_value, help = "Additional key=value context fields; repeat as needed")]
    pub context: Vec<(String, String)>,
    #[arg(
        long,
        default_value_t = 32,
        help = "Number of derived bytes to produce"
    )]
    pub length: u16,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(long, help = "After deriving, also add the material to ssh-agent")]
    pub ssh_agent_add: bool,
    #[arg(
        long,
        help = "Optional ssh-agent comment for the added key (used with --ssh-agent-add)"
    )]
    pub ssh_agent_comment: Option<String>,
    #[arg(
        long,
        help = "Explicit ssh-agent socket path; otherwise SSH_AUTH_SOCK is used (used with --ssh-agent-add)"
    )]
    pub ssh_agent_socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(about = "Sign input with a persisted profile")]
pub struct SignArgs {
    #[arg(long, help = "Existing profile name to use for signing")]
    pub profile: String,
    #[arg(
        long,
        default_value = "-",
        help = "Input file to sign, or '-' for stdin"
    )]
    pub input: String,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(about = "Verify a signature against a persisted profile")]
pub struct VerifyArgs {
    #[arg(long, help = "Existing profile name to use for verification")]
    pub profile: String,
    #[arg(
        long,
        default_value = "-",
        help = "Input file that was signed, or '-' for stdin"
    )]
    pub input: String,
    #[arg(long, help = "Signature file to verify")]
    pub signature: String,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(about = "Encrypt data using a derived symmetric key from a persisted profile")]
pub struct EncryptArgs {
    #[arg(long, help = "Existing profile name to use for encryption")]
    pub profile: String,
    #[arg(
        long,
        default_value = "-",
        help = "Input file to encrypt, or '-' for stdin"
    )]
    pub input: String,
    #[arg(long, help = "Output file for ciphertext; defaults to stdout")]
    pub output: Option<std::path::PathBuf>,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<std::path::PathBuf>,
}

#[derive(Debug, Args)]
#[command(about = "Decrypt data previously encrypted with the encrypt command")]
pub struct DecryptArgs {
    #[arg(long, help = "Existing profile name to use for decryption")]
    pub profile: String,
    #[arg(
        long,
        default_value = "-",
        help = "Input file to decrypt, or '-' for stdin"
    )]
    pub input: String,
    #[arg(long, help = "Output file for plaintext; defaults to stdout")]
    pub output: Option<std::path::PathBuf>,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<std::path::PathBuf>,
}

#[derive(Debug, Args)]
#[command(about = "Derive a keypair (secret key + public key) from a persisted profile")]
pub struct KeygenArgs {
    #[arg(
        long = "from-profile",
        visible_alias = "profile",
        help = "Profile name to derive the keypair from"
    )]
    pub from_profile: String,
    #[arg(
        long,
        value_enum,
        default_value_t = KeygenKindArg::Auto,
        help = "Derivation kind: auto tries prf then seed, or force a specific kind"
    )]
    pub kind: KeygenKindArg,
    #[arg(
        long = "format",
        value_enum,
        default_value_t = KeygenFormatArg::Hex,
        help = "Output encoding for the generated keypair"
    )]
    pub format: KeygenFormatArg,
    #[arg(long, help = "Output file for the keypair; defaults to stdout")]
    pub output: Option<std::path::PathBuf>,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum KeygenKindArg {
    /// Try PRF first, then seed, otherwise error.
    #[default]
    Auto,
    /// Derive from a PRF-mode profile.
    Prf,
    /// Derive from a seed-mode profile.
    Seed,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum KeygenFormatArg {
    /// Lowercase hexadecimal.
    #[default]
    Hex,
    /// JSON object with hex-encoded fields.
    Json,
}

#[derive(Debug, Args)]
#[command(about = "Export public material or high-friction recovery artifacts")]
pub struct ExportArgs {
    #[arg(long, help = "Existing profile name to export from")]
    pub profile: String,
    #[arg(long, value_enum, help = "Artifact kind to export")]
    pub kind: ExportKindArg,
    #[arg(
        long = "format",
        value_enum,
        help = "Public-key encoding to emit; defaults to spki-der"
    )]
    pub public_key_format: Option<PublicKeyExportFormatArg>,
    #[arg(
        long,
        help = "Destination file path; recovery-bundle export requires this"
    )]
    pub output: Option<PathBuf>,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Operator-provided reason required for recovery-bundle export"
    )]
    pub reason: Option<String>,
    #[arg(
        long,
        help = "Acknowledge this is a break-glass recovery export and exported material leaves TPM protection"
    )]
    pub confirm: bool,
    #[arg(
        long,
        help = "Exact confirmation phrase required for recovery-bundle export"
    )]
    pub confirm_phrase: Option<String>,
}

#[derive(Debug, Args)]
#[command(about = "Import a recovery-bundle JSON file and reseal its seed into TPM-backed state")]
pub struct ImportArgs {
    #[arg(
        long,
        help = "Recovery-bundle JSON file to import; stdin is intentionally not supported"
    )]
    pub bundle: PathBuf,
    #[arg(
        long,
        help = "Optional destination profile name; defaults to the profile recorded in the bundle"
    )]
    pub profile: Option<String>,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(long, help = "Replace existing profile/object state if present")]
    pub overwrite_existing: bool,
    #[arg(
        long,
        help = "Acknowledge that the bundle contains exported seed material"
    )]
    pub confirm: bool,
}

#[derive(Debug, Args)]
#[command(
    about = "Add a derived private key to ssh-agent (currently the direct seed ed25519 / seed p256 slice in this CLI)"
)]
pub struct SshAgentAddArgs {
    #[arg(long, help = "Existing profile name to derive from")]
    pub profile: String,
    #[arg(long, help = "Optional ssh-agent comment for the added key")]
    pub comment: Option<String>,
    #[arg(
        long,
        help = "Explicit ssh-agent socket path; otherwise SSH_AUTH_SOCK is used"
    )]
    pub socket: Option<PathBuf>,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AlgorithmArg {
    /// NIST P-256 / secp256r1.
    P256,
    /// Ed25519.
    Ed25519,
    /// secp256k1.
    Secp256k1,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum UseArg {
    /// Expand to every currently supported use for the resolved mode.
    All,
    /// Allow signing operations.
    Sign,
    /// Allow signature verification operations.
    Verify,
    /// Allow deterministic derivation operations.
    Derive,
    /// Intended for ssh-agent loading.
    SshAgent,
    /// Allow encryption operations.
    Encrypt,
    /// Allow decryption operations.
    Decrypt,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum ModeArg {
    /// Pick the recommended mode from the capability probe.
    #[default]
    Auto,
    /// Use TPM-native objects and operations.
    Native,
    /// Use a TPM-backed PRF/HMAC root.
    Prf,
    /// Use a TPM-sealed seed with software derivation.
    Seed,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportKindArg {
    /// Export public key material.
    PublicKey,
    /// Export a break-glass seed recovery bundle.
    RecoveryBundle,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum PublicKeyExportFormatArg {
    /// Write binary SubjectPublicKeyInfo DER.
    SpkiDer,
    /// Write PEM-armored SubjectPublicKeyInfo.
    SpkiPem,
    /// Write lowercase hexadecimal SubjectPublicKeyInfo DER.
    SpkiHex,
    /// Write an OpenSSH public key line.
    Openssh,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_parses_public_key_format_flag() {
        let cli = Cli::try_parse_from([
            "tpm2-derive",
            "export",
            "--profile",
            "prod-signer",
            "--kind",
            "public-key",
            "--format",
            "openssh",
        ])
        .expect("cli should parse");

        match cli.command {
            Command::Export(args) => {
                assert_eq!(args.profile, "prod-signer");
                assert_eq!(
                    args.public_key_format,
                    Some(PublicKeyExportFormatArg::Openssh)
                );
            }
            other => panic!("expected export command, found {other:?}"),
        }
    }

    #[test]
    fn setup_parses_use_all() {
        let cli = Cli::try_parse_from([
            "tpm2-derive",
            "setup",
            "--profile",
            "prod-signer",
            "--algorithm",
            "p256",
            "--use",
            "all",
        ])
        .expect("cli should parse use=all");

        match cli.command {
            Command::Setup(args) => {
                assert_eq!(args.uses.len(), 1);
                assert!(matches!(args.uses[0], UseArg::All));
            }
            other => panic!("expected setup command, found {other:?}"),
        }
    }
}
