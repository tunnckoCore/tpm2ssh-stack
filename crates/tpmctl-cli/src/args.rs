use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tpmctl_core::{HashAlgorithm, PersistentHandle, Target};

#[derive(Debug, Parser)]
#[command(
    name = "tpmctl",
    version,
    about = "TPM-backed key management and derivation CLI"
)]
pub struct Cli {
    /// Emit structured JSON where supported.
    #[arg(long, global = true)]
    pub json: bool,

    /// Local registry root. Overrides TPMCTL_STORE.
    #[arg(long, global = true, env = "TPMCTL_STORE", value_name = "PATH")]
    pub store: Option<PathBuf>,

    /// Allow binary output to an interactive terminal.
    #[arg(long, global = true)]
    pub force: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Keygen(KeygenArgs),
    Sign(SignArgs),
    Pubkey(PubkeyArgs),
    Ecdh(EcdhArgs),
    Hmac(HmacArgs),
    Seal(SealArgs),
    Unseal(UnsealArgs),
    Derive(DeriveArgs),
}

#[derive(Debug, Args)]
pub struct ExistingTargetArgs {
    /// Local registry identity.
    #[arg(long, conflicts_with = "handle", required_unless_present = "handle")]
    pub id: Option<String>,

    /// TPM persistent handle, e.g. 0x81010010.
    #[arg(long, value_parser = parse_handle, conflicts_with = "id", required_unless_present = "id")]
    pub handle: Option<PersistentHandle>,
}

impl ExistingTargetArgs {
    #[allow(dead_code)]
    pub fn target(&self) -> Target {
        match (&self.id, self.handle) {
            (Some(id), None) => Target::Id(id.clone()),
            (None, Some(handle)) => Target::Handle(handle),
            _ => unreachable!("clap requires exactly one of --id/--handle"),
        }
    }
}

#[derive(Debug, Args)]
pub struct IoArgs {
    /// Write output to file, or '-' for stdout.
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InputOrDigestArgs {
    /// Input message path, or '-' for stdin.
    #[arg(long, conflicts_with = "digest", required_unless_present = "digest")]
    pub input: Option<PathBuf>,

    /// Precomputed digest path, or '-' for stdin.
    #[arg(long, conflicts_with = "input", required_unless_present = "input")]
    pub digest: Option<PathBuf>,
}

impl InputOrDigestArgs {
    pub fn mode(&self) -> InputMode {
        match (&self.input, &self.digest) {
            (Some(path), None) => InputMode::Input(path.clone()),
            (None, Some(path)) => InputMode::Digest(path.clone()),
            _ => unreachable!("clap requires exactly one of --input/--digest"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMode {
    Input(PathBuf),
    Digest(PathBuf),
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(long = "use", value_enum)]
    pub usage: KeyUsage,

    #[arg(long)]
    pub id: String,

    #[arg(long, value_parser = parse_handle)]
    pub handle: Option<PersistentHandle>,

    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    #[command(flatten)]
    pub target: ExistingTargetArgs,
    #[command(flatten)]
    pub data: InputOrDigestArgs,
    #[arg(long, value_enum, default_value_t = HashArg::Sha256)]
    pub hash: HashArg,
    #[arg(long, value_enum, default_value_t = SignatureFormat::Der)]
    pub format: SignatureFormat,
    #[command(flatten)]
    pub io: IoArgs,
}

#[derive(Debug, Args)]
pub struct PubkeyArgs {
    #[command(flatten)]
    pub target: ExistingTargetArgs,
    #[arg(long, value_enum, default_value_t = PubkeyFormat::Pem)]
    pub format: PubkeyFormat,
    #[command(flatten)]
    pub io: IoArgs,
}

#[derive(Debug, Args)]
pub struct EcdhArgs {
    #[command(flatten)]
    pub target: ExistingTargetArgs,
    #[arg(long, value_name = "PATH")]
    pub peer_pub: PathBuf,
    #[arg(long, value_enum, default_value_t = RawHexFormat::Raw)]
    pub format: RawHexFormat,
    #[command(flatten)]
    pub io: IoArgs,
}

#[derive(Debug, Args)]
pub struct HmacArgs {
    #[command(flatten)]
    pub target: ExistingTargetArgs,
    #[arg(long, value_name = "PATH")]
    pub input: PathBuf,
    #[arg(long, value_enum)]
    pub hash: Option<HashArg>,
    #[arg(long, value_enum, default_value_t = RawHexFormat::Raw)]
    pub format: RawHexFormat,
    #[arg(long, value_parser = parse_handle, conflicts_with = "seal_id")]
    pub seal_at: Option<PersistentHandle>,
    #[arg(long, conflicts_with = "seal_at")]
    pub seal_id: Option<String>,
    #[command(flatten)]
    pub io: IoArgs,
}

#[derive(Debug, Args)]
pub struct SealArgs {
    #[command(flatten)]
    pub target: ExistingTargetArgs,
    #[arg(long, value_name = "PATH")]
    pub input: PathBuf,
}

#[derive(Debug, Args)]
pub struct UnsealArgs {
    #[command(flatten)]
    pub target: ExistingTargetArgs,
    #[command(flatten)]
    pub io: IoArgs,
}

#[derive(Debug, Args)]
pub struct DeriveArgs {
    #[command(flatten)]
    pub target: ExistingTargetArgs,
    #[arg(long)]
    pub label: Option<String>,
    #[arg(long, value_enum)]
    pub algorithm: DeriveAlgorithm,
    #[arg(long = "use", value_enum, default_value_t = DeriveUse::Secret)]
    pub usage: DeriveUse,
    #[command(flatten)]
    pub data: OptionalInputOrDigestArgs,
    #[arg(long, value_enum)]
    pub hash: Option<HashArg>,
    #[arg(long, value_enum)]
    pub format: Option<DeriveFormat>,
    #[arg(long)]
    pub compressed: bool,
    #[command(flatten)]
    pub io: IoArgs,
}

#[derive(Debug, Args)]
pub struct OptionalInputOrDigestArgs {
    #[arg(long, conflicts_with = "digest")]
    pub input: Option<PathBuf>,
    #[arg(long, conflicts_with = "input")]
    pub digest: Option<PathBuf>,
}

impl OptionalInputOrDigestArgs {
    pub fn mode(&self) -> Option<InputMode> {
        match (&self.input, &self.digest) {
            (Some(path), None) => Some(InputMode::Input(path.clone())),
            (None, Some(path)) => Some(InputMode::Digest(path.clone())),
            (None, None) => None,
            _ => unreachable!("clap rejects both --input and --digest"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeyUsage {
    Sign,
    Ecdh,
    Hmac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HashArg {
    Sha256,
    Sha384,
    Sha512,
}

impl From<HashArg> for HashAlgorithm {
    fn from(value: HashArg) -> Self {
        match value {
            HashArg::Sha256 => Self::Sha256,
            HashArg::Sha384 => Self::Sha384,
            HashArg::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SignatureFormat {
    Der,
    Raw,
    Hex,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PubkeyFormat {
    Raw,
    Hex,
    Pem,
    Der,
    Ssh,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RawHexFormat {
    Raw,
    Hex,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DeriveAlgorithm {
    P256,
    Ed25519,
    Secp256k1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DeriveUse {
    Secret,
    Pubkey,
    Sign,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DeriveFormat {
    Raw,
    Hex,
    Der,
    Address,
}

pub fn parse_handle(s: &str) -> Result<PersistentHandle, String> {
    let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) else {
        return Err("handle must be a hex string like 0x81010010".into());
    };
    if hex.is_empty() || hex.len() > 8 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("handle must be a hex string like 0x81010010".into());
    }
    let raw = u32::from_str_radix(hex, 16).map_err(|_| "handle is out of range".to_string())?;
    PersistentHandle::new(raw).map_err(|error| error.to_string())
}

impl DeriveArgs {
    pub fn effective_format(&self) -> DeriveFormat {
        self.format.unwrap_or(match self.usage {
            DeriveUse::Secret | DeriveUse::Pubkey => DeriveFormat::Raw,
            DeriveUse::Sign => match self.algorithm {
                DeriveAlgorithm::Ed25519 => DeriveFormat::Raw,
                DeriveAlgorithm::P256 | DeriveAlgorithm::Secp256k1 => DeriveFormat::Der,
            },
        })
    }
}
