use std::{io::IsTerminal as _, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use tpmctl_core::{
    BinaryTextFormat, DeriveAlgorithm, DeriveFormat, DeriveUse, HashAlgorithm, InputSource,
    KeyUsage, MaterialRef, OutputTarget, PersistentHandle, PublicKeyFormat, SealDestination,
    SignatureFormat, StoreConfig,
};

#[derive(Debug, Parser)]
#[command(
    name = "tpmctl",
    version,
    about = "TPM-backed key management and helper operations",
    long_about = "Manage TPM-backed identities and dispatch TPM-backed signing, public-key export, ECDH, HMAC, seal/unseal, and derived-key helper operations. TPM behavior lives in tpmctl-core; the CLI validates arguments and I/O policy."
)]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH", env = "TPMCTL_STORE")]
    pub store: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "Emit structured JSON results where supported"
    )]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }

    #[cfg(test)]
    pub fn try_parse_args<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::try_parse_from(args)
    }

    pub fn runtime(&self) -> Result<tpmctl_core::RuntimeOptions, CliError> {
        Ok(tpmctl_core::RuntimeOptions {
            store: StoreConfig::resolve(self.store.clone())?,
            json: self.json,
        })
    }

    pub fn validate(&self) -> Result<(), CliError> {
        self.command.validate()?;
        self.guard_binary_stdout(std::io::stdout().is_terminal())?;
        Ok(())
    }

    pub(crate) fn guard_binary_stdout(&self, stdout_is_tty: bool) -> Result<(), CliError> {
        if stdout_is_tty && self.command.writes_binary_stdout() && !self.command.force() {
            return Err(CliError::Usage(
                "refusing to write binary output to an interactive terminal; use --output <file>, --output -, a text format, or --force"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Create a TPM-backed identity")]
    Keygen(KeygenArgs),
    #[command(about = "Sign input or a digest with a TPM-backed signing identity")]
    Sign(SignArgs),
    #[command(about = "Export a TPM-backed public key")]
    Pubkey(PubkeyArgs),
    #[command(about = "Generate an ECDH shared secret")]
    Ecdh(EcdhArgs),
    #[command(about = "Compute TPM-backed HMAC/PRF output")]
    Hmac(HmacArgs),
    #[command(about = "Seal input data to the TPM")]
    Seal(SealArgs),
    #[command(about = "Unseal TPM-sealed data")]
    Unseal(UnsealArgs),
    #[command(about = "Derive short-lived software keys from TPM-protected PRF material")]
    Derive(DeriveArgs),
}

impl Command {
    fn validate(&self) -> Result<(), CliError> {
        match self {
            Self::Keygen(_) => Ok(()),
            Self::Sign(_) => Ok(()),
            Self::Pubkey(_) => Ok(()),
            Self::Ecdh(_) => Ok(()),
            Self::Hmac(args) => args.validate(),
            Self::Seal(_) => Ok(()),
            Self::Unseal(_) => Ok(()),
            Self::Derive(args) => args.validate(),
        }
    }

    fn writes_binary_stdout(&self) -> bool {
        match self {
            Self::Keygen(_) | Self::Seal(_) => false,
            Self::Sign(args) => args.output.is_stdout() && args.format.is_binary(),
            Self::Pubkey(args) => args.output.is_stdout() && args.format.is_binary(),
            Self::Ecdh(args) => args.output.is_stdout() && args.format.is_binary(),
            Self::Hmac(args) => {
                args.output.is_stdout()
                    && args.seal_destination().is_none()
                    && args.format.is_binary()
            }
            Self::Unseal(args) => args.output.is_stdout(),
            Self::Derive(args) => args.output.is_stdout() && args.format.is_binary(),
        }
    }

    fn force(&self) -> bool {
        match self {
            Self::Keygen(args) => args.force,
            Self::Sign(args) => args.force,
            Self::Pubkey(args) => args.force,
            Self::Ecdh(args) => args.force,
            Self::Hmac(args) => args.force,
            Self::Seal(args) => args.force,
            Self::Unseal(args) => args.force,
            Self::Derive(args) => args.force,
        }
    }
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(long = "use", value_enum)]
    pub usage: KeyUsageArg,

    #[arg(long, value_name = "ID")]
    pub id: String,

    #[arg(long, value_name = "0xHANDLE", value_parser = parse_persistent_handle)]
    pub handle: Option<PersistentHandle>,

    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false, args = ["id", "handle"])]
pub struct MaterialArgs {
    #[arg(long, value_name = "ID")]
    pub id: Option<String>,

    #[arg(long, value_name = "0xHANDLE", value_parser = parse_persistent_handle)]
    pub handle: Option<PersistentHandle>,
}

impl MaterialArgs {
    pub fn material(&self) -> MaterialRef {
        match (&self.id, self.handle) {
            (Some(id), None) => MaterialRef::Id(id.clone()),
            (None, Some(handle)) => MaterialRef::Handle(handle),
            _ => unreachable!("clap enforces exactly one material reference"),
        }
    }
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false, args = ["input", "digest"])]
pub struct SignArgs {
    #[command(flatten)]
    pub material: MaterialArgs,

    #[arg(long, value_name = "PATH", value_parser = parse_input_source)]
    pub input: Option<InputSource>,

    #[arg(long, value_name = "PATH", value_parser = parse_input_source)]
    pub digest: Option<InputSource>,

    #[arg(long, value_enum, default_value_t = HashArg::Sha256)]
    pub hash: HashArg,

    #[arg(long, value_enum, default_value_t = SignatureFormatArg::Der)]
    pub format: SignatureFormatArg,

    #[command(flatten)]
    pub output: OutputArgs,

    #[arg(long)]
    pub force: bool,
}

impl SignArgs {
    pub fn sign_input(&self) -> tpmctl_core::SignInput {
        match (&self.input, &self.digest) {
            (Some(input), None) => tpmctl_core::SignInput::Message(input.clone()),
            (None, Some(digest)) => tpmctl_core::SignInput::Digest(digest.clone()),
            _ => unreachable!("clap enforces exactly one sign input"),
        }
    }
}

#[derive(Debug, Args)]
pub struct PubkeyArgs {
    #[command(flatten)]
    pub material: MaterialArgs,

    #[arg(long, value_enum, default_value_t = PublicKeyFormatArg::Pem)]
    pub format: PublicKeyFormatArg,

    #[command(flatten)]
    pub output: OutputArgs,

    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct EcdhArgs {
    #[command(flatten)]
    pub material: MaterialArgs,

    #[arg(long = "peer-pub", value_name = "PATH", value_parser = parse_input_source)]
    pub peer_pub: InputSource,

    #[arg(long, value_enum, default_value_t = BinaryTextFormatArg::Raw)]
    pub format: BinaryTextFormatArg,

    #[command(flatten)]
    pub output: OutputArgs,

    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
#[group(required = false, multiple = false, args = ["seal_at", "seal_id"])]
pub struct HmacArgs {
    #[command(flatten)]
    pub material: MaterialArgs,

    #[arg(long, value_name = "PATH", value_parser = parse_input_source)]
    pub input: InputSource,

    #[arg(long, value_enum)]
    pub hash: Option<HashArg>,

    #[arg(long, value_enum, default_value_t = BinaryTextFormatArg::Raw)]
    pub format: BinaryTextFormatArg,

    #[command(flatten)]
    pub output: OutputArgs,

    #[arg(long = "seal-at", value_name = "0xHANDLE", value_parser = parse_persistent_handle)]
    pub seal_at: Option<PersistentHandle>,

    #[arg(long = "seal-id", value_name = "ID")]
    pub seal_id: Option<String>,

    #[arg(long)]
    pub force: bool,
}

impl HmacArgs {
    pub fn validate(&self) -> Result<(), CliError> {
        if self.seal_destination().is_some() && self.output.path.is_some() {
            return Err(CliError::Usage(
                "hmac sealing does not write PRF bytes; omit --output unless unsealed output support is added"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn seal_destination(&self) -> Option<SealDestination> {
        match (&self.seal_id, self.seal_at) {
            (Some(id), None) => Some(SealDestination::Id(id.clone())),
            (None, Some(handle)) => Some(SealDestination::Handle(handle)),
            (None, None) => None,
            _ => unreachable!("clap enforces mutually exclusive hmac seal destinations"),
        }
    }
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false, args = ["id", "handle"])]
pub struct SealArgs {
    #[arg(long, value_name = "PATH", value_parser = parse_input_source)]
    pub input: InputSource,

    #[arg(long, value_name = "ID")]
    pub id: Option<String>,

    #[arg(long, value_name = "0xHANDLE", value_parser = parse_persistent_handle)]
    pub handle: Option<PersistentHandle>,

    #[arg(long)]
    pub force: bool,
}

impl SealArgs {
    pub fn destination(&self) -> SealDestination {
        match (&self.id, self.handle) {
            (Some(id), None) => SealDestination::Id(id.clone()),
            (None, Some(handle)) => SealDestination::Handle(handle),
            _ => unreachable!("clap enforces exactly one seal destination"),
        }
    }
}

#[derive(Debug, Args)]
pub struct UnsealArgs {
    #[command(flatten)]
    pub material: MaterialArgs,

    #[command(flatten)]
    pub output: OutputArgs,

    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct DeriveArgs {
    #[command(flatten)]
    pub material: MaterialArgs,

    #[arg(long, value_name = "LABEL")]
    pub label: Option<String>,

    #[arg(long, value_enum)]
    pub algorithm: DeriveAlgorithmArg,

    #[arg(long = "use", value_enum, default_value_t = DeriveUseArg::Secret)]
    pub usage: DeriveUseArg,

    #[arg(long, value_name = "PATH", value_parser = parse_input_source)]
    pub input: Option<InputSource>,

    #[arg(long, value_name = "PATH", value_parser = parse_input_source)]
    pub digest: Option<InputSource>,

    #[arg(long, value_enum)]
    pub hash: Option<HashArg>,

    #[arg(long, value_enum, default_value_t = DeriveFormatArg::Raw)]
    pub format: DeriveFormatArg,

    #[arg(long)]
    pub compressed: bool,

    #[command(flatten)]
    pub output: OutputArgs,

    #[arg(long)]
    pub force: bool,
}

impl DeriveArgs {
    pub fn validate(&self) -> Result<(), CliError> {
        let sign_input_count =
            usize::from(self.input.is_some()) + usize::from(self.digest.is_some());
        if self.usage == DeriveUseArg::Sign && sign_input_count != 1 {
            return Err(CliError::Usage(
                "derive --use sign requires exactly one of --input or --digest".to_string(),
            ));
        }
        if self.usage != DeriveUseArg::Sign && sign_input_count > 0 {
            return Err(CliError::Usage(
                "derive --input/--digest are only valid with --use sign".to_string(),
            ));
        }
        if self.algorithm == DeriveAlgorithmArg::Ed25519
            && self.usage == DeriveUseArg::Sign
            && self.hash.is_some()
        {
            return Err(CliError::Usage(
                "derive --algorithm ed25519 --use sign does not support --hash in v1".to_string(),
            ));
        }
        if self.usage == DeriveUseArg::Secret
            && !matches!(self.format, DeriveFormatArg::Raw | DeriveFormatArg::Hex)
        {
            return Err(CliError::Usage(
                "derive --use secret supports only --format raw or --format hex".to_string(),
            ));
        }
        if self.usage == DeriveUseArg::Pubkey {
            match self.algorithm {
                DeriveAlgorithmArg::P256 | DeriveAlgorithmArg::Ed25519 => {
                    if !matches!(self.format, DeriveFormatArg::Raw | DeriveFormatArg::Hex) {
                        return Err(CliError::Usage(
                            "derive --use pubkey with p256 or ed25519 supports only --format raw or --format hex"
                                .to_string(),
                        ));
                    }
                }
                DeriveAlgorithmArg::Secp256k1 => {
                    if !matches!(
                        self.format,
                        DeriveFormatArg::Raw | DeriveFormatArg::Hex | DeriveFormatArg::Address
                    ) {
                        return Err(CliError::Usage(
                            "derive --use pubkey --algorithm secp256k1 supports --format raw, hex, or address"
                                .to_string(),
                        ));
                    }
                }
            }
        }
        if self.usage == DeriveUseArg::Sign {
            match self.algorithm {
                DeriveAlgorithmArg::Ed25519 => {
                    if !matches!(self.format, DeriveFormatArg::Raw | DeriveFormatArg::Hex) {
                        return Err(CliError::Usage(
                            "derive --algorithm ed25519 --use sign supports only --format raw or --format hex"
                                .to_string(),
                        ));
                    }
                }
                DeriveAlgorithmArg::P256 | DeriveAlgorithmArg::Secp256k1 => {
                    if !matches!(
                        self.format,
                        DeriveFormatArg::Der | DeriveFormatArg::Raw | DeriveFormatArg::Hex
                    ) {
                        return Err(CliError::Usage(
                            "derive --use sign with p256 or secp256k1 supports --format der, raw, or hex"
                                .to_string(),
                        ));
                    }
                }
            }
        }
        if self.compressed
            && !(self.algorithm == DeriveAlgorithmArg::Secp256k1
                && self.usage == DeriveUseArg::Pubkey
                && matches!(self.format, DeriveFormatArg::Raw | DeriveFormatArg::Hex))
        {
            return Err(CliError::Usage(
                "--compressed is valid only for derive --algorithm secp256k1 --use pubkey with --format raw or hex"
                    .to_string(),
            ));
        }
        if self.format == DeriveFormatArg::Address
            && !(self.algorithm == DeriveAlgorithmArg::Secp256k1
                && self.usage == DeriveUseArg::Pubkey)
        {
            return Err(CliError::Usage(
                "--format address is valid only for derive --algorithm secp256k1 --use pubkey"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn sign_input(&self) -> Option<tpmctl_core::SignInput> {
        match (&self.input, &self.digest) {
            (Some(input), None) => Some(tpmctl_core::SignInput::Message(input.clone())),
            (None, Some(digest)) => Some(tpmctl_core::SignInput::Digest(digest.clone())),
            (None, None) => None,
            _ => unreachable!("derive validation enforces at most one sign input"),
        }
    }
}

#[derive(Debug, Args)]
pub struct OutputArgs {
    #[arg(
        short = 'o',
        long = "output",
        value_name = "PATH",
        help = "Write primary output to PATH, or '-' for stdout"
    )]
    pub path: Option<PathBuf>,
}

impl OutputArgs {
    pub fn is_stdout(&self) -> bool {
        self.path
            .as_ref()
            .is_none_or(|path| path == std::path::Path::new("-"))
    }
}

impl From<&OutputArgs> for OutputTarget {
    fn from(value: &OutputArgs) -> Self {
        let path = value
            .path
            .as_ref()
            .filter(|path| *path != std::path::Path::new("-"))
            .cloned();
        Self { path }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum KeyUsageArg {
    Sign,
    Ecdh,
    Hmac,
}

impl From<KeyUsageArg> for KeyUsage {
    fn from(value: KeyUsageArg) -> Self {
        match value {
            KeyUsageArg::Sign => Self::Sign,
            KeyUsageArg::Ecdh => Self::Ecdh,
            KeyUsageArg::Hmac => Self::Hmac,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum SignatureFormatArg {
    Der,
    Raw,
    Hex,
}

impl SignatureFormatArg {
    fn is_binary(self) -> bool {
        matches!(self, Self::Der | Self::Raw)
    }
}

impl From<SignatureFormatArg> for SignatureFormat {
    fn from(value: SignatureFormatArg) -> Self {
        match value {
            SignatureFormatArg::Der => Self::Der,
            SignatureFormatArg::Raw => Self::Raw,
            SignatureFormatArg::Hex => Self::Hex,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum PublicKeyFormatArg {
    Raw,
    Hex,
    Pem,
    Der,
    Ssh,
}

impl PublicKeyFormatArg {
    fn is_binary(self) -> bool {
        matches!(self, Self::Raw | Self::Der)
    }
}

impl From<PublicKeyFormatArg> for PublicKeyFormat {
    fn from(value: PublicKeyFormatArg) -> Self {
        match value {
            PublicKeyFormatArg::Raw => Self::Raw,
            PublicKeyFormatArg::Hex => Self::Hex,
            PublicKeyFormatArg::Pem => Self::Pem,
            PublicKeyFormatArg::Der => Self::Der,
            PublicKeyFormatArg::Ssh => Self::Ssh,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum BinaryTextFormatArg {
    Raw,
    Hex,
}

impl BinaryTextFormatArg {
    fn is_binary(self) -> bool {
        matches!(self, Self::Raw)
    }
}

impl From<BinaryTextFormatArg> for BinaryTextFormat {
    fn from(value: BinaryTextFormatArg) -> Self {
        match value {
            BinaryTextFormatArg::Raw => Self::Raw,
            BinaryTextFormatArg::Hex => Self::Hex,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum DeriveAlgorithmArg {
    P256,
    Ed25519,
    Secp256k1,
}

impl From<DeriveAlgorithmArg> for DeriveAlgorithm {
    fn from(value: DeriveAlgorithmArg) -> Self {
        match value {
            DeriveAlgorithmArg::P256 => Self::P256,
            DeriveAlgorithmArg::Ed25519 => Self::Ed25519,
            DeriveAlgorithmArg::Secp256k1 => Self::Secp256k1,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum DeriveUseArg {
    Secret,
    Pubkey,
    Sign,
}

impl From<DeriveUseArg> for DeriveUse {
    fn from(value: DeriveUseArg) -> Self {
        match value {
            DeriveUseArg::Secret => Self::Secret,
            DeriveUseArg::Pubkey => Self::Pubkey,
            DeriveUseArg::Sign => Self::Sign,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum DeriveFormatArg {
    Raw,
    Hex,
    Der,
    Address,
}

impl DeriveFormatArg {
    fn is_binary(self) -> bool {
        matches!(self, Self::Raw | Self::Der)
    }
}

impl From<DeriveFormatArg> for DeriveFormat {
    fn from(value: DeriveFormatArg) -> Self {
        match value {
            DeriveFormatArg::Raw => Self::Raw,
            DeriveFormatArg::Hex => Self::Hex,
            DeriveFormatArg::Der => Self::Der,
            DeriveFormatArg::Address => Self::Address,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Core(#[from] tpmctl_core::Error),
}

pub fn parse_input_source(value: &str) -> Result<InputSource, String> {
    if value == "-" {
        Ok(InputSource::Stdin)
    } else {
        Ok(InputSource::File(PathBuf::from(value)))
    }
}

pub fn parse_persistent_handle(value: &str) -> Result<PersistentHandle, String> {
    value
        .parse::<PersistentHandle>()
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_args(args).unwrap()
    }

    #[test]
    fn help_and_version_parse_before_subcommands() {
        assert!(Cli::try_parse_args(["tpmctl", "--help"]).is_err());
        assert!(Cli::try_parse_args(["tpmctl", "--version"]).is_err());
    }

    #[test]
    fn sign_rejects_id_and_handle_together() {
        assert!(
            Cli::try_parse_args([
                "tpmctl",
                "sign",
                "--id",
                "alice",
                "--handle",
                "0x81010010",
                "--input",
                "msg",
            ])
            .is_err()
        );
    }

    #[test]
    fn sign_requires_input_or_digest() {
        assert!(Cli::try_parse_args(["tpmctl", "sign", "--id", "alice"]).is_err());
    }

    #[test]
    fn sign_accepts_stdin_and_stdout_dash() {
        let cli = parse(&[
            "tpmctl", "sign", "--id", "alice", "--input", "-", "--format", "hex", "--output", "-",
        ]);
        assert!(matches!(cli.command, Command::Sign(_)));
    }

    #[test]
    fn hmac_rejects_two_seal_destinations() {
        assert!(
            Cli::try_parse_args([
                "tpmctl",
                "hmac",
                "--id",
                "alice",
                "--input",
                "ctx",
                "--seal-at",
                "0x81010020",
                "--seal-id",
                "sealed/id",
            ])
            .is_err()
        );
    }

    #[test]
    fn derive_sign_requires_one_input_or_digest() {
        let cli = parse(&[
            "tpmctl",
            "derive",
            "--id",
            "seed",
            "--algorithm",
            "p256",
            "--use",
            "sign",
        ]);
        assert!(cli.validate().is_err());

        let cli = parse(&[
            "tpmctl",
            "derive",
            "--id",
            "seed",
            "--algorithm",
            "p256",
            "--use",
            "sign",
            "--input",
            "msg",
            "--digest",
            "digest",
        ]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn derive_rejects_ed25519_sign_hash() {
        let cli = parse(&[
            "tpmctl",
            "derive",
            "--id",
            "seed",
            "--algorithm",
            "ed25519",
            "--use",
            "sign",
            "--input",
            "msg",
            "--hash",
            "sha512",
        ]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn derive_compressed_scope_is_validated() {
        let cli = parse(&[
            "tpmctl",
            "derive",
            "--id",
            "seed",
            "--algorithm",
            "p256",
            "--use",
            "pubkey",
            "--compressed",
        ]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn binary_stdout_to_tty_requires_force() {
        let cli = parse(&["tpmctl", "pubkey", "--id", "alice", "--format", "der"]);
        assert!(cli.guard_binary_stdout(true).is_err());

        let cli = parse(&[
            "tpmctl", "pubkey", "--id", "alice", "--format", "der", "--force",
        ]);
        assert!(cli.guard_binary_stdout(true).is_ok());
    }

    #[test]
    fn parse_handle_requires_hex_prefix() {
        assert!(Cli::try_parse_args(["tpmctl", "pubkey", "--handle", "81010010",]).is_err());
        assert!(Cli::try_parse_args(["tpmctl", "pubkey", "--handle", "0x81010010",]).is_ok());
    }
}
