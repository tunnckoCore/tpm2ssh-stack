use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "tpm2-derive",
    version,
    about = "TPM-backed identity operations with native, PRF, and seed modes",
    long_about = "TPM-backed identity operations with native, PRF, and seed modes.\n\nUse 'inspect' to see what the local TPM can do, 'identity' to provision persistent state, and the operational subcommands ('derive', 'sign', 'verify', 'encrypt', 'decrypt', 'export', 'ssh-add') to use an existing identity.\n\nImportant: SSH in this project does not imply Ed25519 only. P-256 is also a valid SSH/OpenSSH identity algorithm here. The direct 'tpm2-derive ssh-add' path supports PRF- and seed-backed identities and intentionally rejects native identities.",
    after_help = "Examples:\n  tpm2-derive inspect --algorithm p256 --use sign --use verify\n  tpm2-derive identity prod-signer --algorithm p256 --mode native --use sign --use verify\n  tpm2-derive identity app-prf --algorithm p256 --mode prf --use all --org com.example --purpose app\n  tpm2-derive sign --with prod-signer --input message.bin --format base64 --output message.sig\n  tpm2-derive verify --with prod-signer --input message.bin --signature message.sig --format base64\n  tpm2-derive derive --with app-prf --org com.example --purpose session --context tenant=alpha --format base64 --output session.key\n  tpm2-derive derive --with app-prf --org com.example --purpose session --context tenant=alpha --format pem\n  tpm2-derive ssh-add --with app-prf --org com.example --context account=prod\n  tpm2-derive export --with prod-signer --kind public-key --format pem --output prod-signer.pem\n  tpm2-derive export --with wallet-seed --kind public-key --format eth --output wallet.address\n  tpm2-derive export --with app-prf --kind secret-key --format der --confirm --reason \"hardware migration\" --output app-prf.key\n  tpm2-derive export --with app-prf --kind keypair --format pem --confirm --reason \"hardware migration\" --output app-prf.json"
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
    /// Create or update an identity and materialize backend state unless --dry-run is used.
    Identity(IdentityArgs),
    /// Derive deterministic bytes or a derived public key from a persisted PRF or seed identity.
    Derive(DeriveArgs),
    /// Sign input with a persisted identity.
    Sign(SignArgs),
    /// Verify a signature against a persisted identity.
    Verify(VerifyArgs),
    /// Encrypt data using a derived symmetric key from a persisted identity.
    Encrypt(EncryptArgs),
    /// Decrypt data previously encrypted with the encrypt command.
    Decrypt(DecryptArgs),
    /// Export public material or gated secret-bearing artifacts from a persisted identity.
    Export(ExportArgs),
    /// Add a PRF- or seed-derived private key to ssh-agent.
    #[command(name = "ssh-add")]
    SshAdd(SshAddArgs),
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
#[command(about = "Create or update an identity and provision TPM-backed state")]
pub struct IdentityArgs {
    #[arg(help = "Identity name used to persist metadata and backend state")]
    pub identity: String,
    #[arg(long, value_enum, help = "Algorithm the identity is centered on")]
    pub algorithm: AlgorithmArg,
    #[arg(
        long = "use",
        value_enum,
        required = true,
        help = "Allowed use(s) for the identity; repeat as needed"
    )]
    pub uses: Vec<UseArg>,
    #[arg(long, value_enum, default_value_t = ModeArg::Auto, help = "Force a mode or let the tool auto-resolve one")]
    pub mode: ModeArg,
    #[command(flatten)]
    pub defaults: DerivationInputArgs,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Validate and resolve the identity without provisioning TPM state"
    )]
    pub dry_run: bool,
}

#[derive(Debug, Args, Clone, Default)]
pub struct DerivationInputArgs {
    #[arg(long, help = "Organization string used for derivation identity")]
    pub org: Option<String>,
    #[arg(long, help = "Purpose string used for derivation identity")]
    pub purpose: Option<String>,
    #[arg(long = "context", value_parser = parse_key_value, help = "Additional key=value context fields; repeat as needed")]
    pub context: Vec<(String, String)>,
}

#[derive(Debug, Args)]
#[command(about = "Derive deterministic bytes or a derived public key from a persisted identity")]
pub struct DeriveArgs {
    #[arg(long = "with", help = "Existing identity name to use")]
    pub identity: String,
    #[command(flatten)]
    pub derivation: DerivationInputArgs,
    #[arg(
        long,
        default_value_t = 32,
        help = "Number of derived bytes to produce"
    )]
    pub length: u16,
    #[arg(
        long = "format",
        value_enum,
        default_value_t = DeriveFormatArg::Hex,
        help = "Output format for derived output (hex/base64 return derived bytes; der/pem/openssh return the derived public key for the effective child identity and require --length 32; der also requires --output)"
    )]
    pub format: DeriveFormatArg,
    #[arg(
        long,
        help = "Write derived output to a file instead of returning it inline"
    )]
    pub output: Option<PathBuf>,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(about = "Sign input with a persisted identity")]
pub struct SignArgs {
    #[arg(long = "with", help = "Existing identity name to use")]
    pub identity: String,
    #[command(flatten)]
    pub derivation: DerivationInputArgs,
    #[arg(
        long,
        default_value = "-",
        help = "Input file to sign, or '-' for stdin"
    )]
    pub input: String,
    #[arg(
        long = "format",
        value_enum,
        default_value_t = SignFormatArg::Hex,
        help = "Output format for the emitted signature (der is for ECDSA signatures; ed25519 uses hex/base64)"
    )]
    pub format: SignFormatArg,
    #[arg(
        long,
        help = "Write the signature to a file instead of returning it inline"
    )]
    pub output: Option<PathBuf>,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(about = "Verify a signature against a persisted identity")]
pub struct VerifyArgs {
    #[arg(long = "with", help = "Existing identity name to use")]
    pub identity: String,
    #[command(flatten)]
    pub derivation: DerivationInputArgs,
    #[arg(
        long,
        default_value = "-",
        help = "Input file that was signed, or '-' for stdin"
    )]
    pub input: String,
    #[arg(long, help = "Signature file to verify")]
    pub signature: String,
    #[arg(
        long = "format",
        value_enum,
        default_value_t = VerifyFormatArg::Auto,
        help = "Input format for the signature data (der is for ECDSA signatures; ed25519 uses hex/base64 or auto)"
    )]
    pub format: VerifyFormatArg,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(about = "Encrypt data using a derived symmetric key from a persisted identity")]
pub struct EncryptArgs {
    #[arg(long = "with", help = "Existing identity name to use")]
    pub identity: String,
    #[command(flatten)]
    pub derivation: DerivationInputArgs,
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
    #[arg(long = "with", help = "Existing identity name to use")]
    pub identity: String,
    #[command(flatten)]
    pub derivation: DerivationInputArgs,
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
#[command(
    about = "Export public material or gated secret-bearing artifacts from a persisted identity"
)]
pub struct ExportArgs {
    #[arg(long = "with", help = "Existing identity name to use")]
    pub identity: String,
    #[command(flatten)]
    pub derivation: DerivationInputArgs,
    #[arg(long, value_enum, help = "Artifact kind to export")]
    pub kind: ExportKindArg,
    #[arg(
        long = "format",
        value_enum,
        help = "Artifact format; valid values depend on --kind (public-key: der|pem|openssh [ed25519/p256 only]|eth [secp256k1 only]|hex|base64, secret-key: der|pem|openssh [ed25519/p256 only]|eth [aliases hex]|hex|base64, keypair: der|pem|openssh [ed25519/p256 only]|eth [secp256k1 only; hex keys + address] inside JSON; public-key hex/base64 use raw public bytes)"
    )]
    pub format: Option<ExportFormatArg>,
    #[arg(long, help = "Destination file path")]
    pub output: Option<PathBuf>,
    #[arg(
        long,
        help = "Override the state root directory instead of the default local state path"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Operator-provided reason required for secret-bearing export"
    )]
    pub reason: Option<String>,
    #[arg(
        long,
        help = "Acknowledge this export removes TPM-only protection from secret-bearing material"
    )]
    pub confirm: bool,
}

#[derive(Debug, Args)]
#[command(about = "Add a PRF- or seed-derived private key to ssh-agent")]
pub struct SshAddArgs {
    #[arg(long = "with", help = "Existing identity name to use")]
    pub identity: String,
    #[command(flatten)]
    pub derivation: DerivationInputArgs,
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum UseArg {
    /// Expand to the mode-aware full supported set.
    All,
    /// Allow signing operations.
    Sign,
    /// Allow signature verification operations.
    Verify,
    /// Allow deterministic derivation operations.
    Derive,
    /// Intended for SSH usage.
    Ssh,
    /// Allow encryption operations.
    Encrypt,
    /// Allow decryption operations.
    Decrypt,
    /// Allow secret-bearing export operations.
    ExportSecret,
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
    /// Export a derived secret key.
    SecretKey,
    /// Export both derived secret and public key material together as JSON; --format applies to the embedded key values, and `eth` (secp256k1 only) also adds an address field.
    Keypair,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum DeriveFormatArg {
    /// Write binary DER public-key output for the effective derived child identity.
    Der,
    /// Write PEM public-key output for the effective derived child identity.
    Pem,
    /// Write an OpenSSH public key for the effective derived child identity when supported.
    Openssh,
    /// Write lowercase hexadecimal text.
    Hex,
    /// Write base64 text.
    Base64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum SignFormatArg {
    /// Write binary DER when that signature has a DER representation.
    Der,
    /// Write lowercase hexadecimal text.
    Hex,
    /// Write base64 text.
    Base64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum VerifyFormatArg {
    /// Auto-detect hex/base64 text and otherwise treat the signature as raw bytes.
    Auto,
    /// Treat the signature as DER when supported.
    Der,
    /// Treat the signature input as hexadecimal text.
    Hex,
    /// Treat the signature input as base64 text.
    Base64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum ExportFormatArg {
    /// Write DER.
    Der,
    /// Write PEM.
    Pem,
    /// Write an OpenSSH-formatted key.
    Openssh,
    /// Write Ethereum-oriented output (`eth`); for public-key this is the address, for secret-key this aliases hex, and for keypair JSON it includes hex keys plus the address.
    #[value(alias = "ethereum-address")]
    Eth,
    /// Write lowercase hexadecimal text.
    Hex,
    /// Write base64 text.
    Base64,
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
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn identity_command_parses_new_surface() {
        let cli = Cli::try_parse_from([
            "tpm2-derive",
            "identity",
            "prod-signer",
            "--algorithm",
            "p256",
            "--mode",
            "native",
            "--use",
            "sign",
            "--use",
            "verify",
        ])
        .expect("cli should parse");

        match cli.command {
            Command::Identity(args) => {
                assert_eq!(args.identity, "prod-signer");
                assert_eq!(args.uses, vec![UseArg::Sign, UseArg::Verify]);
            }
            other => panic!("expected identity command, found {other:?}"),
        }
    }

    #[test]
    fn operational_commands_parse_with_selector_and_derivation_inputs() {
        let cli = Cli::try_parse_from([
            "tpm2-derive",
            "derive",
            "--with",
            "app-prf",
            "--org",
            "com.example",
            "--purpose",
            "session",
            "--context",
            "tenant=alpha",
            "--length",
            "32",
            "--format",
            "base64",
            "--output",
            "derived.txt",
        ])
        .expect("cli should parse");

        match cli.command {
            Command::Derive(args) => {
                assert_eq!(args.identity, "app-prf");
                assert_eq!(args.derivation.org.as_deref(), Some("com.example"));
                assert_eq!(args.derivation.purpose.as_deref(), Some("session"));
                assert_eq!(
                    args.derivation.context,
                    vec![("tenant".to_string(), "alpha".to_string())]
                );
                assert_eq!(args.format, DeriveFormatArg::Base64);
                assert_eq!(args.output, Some(PathBuf::from("derived.txt")));
            }
            other => panic!("expected derive command, found {other:?}"),
        }
    }

    #[test]
    fn ssh_add_parses_flat_command() {
        let cli = Cli::try_parse_from(["tpm2-derive", "ssh-add", "--with", "seed-user"])
            .expect("cli should parse");

        match cli.command {
            Command::SshAdd(args) => assert_eq!(args.identity, "seed-user"),
            other => panic!("expected ssh-add command, found {other:?}"),
        }
    }

    #[test]
    fn derive_parses_public_key_formats() {
        let cli = Cli::try_parse_from([
            "tpm2-derive",
            "derive",
            "--with",
            "app-prf",
            "--format",
            "pem",
        ])
        .expect("derive pem should parse");

        match cli.command {
            Command::Derive(args) => assert_eq!(args.format, DeriveFormatArg::Pem),
            other => panic!("expected derive command, found {other:?}"),
        }
    }

    #[test]
    fn sign_and_verify_parse_format_flags() {
        let sign = Cli::try_parse_from([
            "tpm2-derive",
            "sign",
            "--with",
            "prod-signer",
            "--format",
            "base64",
            "--output",
            "sig.txt",
        ])
        .expect("sign cli should parse");

        match sign.command {
            Command::Sign(args) => {
                assert_eq!(args.identity, "prod-signer");
                assert_eq!(args.format, SignFormatArg::Base64);
                assert_eq!(args.output, Some(PathBuf::from("sig.txt")));
            }
            other => panic!("expected sign command, found {other:?}"),
        }

        let verify = Cli::try_parse_from([
            "tpm2-derive",
            "verify",
            "--with",
            "prod-signer",
            "--signature",
            "sig.txt",
            "--format",
            "base64",
        ])
        .expect("verify cli should parse");

        match verify.command {
            Command::Verify(args) => {
                assert_eq!(args.identity, "prod-signer");
                assert_eq!(args.format, VerifyFormatArg::Base64);
            }
            other => panic!("expected verify command, found {other:?}"),
        }
    }

    #[test]
    fn export_parses_format_flag() {
        let cli = Cli::try_parse_from([
            "tpm2-derive",
            "export",
            "--with",
            "prod-signer",
            "--kind",
            "public-key",
            "--format",
            "openssh",
        ])
        .expect("cli should parse");

        match cli.command {
            Command::Export(args) => {
                assert_eq!(args.identity, "prod-signer");
                assert_eq!(args.format, Some(ExportFormatArg::Openssh));
            }
            other => panic!("expected export command, found {other:?}"),
        }

        let eth = Cli::try_parse_from([
            "tpm2-derive",
            "export",
            "--with",
            "prod-signer",
            "--kind",
            "public-key",
            "--format",
            "eth",
        ])
        .expect("eth format should parse");
        match eth.command {
            Command::Export(args) => assert_eq!(args.format, Some(ExportFormatArg::Eth)),
            other => panic!("expected export command, found {other:?}"),
        }

        let legacy_alias = Cli::try_parse_from([
            "tpm2-derive",
            "export",
            "--with",
            "prod-signer",
            "--kind",
            "public-key",
            "--format",
            "ethereum-address",
        ])
        .expect("ethereum-address alias should parse");
        match legacy_alias.command {
            Command::Export(args) => assert_eq!(args.format, Some(ExportFormatArg::Eth)),
            other => panic!("expected export command, found {other:?}"),
        }
    }

    #[test]
    fn removed_old_surface_no_longer_parses() {
        assert!(
            Cli::try_parse_from([
                "tpm2-derive",
                "setup",
                "--identity",
                "prod-signer",
                "--algorithm",
                "p256",
                "--use",
                "sign",
            ])
            .is_err()
        );

        assert!(
            Cli::try_parse_from([
                "tpm2-derive",
                "ssh",
                "agent",
                "add",
                "--identity",
                "seed-user",
            ])
            .is_err()
        );

        assert!(
            Cli::try_parse_from([
                "tpm2-derive",
                "derive",
                "--with",
                "app-prf",
                "--namespace",
                "com.example",
            ])
            .is_err()
        );

        assert!(Cli::try_parse_from(["tpm2-derive", "keygen", "--with", "seed-user"]).is_err());
        assert!(Cli::try_parse_from(["tpm2-derive", "import", "--bundle", "backup.json"]).is_err());
    }

    #[test]
    fn top_level_help_tracks_adr_surface() {
        let mut command = Cli::command();
        let mut help = Vec::new();
        command.write_long_help(&mut help).expect("help renders");
        let help = String::from_utf8(help).expect("utf8 help");

        assert!(help.contains("identity"));
        assert!(help.contains("ssh-add"));
        assert!(help.contains("supports PRF- and seed-backed identities"));
        assert!(!help.contains("seed-backed slice"));
        assert!(!help.contains("\n  keygen\n"));
        assert!(!help.contains("\n  import\n"));
        assert!(!help.contains("recovery-bundle"));
    }
}
