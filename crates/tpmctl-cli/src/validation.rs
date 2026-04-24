use crate::args::*;
use std::path::Path;
use tpmctl_core::HashAlgorithm;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("digest length for {hash:?} must be {expected} bytes, got {actual} bytes")]
    DigestLength {
        hash: HashAlgorithm,
        expected: usize,
        actual: usize,
    },
}

pub type Result<T> = std::result::Result<T, ValidationError>;

pub fn validate_command(command: &Command) -> Result<Vec<&'static str>> {
    match command {
        Command::Sign(args) => validate_sign(args),
        Command::Derive(args) => validate_derive(args),
        Command::Hmac(args) => validate_hmac(args),
        _ => Ok(Vec::new()),
    }
}

pub fn validate_sign(args: &SignArgs) -> Result<Vec<&'static str>> {
    // Clap enforces exactly one of input/digest; runtime digest length is checked
    // after bytes are read because '-' may come from stdin.
    let _ = args.data.mode();
    Ok(Vec::new())
}

pub fn validate_hmac(args: &HmacArgs) -> Result<Vec<&'static str>> {
    if args.seal_at.is_some() && args.seal_id.is_some() {
        return Err(ValidationError::Invalid(
            "--seal-at and --seal-id are mutually exclusive",
        ));
    }
    Ok(Vec::new())
}

pub fn validate_derive(args: &DeriveArgs) -> Result<Vec<&'static str>> {
    let mut warnings = Vec::new();
    if args.usage == DeriveUse::Sign && args.data.mode().is_none() {
        return Err(ValidationError::Invalid(
            "derive --use sign requires exactly one of --input or --digest",
        ));
    }
    if args.usage != DeriveUse::Sign && args.data.mode().is_some() {
        return Err(ValidationError::Invalid(
            "--input/--digest are only valid with derive --use sign",
        ));
    }
    if args.algorithm == DeriveAlgorithm::Ed25519
        && args.usage == DeriveUse::Sign
        && args.hash.is_some()
    {
        return Err(ValidationError::Invalid(
            "--hash is not supported for derive --algorithm ed25519 --use sign",
        ));
    }

    let format = args.effective_format();
    match args.usage {
        DeriveUse::Secret => require_format(
            format,
            &[DeriveFormat::Raw, DeriveFormat::Hex],
            "derive --use secret supports only raw or hex",
        )?,
        DeriveUse::Pubkey => match args.algorithm {
            DeriveAlgorithm::P256 | DeriveAlgorithm::Ed25519 => require_format(
                format,
                &[DeriveFormat::Raw, DeriveFormat::Hex],
                "this public key derivation supports only raw or hex",
            )?,
            DeriveAlgorithm::Secp256k1 => require_format(
                format,
                &[DeriveFormat::Raw, DeriveFormat::Hex, DeriveFormat::Address],
                "secp256k1 public key derivation supports raw, hex, or address",
            )?,
        },
        DeriveUse::Sign => match args.algorithm {
            DeriveAlgorithm::Ed25519 => require_format(
                format,
                &[DeriveFormat::Raw, DeriveFormat::Hex],
                "ed25519 signatures support only raw or hex",
            )?,
            DeriveAlgorithm::P256 | DeriveAlgorithm::Secp256k1 => require_format(
                format,
                &[DeriveFormat::Der, DeriveFormat::Raw, DeriveFormat::Hex],
                "ecdsa signatures support der, raw, or hex",
            )?,
        },
    }

    if args.compressed {
        if !(args.algorithm == DeriveAlgorithm::Secp256k1 && args.usage == DeriveUse::Pubkey) {
            return Err(ValidationError::Invalid(
                "--compressed is valid only for derive --algorithm secp256k1 --use pubkey",
            ));
        }
        if format == DeriveFormat::Address {
            return Err(ValidationError::Invalid(
                "--compressed cannot be combined with --format address",
            ));
        }
        require_format(
            format,
            &[DeriveFormat::Raw, DeriveFormat::Hex],
            "--compressed supports only raw or hex output",
        )?;
    }

    if args.label.is_none() && matches!(args.usage, DeriveUse::Secret | DeriveUse::Pubkey) {
        warnings.push(
            "warning: --label omitted; derived key is ephemeral and will change on each invocation",
        );
    }
    Ok(warnings)
}

fn require_format(
    format: DeriveFormat,
    allowed: &[DeriveFormat],
    message: &'static str,
) -> Result<()> {
    if allowed.contains(&format) {
        Ok(())
    } else {
        Err(ValidationError::Invalid(message))
    }
}

pub fn validate_digest_len(bytes: &[u8], hash: HashAlgorithm) -> Result<()> {
    let expected = hash.digest_len();
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(ValidationError::DigestLength {
            hash,
            expected,
            actual: bytes.len(),
        })
    }
}

#[allow(dead_code)]
pub fn output_path_is_stdout(path: Option<&std::path::PathBuf>) -> bool {
    path.map_or(true, |p| p.as_path() == Path::new("-"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn id_and_handle_conflict() {
        assert!(parse(&[
            "tpmctl",
            "sign",
            "--id",
            "a",
            "--handle",
            "0x81010010",
            "--input",
            "m"
        ])
        .is_err());
    }

    #[test]
    fn sign_requires_input_xor_digest() {
        assert!(parse(&["tpmctl", "sign", "--id", "a"]).is_err());
        assert!(parse(&["tpmctl", "sign", "--id", "a", "--input", "m", "--digest", "d"]).is_err());
        assert!(parse(&["tpmctl", "sign", "--id", "a", "--input", "m"]).is_ok());
    }

    #[test]
    fn hmac_seal_targets_conflict() {
        assert!(parse(&[
            "tpmctl",
            "hmac",
            "--id",
            "a",
            "--input",
            "m",
            "--seal-at",
            "0x81010020",
            "--seal-id",
            "b"
        ])
        .is_err());
    }

    #[test]
    fn derive_sign_requires_input_or_digest() {
        let cli = parse(&[
            "tpmctl",
            "derive",
            "--id",
            "a",
            "--algorithm",
            "p256",
            "--use",
            "sign",
        ])
        .unwrap();
        assert!(matches!(
            validate_command(&cli.command),
            Err(ValidationError::Invalid(_))
        ));
    }

    #[test]
    fn derive_rejects_ed25519_hash() {
        let cli = parse(&[
            "tpmctl",
            "derive",
            "--id",
            "a",
            "--algorithm",
            "ed25519",
            "--use",
            "sign",
            "--input",
            "m",
            "--hash",
            "sha256",
        ])
        .unwrap();
        assert!(validate_command(&cli.command).is_err());
    }

    #[test]
    fn derive_format_matrix() {
        let bad = parse(&[
            "tpmctl",
            "derive",
            "--id",
            "a",
            "--algorithm",
            "p256",
            "--use",
            "secret",
            "--format",
            "der",
        ])
        .unwrap();
        assert!(validate_command(&bad.command).is_err());
        let good = parse(&[
            "tpmctl",
            "derive",
            "--id",
            "a",
            "--algorithm",
            "secp256k1",
            "--use",
            "pubkey",
            "--format",
            "address",
        ])
        .unwrap();
        assert!(validate_command(&good.command).is_ok());
    }

    #[test]
    fn digest_length_validation() {
        assert!(validate_digest_len(&[0_u8; 32], HashAlgorithm::Sha256).is_ok());
        assert!(validate_digest_len(&[0_u8; 31], HashAlgorithm::Sha256).is_err());
    }
}
