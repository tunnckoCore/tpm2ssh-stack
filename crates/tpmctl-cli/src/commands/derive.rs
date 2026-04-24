use crate::{
    args::{CliError, DeriveAlgorithmArg, DeriveArgs, DeriveUseArg, HashArg},
    commands::io::{read_input, selector_from_material, write_output},
};
use tpmctl_core::{
    CommandContext, CoreError, DeriveFormat, HashAlgorithm, SignInput, StoreOptions,
    crypto::{DeriveMode, SecretSeed},
    output::{
        BinaryFormat, SignatureFormat, encode_binary, encode_p256_signature,
        encode_secp256k1_signature,
    },
    seal as core_seal,
};
use zeroize::{Zeroize as _, Zeroizing};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &DeriveArgs) -> Result<(), CliError> {
    if args.should_warn_ephemeral() {
        eprintln!(
            "warning: --label was not provided; derived material is ephemeral and will change on each invocation"
        );
    }

    let unseal_request = core_seal::UnsealRequest {
        selector: selector_from_material(&args.material.material())?,
        force_binary_stdout: false,
    };
    let command = CommandContext {
        store: StoreOptions {
            root: Some(runtime.store.root.clone()),
        },
        tcti: None,
    };
    let seed_bytes = unseal_request.execute_with_context(&command)?;
    let seed = SecretSeed::new(&*seed_bytes).map_err(derive_error)?;
    let mode = derive_mode(args)?;
    let output = derive_output(args, &seed, &mode)?;
    let target: tpmctl_core::OutputTarget = (&args.output).into();
    write_output(&target, &output)?;
    Ok(())
}

fn derive_mode(args: &DeriveArgs) -> Result<DeriveMode, CliError> {
    if let Some(label) = &args.label {
        Ok(DeriveMode::deterministic(label.as_bytes().to_vec()))
    } else {
        let mut entropy = Zeroizing::new(vec![0_u8; 32]);
        getrandom::fill(&mut entropy)
            .map_err(|error| CoreError::invalid("entropy", error.to_string()))?;
        Ok(DeriveMode::ephemeral(Vec::new(), entropy.to_vec()))
    }
}

fn derive_output(
    args: &DeriveArgs,
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    match args.usage {
        DeriveUseArg::Secret => derive_secret(args, seed, mode),
        DeriveUseArg::Pubkey => derive_public_key(args, seed, mode),
        DeriveUseArg::Sign => derive_signature(args, seed, mode),
    }
}

fn derive_secret(
    args: &DeriveArgs,
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut raw = match args.algorithm {
        DeriveAlgorithmArg::P256 => {
            let secret =
                tpmctl_core::crypto::p256::derive_secret_key(seed, mode).map_err(derive_error)?;
            secret.to_bytes().to_vec()
        }
        DeriveAlgorithmArg::Ed25519 => {
            let signing_key = tpmctl_core::crypto::ed25519::derive_signing_key(seed, mode)
                .map_err(derive_error)?;
            signing_key.to_bytes().to_vec()
        }
        DeriveAlgorithmArg::Secp256k1 => {
            let secret = tpmctl_core::crypto::secp256k1::derive_secret_key(seed, mode)
                .map_err(derive_error)?;
            secret.to_bytes().to_vec()
        }
    };
    let encoded = encode_raw_or_hex(&raw, args.format)?;
    raw.zeroize();
    Ok(Zeroizing::new(encoded))
}

fn derive_public_key(
    args: &DeriveArgs,
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let bytes = match args.algorithm {
        DeriveAlgorithmArg::P256 => {
            let raw = tpmctl_core::crypto::p256::derive_public_key_sec1(seed, mode, false)
                .map_err(derive_error)?;
            encode_raw_or_hex(&raw, args.format)?
        }
        DeriveAlgorithmArg::Ed25519 => {
            let raw = tpmctl_core::crypto::ed25519::derive_public_key_bytes(seed, mode)
                .map_err(derive_error)?;
            encode_raw_or_hex(&raw, args.format)?
        }
        DeriveAlgorithmArg::Secp256k1
            if DeriveFormat::from(args.format) == DeriveFormat::Address =>
        {
            tpmctl_core::crypto::secp256k1::derive_ethereum_address(seed, mode)
                .map_err(derive_error)?
                .into_bytes()
        }
        DeriveAlgorithmArg::Secp256k1 => {
            let raw =
                tpmctl_core::crypto::secp256k1::derive_public_key_sec1(seed, mode, args.compressed)
                    .map_err(derive_error)?;
            encode_raw_or_hex(&raw, args.format)?
        }
    };
    Ok(Zeroizing::new(bytes))
}

fn derive_signature(
    args: &DeriveArgs,
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let message = sign_message_bytes(args)?;
    let bytes = match args.algorithm {
        DeriveAlgorithmArg::P256 => {
            let mut p1363 = tpmctl_core::crypto::p256::sign_message(seed, mode, &message)
                .map_err(derive_error)?;
            let encoded = encode_p256_signature(&p1363, signature_format(args.format)?)?;
            p1363.zeroize();
            encoded
        }
        DeriveAlgorithmArg::Ed25519 => {
            let mut raw = tpmctl_core::crypto::ed25519::sign_message(seed, mode, &message)
                .map_err(derive_error)?;
            let encoded = encode_raw_or_hex(&raw, args.format)?;
            raw.zeroize();
            encoded
        }
        DeriveAlgorithmArg::Secp256k1 => {
            let mut p1363 = tpmctl_core::crypto::secp256k1::sign_message(seed, mode, &message)
                .map_err(derive_error)?;
            let encoded = encode_secp256k1_signature(&p1363, signature_format(args.format)?)?;
            p1363.zeroize();
            encoded
        }
    };
    Ok(Zeroizing::new(bytes))
}

fn sign_message_bytes(args: &DeriveArgs) -> Result<Zeroizing<Vec<u8>>, CliError> {
    match args.sign_input().expect("derive --use sign has sign input") {
        SignInput::Message(source) => {
            let bytes = read_input(&source)?;
            if args.algorithm == DeriveAlgorithmArg::Ed25519 {
                Ok(Zeroizing::new(bytes))
            } else {
                Ok(Zeroizing::new(derive_hash(args).unwrap().digest(&bytes)))
            }
        }
        SignInput::Digest(source) => {
            let bytes = read_input(&source)?;
            if args.algorithm != DeriveAlgorithmArg::Ed25519 {
                derive_hash(args).unwrap().validate_digest(&bytes)?;
            }
            Ok(Zeroizing::new(bytes))
        }
    }
}

fn encode_raw_or_hex(
    raw: &[u8],
    format: crate::args::DeriveFormatArg,
) -> Result<Vec<u8>, CliError> {
    match format.into() {
        DeriveFormat::Raw => Ok(encode_binary(raw, BinaryFormat::Raw)),
        DeriveFormat::Hex => Ok(encode_binary(raw, BinaryFormat::Hex)),
        DeriveFormat::Der | DeriveFormat::Address => Err(CliError::Usage(
            "derive output format is not valid for this operation".to_string(),
        )),
    }
}

fn signature_format(format: crate::args::DeriveFormatArg) -> Result<SignatureFormat, CliError> {
    match format.into() {
        DeriveFormat::Der => Ok(SignatureFormat::Der),
        DeriveFormat::Raw => Ok(SignatureFormat::Raw),
        DeriveFormat::Hex => Ok(SignatureFormat::Hex),
        DeriveFormat::Address => Err(CliError::Usage(
            "derive --use sign does not support --format address".to_string(),
        )),
    }
}

fn derive_hash(args: &DeriveArgs) -> Option<HashAlgorithm> {
    if args.usage == DeriveUseArg::Sign
        && matches!(
            args.algorithm,
            DeriveAlgorithmArg::P256 | DeriveAlgorithmArg::Secp256k1
        )
    {
        Some(args.hash.unwrap_or(HashArg::Sha256).into())
    } else {
        args.hash.map(Into::into)
    }
}

fn derive_error(error: impl std::fmt::Display) -> CoreError {
    CoreError::invalid("derive", error.to_string())
}
