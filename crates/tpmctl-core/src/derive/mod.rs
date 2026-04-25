//! TPM-backed derived software keys.
//!
//! This module resolves seed material from either sealed registry entries or
//! HMAC identities, then derives P-256, secp256k1, or Ed25519 software keys for
//! secret export, public-key export, or deterministic signing.

use std::fmt;

use zeroize::Zeroizing;

use crate::{
    CommandContext, DeriveAlgorithm, Error, HashAlgorithm, ObjectSelector, Result,
    output::{self, BinaryFormat, SignatureFormat},
};

use crate::api::Context;

mod ed25519;
mod ethereum;
mod p256;
pub mod primitives;
mod secp256k1;
mod seed;
mod validation;

pub use crate::DeriveFormat;
pub use primitives::{
    DeriveError, DeriveMode, DeriveRequest, DeriveUse, DerivedAlgorithm, HashSelection, SecretSeed,
};
use seed::{resolve_mode, resolve_seed};
use validation::{sign_message_bytes, validate_params};

/// Payload used by [`derive()`] when [`DeriveParams::usage`] is [`DeriveUse::Sign`].
#[derive(Clone, Eq, PartialEq)]
pub enum SignPayload {
    /// Message bytes. P-256 and secp256k1 hash these bytes before signing;
    /// Ed25519 signs the message directly.
    Message(Zeroizing<Vec<u8>>),
    /// Prehashed digest bytes. Valid only for P-256 and secp256k1 signing.
    Digest(Zeroizing<Vec<u8>>),
}

impl fmt::Debug for SignPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(_) => formatter
                .debug_tuple("Message")
                .field(&"<redacted>")
                .finish(),
            Self::Digest(_) => formatter
                .debug_tuple("Digest")
                .field(&"<redacted>")
                .finish(),
        }
    }
}

/// Request for a derived software-key operation.
#[derive(Clone, Eq, PartialEq)]
pub struct DeriveParams {
    /// Seed source. IDs first try sealed material, then HMAC identity fallback.
    /// Handles are treated as HMAC identities when unseal is not applicable.
    pub material: ObjectSelector,
    /// Deterministic derivation label. Required unless [`Self::entropy`] is set.
    pub label: Option<Vec<u8>>,
    /// Derived key algorithm.
    pub algorithm: DerivedAlgorithm,
    /// Requested derived output: secret, public key, or signature.
    pub usage: DeriveUse,
    /// Signing payload. Must be `Some` only when `usage` is [`DeriveUse::Sign`].
    pub payload: Option<SignPayload>,
    /// Signing hash for P-256/secp256k1. Defaults to SHA-256 for signing.
    pub hash: Option<HashAlgorithm>,
    /// Encoded output representation.
    pub output_format: DeriveFormat,
    /// Compressed SEC1 output for secp256k1 public keys with raw/hex output.
    pub compressed: bool,
    /// Entropy for non-deterministic derivation when no label is supplied.
    pub entropy: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for DeriveParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeriveParams")
            .field("material", &self.material)
            .field("label", &self.label.as_ref().map(|_| "<redacted>"))
            .field("algorithm", &self.algorithm)
            .field("usage", &self.usage)
            .field("payload", &self.payload)
            .field("hash", &self.hash)
            .field("output_format", &self.output_format)
            .field("compressed", &self.compressed)
            .field("entropy", &self.entropy.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Execute a derive operation and return encoded bytes.
///
/// Secret-bearing outputs are returned in [`Zeroizing`] storage. The function
/// performs all validation before touching TPM-backed material.
pub fn derive(context: &Context, params: DeriveParams) -> Result<Zeroizing<Vec<u8>>> {
    derive_with_command(&context.command(), params)
}

impl DeriveParams {
    /// Validate request shape, output format, and algorithm-specific payload rules.
    pub fn validate(&self) -> Result<()> {
        validate_params(self)
    }
}

fn derive_with_command(
    command: &CommandContext,
    params: DeriveParams,
) -> Result<Zeroizing<Vec<u8>>> {
    validate_params(&params)?;
    let mode = resolve_mode(&params)?;
    let seed_bytes = resolve_seed(command, &params.material, &params)?;
    let seed = SecretSeed::new(seed_bytes.as_slice()).map_err(derive_error)?;
    dispatch_output(&params, &seed, &mode)
}

fn dispatch_output(
    params: &DeriveParams,
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    match params.usage {
        DeriveUse::Secret => secret(params, seed, mode),
        DeriveUse::Pubkey => pubkey(params, seed, mode),
        DeriveUse::Sign => signature(params, seed, mode),
    }
}

fn secret(
    params: &DeriveParams,
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let raw = Zeroizing::new(match params.algorithm {
        DeriveAlgorithm::P256 => p256::derive_secret_key(seed, mode)
            .map_err(derive_error)?
            .to_bytes()
            .to_vec(),
        DeriveAlgorithm::Ed25519 => ed25519::derive_signing_key(seed, mode)
            .map_err(derive_error)?
            .to_bytes()
            .to_vec(),
        DeriveAlgorithm::Secp256k1 => secp256k1::derive_secret_key(seed, mode)
            .map_err(derive_error)?
            .to_bytes()
            .to_vec(),
    });
    Ok(Zeroizing::new(encode_raw_or_hex(
        raw.as_slice(),
        params.output_format,
    )?))
}

fn pubkey(
    params: &DeriveParams,
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = match params.algorithm {
        DeriveAlgorithm::P256 => encode_raw_or_hex(
            &p256::derive_public_key_sec1(seed, mode, false).map_err(derive_error)?,
            params.output_format,
        )?,
        DeriveAlgorithm::Ed25519 => encode_raw_or_hex(
            &ed25519::derive_public_key_bytes(seed, mode).map_err(derive_error)?,
            params.output_format,
        )?,
        DeriveAlgorithm::Secp256k1 if params.output_format == DeriveFormat::Address => {
            secp256k1::derive_ethereum_address(seed, mode)
                .map_err(derive_error)?
                .into_bytes()
        }
        DeriveAlgorithm::Secp256k1 => encode_raw_or_hex(
            &secp256k1::derive_public_key_sec1(seed, mode, params.compressed)
                .map_err(derive_error)?,
            params.output_format,
        )?,
    };
    Ok(Zeroizing::new(bytes))
}

fn signature(
    params: &DeriveParams,
    seed: &SecretSeed,
    mode: &DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let message = sign_message_bytes(params)?;
    let bytes = match params.algorithm {
        DeriveAlgorithm::P256 => output::encode_p256_signature(
            &p256::sign_prehash(seed, mode, &message).map_err(derive_error)?,
            signature_format(params.output_format)?,
        )?,
        DeriveAlgorithm::Ed25519 => encode_raw_or_hex(
            &ed25519::sign_message(seed, mode, &message).map_err(derive_error)?,
            params.output_format,
        )?,
        DeriveAlgorithm::Secp256k1 => output::encode_secp256k1_signature(
            &secp256k1::sign_prehash(seed, mode, &message).map_err(derive_error)?,
            signature_format(params.output_format)?,
        )?,
    };
    Ok(Zeroizing::new(bytes))
}

fn encode_raw_or_hex(raw: &[u8], format: DeriveFormat) -> Result<Vec<u8>> {
    match format {
        DeriveFormat::Raw => Ok(output::encode_binary(raw, BinaryFormat::Raw)),
        DeriveFormat::Hex => Ok(output::encode_binary(raw, BinaryFormat::Hex)),
        DeriveFormat::Der | DeriveFormat::Address => Err(Error::invalid(
            "output_format",
            "derive output format is not valid for this operation",
        )),
    }
}

fn signature_format(format: DeriveFormat) -> Result<SignatureFormat> {
    match format {
        DeriveFormat::Der => Ok(SignatureFormat::Der),
        DeriveFormat::Raw => Ok(SignatureFormat::Raw),
        DeriveFormat::Hex => Ok(SignatureFormat::Hex),
        DeriveFormat::Address => Err(Error::invalid(
            "output_format",
            "derive sign does not support address output",
        )),
    }
}

fn derive_error(error: impl std::fmt::Display) -> Error {
    Error::invalid("derive", error.to_string())
}

#[cfg(test)]
#[path = "mod.test.rs"]
mod tests;
