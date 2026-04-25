use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    CommandContext, DeriveAlgorithm, DeriveFormat, DeriveUse, Error, HashAlgorithm, ObjectSelector,
    Result, crypto,
    hmac::prf_seed_from_hmac_identity,
    output::{self, BinaryFormat, SignatureFormat},
    seal::UnsealRequest,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Validation {
    pub algorithm: DeriveAlgorithm,
    pub usage: DeriveUse,
    pub has_payload: bool,
    pub payload_is_digest: bool,
    pub hash: Option<HashAlgorithm>,
    pub output_format: DeriveFormat,
    pub compressed: bool,
    pub label_present: bool,
    pub entropy_present: bool,
}

impl Validation {
    pub fn validate(self) -> Result<()> {
        if self.usage == DeriveUse::Sign && !self.has_payload {
            return Err(Error::invalid("derive", "derive sign requires a payload"));
        }
        if self.usage != DeriveUse::Sign && self.has_payload {
            return Err(Error::invalid(
                "derive",
                "payload is valid only for derive sign",
            ));
        }
        if self.label_present && self.entropy_present {
            return Err(Error::invalid(
                "entropy",
                "entropy is valid only when label is omitted",
            ));
        }
        if self.algorithm == DeriveAlgorithm::Ed25519 && self.usage == DeriveUse::Sign {
            if self.hash.is_some() {
                return Err(Error::invalid(
                    "derive",
                    "ed25519 derive sign does not support hash selection",
                ));
            }
            if self.payload_is_digest {
                return Err(Error::invalid(
                    "derive",
                    "ed25519 derive sign supports only message payloads",
                ));
            }
        }
        validate_output_format(self.algorithm, self.usage, self.output_format)?;
        if self.output_format == DeriveFormat::Address
            && !(self.algorithm == DeriveAlgorithm::Secp256k1 && self.usage == DeriveUse::Pubkey)
        {
            return Err(Error::invalid(
                "output_format",
                "address output is valid only for secp256k1 pubkey derivation",
            ));
        }
        if self.compressed
            && !(self.algorithm == DeriveAlgorithm::Secp256k1
                && self.usage == DeriveUse::Pubkey
                && matches!(self.output_format, DeriveFormat::Raw | DeriveFormat::Hex))
        {
            return Err(Error::invalid(
                "compressed",
                "compressed output is valid only for secp256k1 pubkey raw/hex derivation",
            ));
        }
        crypto::derive::DeriveRequest::new(
            self.algorithm,
            self.usage,
            self.hash.map(hash_selection),
        )
        .map_err(derive_error)?;
        Ok(())
    }
}

pub fn derive(
    command: &CommandContext,
    params: crate::api::derive::DeriveParams,
) -> Result<Zeroizing<Vec<u8>>> {
    validate_params(&params)?;
    let mode = derive_mode(&params)?;
    let seed_bytes = prf_seed(command, &params.material, &params)?;
    let seed = crypto::derive::SecretSeed::new(seed_bytes.as_slice()).map_err(derive_error)?;
    dispatch_output(&params, &seed, &mode)
}

pub fn validate_params(params: &crate::api::derive::DeriveParams) -> Result<()> {
    Validation {
        algorithm: params.algorithm,
        usage: params.usage,
        has_payload: params.payload.is_some(),
        payload_is_digest: matches!(
            params.payload,
            Some(crate::api::derive::SignPayload::Digest(_))
        ),
        hash: params.hash,
        output_format: params.output_format,
        compressed: params.compressed,
        label_present: params.label.is_some(),
        entropy_present: params.entropy.is_some(),
    }
    .validate()
}

fn prf_seed(
    command: &CommandContext,
    selector: &ObjectSelector,
    params: &crate::api::derive::DeriveParams,
) -> Result<Zeroizing<Vec<u8>>> {
    match (UnsealRequest {
        selector: selector.clone(),
        force_binary_stdout: true,
    })
    .execute_with_context(command)
    {
        Ok(seed) => Ok(seed),
        Err(Error::NotFound(_)) if matches!(selector, ObjectSelector::Id(_)) => {
            hmac_prf_seed(command, selector, params)
        }
        Err(Error::InvalidInput { .. }) | Err(Error::Tpm { .. })
            if matches!(selector, ObjectSelector::Handle(_)) =>
        {
            hmac_prf_seed(command, selector, params)
        }
        Err(error) => Err(error),
    }
}

fn hmac_prf_seed(
    command: &CommandContext,
    selector: &ObjectSelector,
    params: &crate::api::derive::DeriveParams,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut input = Vec::new();
    input.extend_from_slice(b"tpmctl derive prf v1\0");
    input.extend_from_slice(params.algorithm.domain());
    input.push(0);
    if let Some(label) = &params.label {
        input.extend_from_slice(label);
    }
    let seed = prf_seed_from_hmac_identity(command, selector, &input, None)?;
    input.zeroize();
    Ok(seed)
}

fn derive_mode(params: &crate::api::derive::DeriveParams) -> Result<crypto::derive::DeriveMode> {
    if let Some(label) = &params.label {
        Ok(crypto::derive::DeriveMode::deterministic(label.clone()))
    } else {
        let entropy = params.entropy.as_ref().ok_or_else(|| {
            Error::invalid("entropy", "entropy is required when label is omitted")
        })?;
        Ok(crypto::derive::DeriveMode::ephemeral(
            Vec::new(),
            entropy.as_slice().to_vec(),
        ))
    }
}

fn dispatch_output(
    params: &crate::api::derive::DeriveParams,
    seed: &crypto::derive::SecretSeed,
    mode: &crypto::derive::DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    match params.usage {
        DeriveUse::Secret => secret(params, seed, mode),
        DeriveUse::Pubkey => pubkey(params, seed, mode),
        DeriveUse::Sign => signature(params, seed, mode),
    }
}

fn secret(
    params: &crate::api::derive::DeriveParams,
    seed: &crypto::derive::SecretSeed,
    mode: &crypto::derive::DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut raw = match params.algorithm {
        DeriveAlgorithm::P256 => crypto::p256::derive_secret_key(seed, mode)
            .map_err(derive_error)?
            .to_bytes()
            .to_vec(),
        DeriveAlgorithm::Ed25519 => crypto::ed25519::derive_signing_key(seed, mode)
            .map_err(derive_error)?
            .to_bytes()
            .to_vec(),
        DeriveAlgorithm::Secp256k1 => crypto::secp256k1::derive_secret_key(seed, mode)
            .map_err(derive_error)?
            .to_bytes()
            .to_vec(),
    };
    let encoded = encode_raw_or_hex(&raw, params.output_format)?;
    raw.zeroize();
    Ok(Zeroizing::new(encoded))
}

fn pubkey(
    params: &crate::api::derive::DeriveParams,
    seed: &crypto::derive::SecretSeed,
    mode: &crypto::derive::DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = match params.algorithm {
        DeriveAlgorithm::P256 => encode_raw_or_hex(
            &crypto::p256::derive_public_key_sec1(seed, mode, false).map_err(derive_error)?,
            params.output_format,
        )?,
        DeriveAlgorithm::Ed25519 => encode_raw_or_hex(
            &crypto::ed25519::derive_public_key_bytes(seed, mode).map_err(derive_error)?,
            params.output_format,
        )?,
        DeriveAlgorithm::Secp256k1 if params.output_format == DeriveFormat::Address => {
            crypto::secp256k1::derive_ethereum_address(seed, mode)
                .map_err(derive_error)?
                .into_bytes()
        }
        DeriveAlgorithm::Secp256k1 => encode_raw_or_hex(
            &crypto::secp256k1::derive_public_key_sec1(seed, mode, params.compressed)
                .map_err(derive_error)?,
            params.output_format,
        )?,
    };
    Ok(Zeroizing::new(bytes))
}

fn signature(
    params: &crate::api::derive::DeriveParams,
    seed: &crypto::derive::SecretSeed,
    mode: &crypto::derive::DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let message = sign_message_bytes(params)?;
    let bytes = match params.algorithm {
        DeriveAlgorithm::P256 => output::encode_p256_signature(
            &crypto::p256::sign_prehash(seed, mode, &message).map_err(derive_error)?,
            signature_format(params.output_format)?,
        )?,
        DeriveAlgorithm::Ed25519 => encode_raw_or_hex(
            &crypto::ed25519::sign_message(seed, mode, &message).map_err(derive_error)?,
            params.output_format,
        )?,
        DeriveAlgorithm::Secp256k1 => output::encode_secp256k1_signature(
            &crypto::secp256k1::sign_prehash(seed, mode, &message).map_err(derive_error)?,
            signature_format(params.output_format)?,
        )?,
    };
    Ok(Zeroizing::new(bytes))
}

fn sign_message_bytes(params: &crate::api::derive::DeriveParams) -> Result<Zeroizing<Vec<u8>>> {
    let payload = params
        .payload
        .as_ref()
        .ok_or_else(|| Error::invalid("derive", "derive sign requires a payload"))?;
    match payload {
        crate::api::derive::SignPayload::Message(message)
            if params.algorithm == DeriveAlgorithm::Ed25519 =>
        {
            Ok(message.clone())
        }
        crate::api::derive::SignPayload::Message(message) => {
            let hash = derive_hash(params.algorithm, params.usage, params.hash)
                .ok_or_else(|| Error::invalid("derive", "derive sign requires a hash"))?;
            Ok(Zeroizing::new(hash.digest(message)))
        }
        crate::api::derive::SignPayload::Digest(digest) => {
            let hash = derive_hash(params.algorithm, params.usage, params.hash)
                .ok_or_else(|| Error::invalid("derive", "derive sign requires a hash"))?;
            hash.validate_digest(digest)?;
            Ok(digest.clone())
        }
    }
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

pub fn validate_output_format(
    algorithm: DeriveAlgorithm,
    usage: DeriveUse,
    output_format: DeriveFormat,
) -> Result<()> {
    match usage {
        DeriveUse::Secret if !matches!(output_format, DeriveFormat::Raw | DeriveFormat::Hex) => {
            Err(Error::invalid(
                "derive",
                "secret output supports only raw or hex",
            ))
        }
        DeriveUse::Pubkey => match algorithm {
            DeriveAlgorithm::P256 | DeriveAlgorithm::Ed25519
                if !matches!(output_format, DeriveFormat::Raw | DeriveFormat::Hex) =>
            {
                Err(Error::invalid(
                    "derive",
                    "pubkey output for p256 or ed25519 supports only raw or hex",
                ))
            }
            DeriveAlgorithm::Secp256k1
                if !matches!(
                    output_format,
                    DeriveFormat::Raw | DeriveFormat::Hex | DeriveFormat::Address
                ) =>
            {
                Err(Error::invalid(
                    "derive",
                    "secp256k1 pubkey output supports only raw, hex, or address",
                ))
            }
            _ => Ok(()),
        },
        DeriveUse::Sign => match algorithm {
            DeriveAlgorithm::Ed25519
                if !matches!(output_format, DeriveFormat::Raw | DeriveFormat::Hex) =>
            {
                Err(Error::invalid(
                    "derive",
                    "ed25519 sign output supports only raw or hex",
                ))
            }
            DeriveAlgorithm::P256 | DeriveAlgorithm::Secp256k1
                if !matches!(
                    output_format,
                    DeriveFormat::Der | DeriveFormat::Raw | DeriveFormat::Hex
                ) =>
            {
                Err(Error::invalid(
                    "derive",
                    "p256 or secp256k1 sign output supports only der, raw, or hex",
                ))
            }
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

pub fn derive_hash(
    algorithm: DeriveAlgorithm,
    usage: DeriveUse,
    hash: Option<HashAlgorithm>,
) -> Option<HashAlgorithm> {
    if usage == DeriveUse::Sign
        && matches!(
            algorithm,
            DeriveAlgorithm::P256 | DeriveAlgorithm::Secp256k1
        )
    {
        Some(hash.unwrap_or(HashAlgorithm::Sha256))
    } else {
        hash
    }
}

pub fn hash_selection(hash: HashAlgorithm) -> crypto::derive::HashSelection {
    match hash {
        HashAlgorithm::Sha256 => crypto::derive::HashSelection::Sha256,
        HashAlgorithm::Sha384 => crypto::derive::HashSelection::Sha384,
        HashAlgorithm::Sha512 => crypto::derive::HashSelection::Sha512,
    }
}

fn derive_error(error: impl std::fmt::Display) -> Error {
    Error::invalid("derive", error.to_string())
}
