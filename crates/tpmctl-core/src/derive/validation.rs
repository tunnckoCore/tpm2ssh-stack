use zeroize::Zeroizing;

use crate::{DeriveAlgorithm, DeriveFormat, Error, HashAlgorithm, Result};

use super::{
    DeriveParams, SignPayload, derive_error,
    primitives::{DeriveRequest, DeriveUse, HashSelection},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Validation {
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
        DeriveRequest::new(self.algorithm, self.usage, self.hash.map(hash_selection))
            .map_err(derive_error)?;
        Ok(())
    }
}

pub(super) fn validate_params(params: &DeriveParams) -> Result<()> {
    Validation {
        algorithm: params.algorithm,
        usage: params.usage,
        has_payload: params.payload.is_some(),
        payload_is_digest: matches!(params.payload, Some(SignPayload::Digest(_))),
        hash: params.hash,
        output_format: params.output_format,
        compressed: params.compressed,
        label_present: params.label.is_some(),
        entropy_present: params.entropy.is_some(),
    }
    .validate()
}

pub(super) fn sign_message_bytes(params: &DeriveParams) -> Result<Zeroizing<Vec<u8>>> {
    let payload = params
        .payload
        .as_ref()
        .ok_or_else(|| Error::invalid("derive", "derive sign requires a payload"))?;
    match payload {
        SignPayload::Message(message) if params.algorithm == DeriveAlgorithm::Ed25519 => {
            Ok(message.clone())
        }
        SignPayload::Message(message) => {
            let hash = derive_hash(params.algorithm, params.usage, params.hash)
                .ok_or_else(|| Error::invalid("derive", "derive sign requires a hash"))?;
            Ok(Zeroizing::new(hash.digest(message)))
        }
        SignPayload::Digest(digest) => {
            let hash = derive_hash(params.algorithm, params.usage, params.hash)
                .ok_or_else(|| Error::invalid("derive", "derive sign requires a hash"))?;
            hash.validate_digest(digest)?;
            Ok(digest.clone())
        }
    }
}

fn validate_output_format(
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

fn derive_hash(
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

fn hash_selection(hash: HashAlgorithm) -> HashSelection {
    match hash {
        HashAlgorithm::Sha256 => HashSelection::Sha256,
        HashAlgorithm::Sha384 => HashSelection::Sha384,
        HashAlgorithm::Sha512 => HashSelection::Sha512,
    }
}

#[cfg(test)]
#[path = "validation.test.rs"]
mod tests;
