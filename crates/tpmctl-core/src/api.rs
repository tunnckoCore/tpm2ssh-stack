use std::fmt;

use zeroize::Zeroizing;

use crate::{
    CommandContext, HashAlgorithm, ObjectSelector, RegistryId, Result, SealTarget, Store,
    StoreOptions,
    ecdh::EcdhRequest,
    hmac::{HmacRequest, HmacResult},
    keygen::{self, KeygenResult, KeygenUsage},
    output::{BinaryFormat, PublicKeyFormat, SignatureFormat},
    pubkey::{self as pubkey_api, PublicKeyInput},
    seal::{SealRequest, SealResult, UnsealRequest},
    sign::{SignInput, SignRequest},
    tpm,
};

/// Library execution context shared by high-level API operations.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Context {
    /// Registry root. If omitted, store resolution uses environment/XDG defaults.
    pub store: StoreOptions,
    /// Optional TCTI string used for TPM connections.
    pub tcti: Option<String>,
}

impl Context {
    /// Convert to the lower-level command context used by domain modules.
    pub fn command(&self) -> CommandContext {
        CommandContext {
            store: self.store.clone(),
            tcti: self.tcti.clone(),
        }
    }

    /// Resolve the registry store for this context.
    pub fn store(&self) -> Result<Store> {
        Store::resolve(self.store.root.as_deref())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenParams {
    pub usage: KeygenUsage,
    pub id: RegistryId,
    pub persist_at: Option<tpm::PersistentHandle>,
    pub overwrite: bool,
}

impl KeygenParams {
    pub fn validate(&self) -> Result<()> {
        if self.id.as_str().starts_with("0x") {
            return Err(crate::Error::invalid(
                "id",
                "registry ids beginning with 0x are reserved for TPM handle literals",
            ));
        }
        Ok(())
    }
}

pub fn keygen(context: &Context, params: KeygenParams) -> Result<KeygenResult> {
    params.validate()?;
    keygen::KeygenRequest {
        usage: params.usage,
        id: params.id,
        persist_at: params.persist_at,
        force: params.overwrite,
    }
    .execute_with_context(&context.command())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PubkeyParams {
    pub material: ObjectSelector,
    pub output_format: PublicKeyFormat,
}

pub fn pubkey(context: &Context, params: PubkeyParams) -> Result<Vec<u8>> {
    pubkey_api::PubkeyRequest {
        selector: params.material,
        output_format: params.output_format,
    }
    .execute_with_context(&context.command())
}

#[derive(Clone, Eq, PartialEq)]
pub struct EcdhParams {
    pub material: ObjectSelector,
    pub peer_public_key: PublicKeyInput,
    pub output_format: BinaryFormat,
}

impl fmt::Debug for EcdhParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcdhParams")
            .field("material", &self.material)
            .field("peer_public_key", &"<redacted>")
            .field("output_format", &self.output_format)
            .finish()
    }
}

pub fn ecdh(context: &Context, params: EcdhParams) -> Result<Zeroizing<Vec<u8>>> {
    EcdhRequest {
        selector: params.material,
        peer_public_key: params.peer_public_key,
        output_format: params.output_format,
    }
    .execute_with_context(&context.command())
}

/// Byte payload for [`sign`].
///
/// `Message` signs arbitrary bytes after hashing them with `SignParams::hash`.
/// `Digest` signs a caller-supplied prehash and validates its length against
/// `SignParams::hash`.
#[derive(Clone, Eq, PartialEq)]
pub enum SignPayload {
    Message(Zeroizing<Vec<u8>>),
    Digest(Zeroizing<Vec<u8>>),
}

/// Parameters for [`sign`], the ergonomic public API around TPM P-256 signing.
#[derive(Clone, Eq, PartialEq)]
pub struct SignParams {
    pub material: ObjectSelector,
    pub payload: SignPayload,
    pub hash: HashAlgorithm,
    pub output_format: SignatureFormat,
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

impl fmt::Debug for SignParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignParams")
            .field("material", &self.material)
            .field("payload", &self.payload)
            .field("hash", &self.hash)
            .field("output_format", &self.output_format)
            .finish()
    }
}

pub fn sign(context: &Context, params: SignParams) -> Result<Vec<u8>> {
    let input = match params.payload {
        SignPayload::Message(message) => SignInput::Message(message),
        SignPayload::Digest(digest) => SignInput::Digest(digest),
    };
    SignRequest {
        selector: params.material,
        input,
        hash: params.hash,
        output_format: params.output_format,
    }
    .execute_with_context(&context.command())
}

#[derive(Clone, Eq, PartialEq)]
pub struct HmacParams {
    pub material: ObjectSelector,
    pub input: Zeroizing<Vec<u8>>,
    pub hash: Option<HashAlgorithm>,
    pub output_format: BinaryFormat,
    pub seal_target: Option<SealTarget>,
    pub emit_prf_when_sealing: bool,
    pub overwrite: bool,
}

impl fmt::Debug for HmacParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacParams")
            .field("material", &self.material)
            .field("input", &"<redacted>")
            .field("hash", &self.hash)
            .field("output_format", &self.output_format)
            .field("seal_target", &self.seal_target)
            .field("emit_prf_when_sealing", &self.emit_prf_when_sealing)
            .field("overwrite", &self.overwrite)
            .finish()
    }
}

pub fn hmac(context: &Context, params: HmacParams) -> Result<HmacResult> {
    HmacRequest {
        selector: params.material,
        input: params.input,
        hash: params.hash,
        output_format: params.output_format,
        seal_target: params.seal_target,
        emit_prf_when_sealing: params.emit_prf_when_sealing,
        force: params.overwrite,
    }
    .execute_with_context(&context.command())
}

#[derive(Clone, Eq, PartialEq)]
pub struct SealParams {
    pub target: ObjectSelector,
    pub input: Zeroizing<Vec<u8>>,
    pub overwrite: bool,
}

impl fmt::Debug for SealParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealParams")
            .field("target", &self.target)
            .field("input", &"<redacted>")
            .field("overwrite", &self.overwrite)
            .finish()
    }
}

pub fn seal(context: &Context, params: SealParams) -> Result<SealResult> {
    SealRequest {
        selector: params.target,
        input: params.input,
        force: params.overwrite,
    }
    .execute_with_context(&context.command())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnsealParams {
    pub material: ObjectSelector,
}

pub fn unseal(context: &Context, params: UnsealParams) -> Result<Zeroizing<Vec<u8>>> {
    UnsealRequest {
        selector: params.material,
        force_binary_stdout: true,
    }
    .execute_with_context(&context.command())
}

#[cfg(test)]
#[path = "api.test.rs"]
mod tests;
