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

/// Parameters for creating a TPM-backed key and registering it in the store.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenParams {
    /// Intended key capability: signing, ECDH, or HMAC.
    pub usage: KeygenUsage,
    /// Registry identifier where the new key metadata and blobs are stored.
    pub id: RegistryId,
    /// Optional persistent TPM handle to evict-control the created key into.
    pub persist_at: Option<tpm::PersistentHandle>,
    /// Whether an existing registry entry or persistent handle may be replaced.
    pub overwrite: bool,
}

impl KeygenParams {
    /// Validate parameters before attempting TPM or store mutations.
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

/// Create a TPM-backed key according to [`KeygenParams`].
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

/// Parameters for exporting a public key from a registry ID or TPM handle.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PubkeyParams {
    /// Object whose public key should be exported.
    pub material: ObjectSelector,
    /// Encoding to use for the exported public key.
    pub output_format: PublicKeyFormat,
}

/// Export the public portion of a TPM-backed asymmetric key.
pub fn pubkey(context: &Context, params: PubkeyParams) -> Result<Vec<u8>> {
    pubkey_api::PubkeyRequest {
        selector: params.material,
        output_format: params.output_format,
    }
    .execute_with_context(&context.command())
}

/// Parameters for deriving an ECDH shared secret with a TPM key.
#[derive(Clone, Eq, PartialEq)]
pub struct EcdhParams {
    /// Local ECDH private key selected by registry ID or persistent handle.
    pub material: ObjectSelector,
    /// Peer public key encoded as SEC1, DER, or PEM.
    pub peer_public_key: PublicKeyInput,
    /// Encoding to apply to the shared secret bytes.
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

/// Derive and encode an ECDH shared secret using a TPM-backed key.
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
    /// Arbitrary message bytes that will be hashed before signing.
    Message(Zeroizing<Vec<u8>>),
    /// Precomputed digest bytes whose length must match the selected hash.
    Digest(Zeroizing<Vec<u8>>),
}

/// Parameters for [`sign`], the ergonomic public API around TPM P-256 signing.
#[derive(Clone, Eq, PartialEq)]
pub struct SignParams {
    /// Signing key selected by registry ID or persistent handle.
    pub material: ObjectSelector,
    /// Message or digest to sign.
    pub payload: SignPayload,
    /// Hash algorithm associated with the signature operation.
    pub hash: HashAlgorithm,
    /// Encoding for the returned signature.
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

/// Sign a message or digest with a TPM-backed P-256 signing key.
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

/// Parameters for computing a TPM HMAC and optionally sealing the result.
#[derive(Clone, Eq, PartialEq)]
pub struct HmacParams {
    /// HMAC key selected by registry ID or persistent handle.
    pub material: ObjectSelector,
    /// Input bytes for the HMAC operation.
    pub input: Zeroizing<Vec<u8>>,
    /// Optional hash override; defaults from object metadata or SHA-256.
    pub hash: Option<HashAlgorithm>,
    /// Encoding for emitted HMAC bytes.
    pub output_format: BinaryFormat,
    /// Optional sealed-object destination for the HMAC output.
    pub seal_target: Option<SealTarget>,
    /// Whether to return HMAC bytes even when also sealing them.
    pub emit_prf_when_sealing: bool,
    /// Whether existing sealed registry entries or persistent handles may be replaced.
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

/// Compute an HMAC with a TPM-backed key and return or seal the result.
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

/// Parameters for sealing bytes into a TPM sealed-data object.
#[derive(Clone, Eq, PartialEq)]
pub struct SealParams {
    /// Registry ID or persistent handle where the sealed object is written.
    pub target: ObjectSelector,
    /// Secret bytes to seal.
    pub input: Zeroizing<Vec<u8>>,
    /// Whether an existing target may be replaced.
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

/// Seal bytes into a TPM object and store or persist it at the requested target.
pub fn seal(context: &Context, params: SealParams) -> Result<SealResult> {
    SealRequest {
        selector: params.target,
        input: params.input,
        force: params.overwrite,
    }
    .execute_with_context(&context.command())
}

/// Parameters for unsealing bytes from a TPM sealed-data object.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnsealParams {
    /// Sealed object selected by registry ID or persistent handle.
    pub material: ObjectSelector,
}

/// Unseal and return secret bytes from a TPM sealed-data object.
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
