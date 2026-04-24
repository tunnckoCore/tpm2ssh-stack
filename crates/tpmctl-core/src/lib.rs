//! Shared public contracts for the `tpmctl` workspace.
//!
//! This crate is intentionally library-first: TPM semantics, registry access,
//! output encoders, and derived-key helpers live here. Frontends such as the CLI
//! and PKCS#11 provider should depend on these typed contracts rather than
//! shelling out to another binary.

pub mod crypto;
pub mod ecdh;
pub mod error;
pub mod hmac;
pub mod keygen;
pub mod output;
pub mod pubkey;
pub mod seal;
pub mod sign;
pub mod store;
pub mod tpm;

use std::{
    fmt, fs,
    io::{self, Read as _, Write as _},
    str::FromStr,
};

use sha2::{Digest as _, Sha256, Sha384, Sha512};
use zeroize::{Zeroize as _, Zeroizing};

pub use error::{CoreError, Error, Result};
pub use output::{EncodedOutput, OutputFormat};
pub use store::{IdentityRef, ObjectKind, RegistryId, Store, StoreOptions};
pub use tpm::{CommandContext, KeyUsage, PersistentHandle};

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sign => "sign",
            Self::Ecdh => "ecdh",
            Self::Hmac => "hmac",
            Self::Sealed => "sealed",
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(input).to_vec(),
            Self::Sha384 => Sha384::digest(input).to_vec(),
            Self::Sha512 => Sha512::digest(input).to_vec(),
        }
    }

    pub fn validate_digest(self, digest: &[u8]) -> Result<()> {
        let expected = self.digest_len();
        if digest.len() == expected {
            Ok(())
        } else {
            Err(Error::invalid(
                "digest",
                format!(
                    "{} digest must be {expected} bytes, got {} bytes",
                    self,
                    digest.len()
                ),
            ))
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        })
    }
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "sha256" | "SHA256" | "sha-256" => Ok(Self::Sha256),
            "sha384" | "SHA384" | "sha-384" => Ok(Self::Sha384),
            "sha512" | "SHA512" | "sha-512" => Ok(Self::Sha512),
            other => Err(Error::invalid(
                "hash",
                format!("expected sha256, sha384, or sha512; got {other:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ObjectSelector {
    Id(RegistryId),
    Handle(PersistentHandle),
}

impl ObjectSelector {
    pub fn ssh_comment(&self) -> String {
        match self {
            Self::Id(id) => id.ssh_comment(),
            Self::Handle(handle) => handle.to_string(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObjectDescriptor {
    pub selector: ObjectSelector,
    pub usage: KeyUsage,
    pub curve: Option<EccCurve>,
    pub hash: Option<HashAlgorithm>,
    pub public_key: Option<EccPublicKey>,
}

impl ObjectDescriptor {
    pub fn require_usage(&self, expected: KeyUsage) -> Result<()> {
        if self.usage == expected {
            Ok(())
        } else {
            Err(Error::invalid(
                "usage",
                format!("expected {expected} object, got {}", self.usage),
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EccCurve {
    P256,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EccPublicKey {
    curve: EccCurve,
    sec1: Vec<u8>,
}

impl EccPublicKey {
    pub fn p256_sec1(sec1: impl Into<Vec<u8>>) -> Result<Self> {
        let sec1 = sec1.into();
        let key = p256::PublicKey::from_sec1_bytes(&sec1)
            .map_err(|error| Error::invalid("public_key", error.to_string()))?;
        let point = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&key, false);
        Ok(Self {
            curve: EccCurve::P256,
            sec1: point.as_bytes().to_vec(),
        })
    }

    pub fn curve(&self) -> EccCurve {
        self.curve
    }

    pub fn sec1(&self) -> &[u8] {
        &self.sec1
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SealTarget {
    Id(RegistryId),
    Handle(PersistentHandle),
}

// Frontend request contracts used by the thin CLI adapter. These are kept at the
// crate root to preserve a stable, parser-free API surface while TPM semantics
// remain in the domain modules above.
use std::path::PathBuf;

pub type SignatureFormat = output::SignatureFormat;
pub type PublicKeyFormat = output::PublicKeyFormat;
pub type BinaryTextFormat = output::BinaryFormat;
pub type DeriveAlgorithm = crypto::derive::DerivedAlgorithm;
pub type DeriveUse = crypto::derive::DeriveUse;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DeriveFormat {
    Raw,
    Hex,
    Der,
    Address,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoreConfig {
    pub root: PathBuf,
}

impl StoreConfig {
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self> {
        Ok(Self {
            root: store::resolve_store_root(explicit.as_deref())?,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeOptions {
    pub store: StoreConfig,
    pub json: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MaterialRef {
    Id(String),
    Handle(PersistentHandle),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OutputTarget {
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InputSource {
    Stdin,
    File(PathBuf),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SealDestination {
    Id(String),
    Handle(PersistentHandle),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenRequest {
    pub runtime: RuntimeOptions,
    pub usage: KeyUsage,
    pub id: String,
    pub handle: Option<PersistentHandle>,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub input: SignInput,
    pub hash: HashAlgorithm,
    pub format: SignatureFormat,
    pub output: OutputTarget,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SignInput {
    Message(InputSource),
    Digest(InputSource),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PubkeyRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub format: PublicKeyFormat,
    pub output: OutputTarget,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EcdhRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub peer_pub: InputSource,
    pub format: BinaryTextFormat,
    pub output: OutputTarget,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HmacRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub input: InputSource,
    pub hash: Option<HashAlgorithm>,
    pub format: BinaryTextFormat,
    pub output: OutputTarget,
    pub seal: Option<SealDestination>,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SealRequest {
    pub runtime: RuntimeOptions,
    pub input: InputSource,
    pub destination: SealDestination,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnsealRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub output: OutputTarget,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeriveRequest {
    pub runtime: RuntimeOptions,
    pub material: MaterialRef,
    pub label: Option<String>,
    pub algorithm: DeriveAlgorithm,
    pub usage: DeriveUse,
    pub input: Option<SignInput>,
    pub hash: Option<HashAlgorithm>,
    pub format: DeriveFormat,
    pub compressed: bool,
    pub output: OutputTarget,
    pub force: bool,
}

pub fn keygen(request: KeygenRequest) -> Result<()> {
    let usage = match request.usage {
        KeyUsage::Sign => keygen::KeygenUsage::Sign,
        KeyUsage::Ecdh => keygen::KeygenUsage::Ecdh,
        KeyUsage::Hmac => keygen::KeygenUsage::Hmac,
        KeyUsage::Sealed => {
            return Err(Error::invalid(
                "usage",
                "keygen supports sign, ecdh, and hmac usages",
            ));
        }
    };
    let id = RegistryId::new(request.id)?;
    let store = Store::new(request.runtime.store.root);
    keygen::KeygenRequest {
        usage,
        id,
        persist_at: request.handle,
        force: request.force,
    }
    .execute_with_store(&store)?;
    Ok(())
}

pub fn sign(request: SignRequest) -> Result<()> {
    let store = Store::new(request.runtime.store.root);
    let input = match request.input {
        SignInput::Message(source) => sign::SignInput::Message(read_input(&source)?),
        SignInput::Digest(source) => sign::SignInput::Digest(read_input(&source)?),
    };
    let domain_request = sign::SignRequest {
        selector: material_selector(request.material)?,
        input,
        hash: request.hash,
        format: request.format,
    };
    let output = domain_request.execute(&store)?;
    write_output(&request.output, &output, request.force)
}

pub fn pubkey(request: PubkeyRequest) -> Result<()> {
    let store = Store::new(request.runtime.store.root);
    let domain_request = pubkey::PubkeyRequest {
        selector: material_selector(request.material)?,
        format: request.format,
    };
    let output = domain_request.execute(&store)?;
    write_output(&request.output, &output, request.force)
}

pub fn ecdh(request: EcdhRequest) -> Result<()> {
    let store = Store::new(request.runtime.store.root);
    let peer_public_key = pubkey::PublicKeyInput::parse_bytes(read_input(&request.peer_pub)?)?;
    let domain_request = ecdh::EcdhRequest {
        selector: material_selector(request.material)?,
        peer_public_key,
        format: request.format,
    };
    let output = domain_request.execute(&store)?;
    write_output(&request.output, &output, request.force)
}

pub fn hmac(request: HmacRequest) -> Result<()> {
    let command = command_context(&request.runtime);
    let selector = material_selector(request.material)?;
    let input = read_input(&request.input)?;
    let seal_target = request.seal.map(seal_target).transpose()?;
    let domain = hmac::HmacRequest {
        selector,
        input,
        hash: request.hash,
        format: request.format,
        seal_target,
        emit_prf_when_sealing: false,
        force: request.force,
    };

    match domain.execute_with_context(&command)? {
        hmac::HmacResult::Output(output) => {
            let encoded = zeroize::Zeroizing::new(hmac::encode_hmac_output(
                output.as_slice(),
                request.format,
            ));
            write_output(&request.output, encoded.as_slice(), request.force)?;
        }
        hmac::HmacResult::Sealed { target, hash } => {
            write_hmac_sealed_result(&request.runtime, &target, hash)?;
        }
        hmac::HmacResult::SealedWithOutput {
            target,
            hash,
            output,
        } => {
            let encoded = zeroize::Zeroizing::new(hmac::encode_hmac_output(
                output.as_slice(),
                request.format,
            ));
            write_output(&request.output, encoded.as_slice(), request.force)?;
            write_hmac_sealed_result(&request.runtime, &target, hash)?;
        }
    }
    Ok(())
}

pub fn seal(request: SealRequest) -> Result<()> {
    let command = command_context(&request.runtime);
    let input = read_input(&request.input)?;
    let selector = seal_destination_selector(request.destination)?;
    let domain = seal::SealRequest {
        selector,
        input,
        force: request.force,
    };
    let result = domain.execute_with_context(&command)?;
    write_seal_result(&request.runtime, &result.selector, result.hash)
}

pub fn unseal(request: UnsealRequest) -> Result<()> {
    let command = command_context(&request.runtime);
    let selector = material_selector(request.material)?;
    let domain = seal::UnsealRequest {
        selector,
        force_binary_stdout: request.force,
    };
    let bytes = domain.execute_with_context(&command)?;
    write_output(&request.output, bytes.as_slice(), request.force)
}

pub fn derive(request: DeriveRequest) -> Result<()> {
    validate_derive_request(&request)?;
    if request.label.is_none() && matches!(request.usage, DeriveUse::Pubkey | DeriveUse::Secret) {
        eprintln!(
            "warning: --label was not provided; derived material is ephemeral and will change on each invocation"
        );
    }

    let command = command_context(&request.runtime);
    let seed_bytes = seal::UnsealRequest {
        selector: material_selector(request.material.clone())?,
        force_binary_stdout: false,
    }
    .execute_with_context(&command)?;
    let seed = crypto::derive::SecretSeed::new(seed_bytes.as_slice()).map_err(derive_error)?;
    let mode = derive_mode(&request)?;
    let output = derive_output(&request, &seed, &mode)?;
    write_output(&request.output, output.as_slice(), request.force)
}

fn validate_derive_request(request: &DeriveRequest) -> Result<()> {
    if request.usage == DeriveUse::Sign && request.input.is_none() {
        return Err(Error::invalid(
            "derive",
            "derive --use sign requires exactly one of --input or --digest",
        ));
    }
    if request.usage != DeriveUse::Sign && request.input.is_some() {
        return Err(Error::invalid(
            "derive",
            "derive --input/--digest are only valid with --use sign",
        ));
    }
    if request.algorithm == DeriveAlgorithm::Ed25519
        && request.usage == DeriveUse::Sign
        && request.hash.is_some()
    {
        return Err(Error::invalid(
            "derive",
            "derive --algorithm ed25519 --use sign does not support --hash in v1",
        ));
    }
    if request.usage == DeriveUse::Secret
        && !matches!(request.format, DeriveFormat::Raw | DeriveFormat::Hex)
    {
        return Err(Error::invalid(
            "derive",
            "derive --use secret supports only --format raw or --format hex",
        ));
    }
    if request.usage == DeriveUse::Pubkey {
        match request.algorithm {
            DeriveAlgorithm::P256 | DeriveAlgorithm::Ed25519 => {
                if !matches!(request.format, DeriveFormat::Raw | DeriveFormat::Hex) {
                    return Err(Error::invalid(
                        "derive",
                        "derive --use pubkey with p256 or ed25519 supports only --format raw or --format hex",
                    ));
                }
            }
            DeriveAlgorithm::Secp256k1 => {
                if !matches!(
                    request.format,
                    DeriveFormat::Raw | DeriveFormat::Hex | DeriveFormat::Address
                ) {
                    return Err(Error::invalid(
                        "derive",
                        "derive --use pubkey --algorithm secp256k1 supports --format raw, hex, or address",
                    ));
                }
            }
        }
    }
    if request.usage == DeriveUse::Sign {
        match request.algorithm {
            DeriveAlgorithm::Ed25519 => {
                if !matches!(request.format, DeriveFormat::Raw | DeriveFormat::Hex) {
                    return Err(Error::invalid(
                        "derive",
                        "derive --algorithm ed25519 --use sign supports only --format raw or --format hex",
                    ));
                }
            }
            DeriveAlgorithm::P256 | DeriveAlgorithm::Secp256k1 => {
                if !matches!(
                    request.format,
                    DeriveFormat::Der | DeriveFormat::Raw | DeriveFormat::Hex
                ) {
                    return Err(Error::invalid(
                        "derive",
                        "derive --use sign with p256 or secp256k1 supports --format der, raw, or hex",
                    ));
                }
            }
        }
    }
    if request.compressed
        && !(request.algorithm == DeriveAlgorithm::Secp256k1
            && request.usage == DeriveUse::Pubkey
            && matches!(request.format, DeriveFormat::Raw | DeriveFormat::Hex))
    {
        return Err(Error::invalid(
            "compressed",
            "--compressed is valid only for derive --algorithm secp256k1 --use pubkey with --format raw or hex",
        ));
    }
    if request.format == DeriveFormat::Address
        && !(request.algorithm == DeriveAlgorithm::Secp256k1 && request.usage == DeriveUse::Pubkey)
    {
        return Err(Error::invalid(
            "format",
            "--format address is valid only for derive --algorithm secp256k1 --use pubkey",
        ));
    }

    crypto::derive::DeriveRequest::new(
        request.algorithm,
        request.usage,
        request.hash.map(hash_selection),
    )
    .map_err(derive_error)?;
    Ok(())
}

fn derive_mode(request: &DeriveRequest) -> Result<crypto::derive::DeriveMode> {
    if let Some(label) = &request.label {
        Ok(crypto::derive::DeriveMode::deterministic(
            label.as_bytes().to_vec(),
        ))
    } else {
        let mut entropy = Zeroizing::new(vec![0_u8; 32]);
        getrandom::fill(&mut entropy)
            .map_err(|error| Error::invalid("entropy", error.to_string()))?;
        Ok(crypto::derive::DeriveMode::ephemeral(
            Vec::new(),
            entropy.to_vec(),
        ))
    }
}

fn derive_output(
    request: &DeriveRequest,
    seed: &crypto::derive::SecretSeed,
    mode: &crypto::derive::DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    match request.usage {
        DeriveUse::Secret => derive_secret(request, seed, mode),
        DeriveUse::Pubkey => derive_public_key(request, seed, mode),
        DeriveUse::Sign => derive_signature(request, seed, mode),
    }
}

fn derive_secret(
    request: &DeriveRequest,
    seed: &crypto::derive::SecretSeed,
    mode: &crypto::derive::DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut raw = match request.algorithm {
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
    let encoded = encode_raw_or_hex(&raw, request.format)?;
    raw.zeroize();
    Ok(Zeroizing::new(encoded))
}

fn derive_public_key(
    request: &DeriveRequest,
    seed: &crypto::derive::SecretSeed,
    mode: &crypto::derive::DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = match request.algorithm {
        DeriveAlgorithm::P256 => {
            let raw =
                crypto::p256::derive_public_key_sec1(seed, mode, false).map_err(derive_error)?;
            encode_raw_or_hex(&raw, request.format)?
        }
        DeriveAlgorithm::Ed25519 => {
            let raw = crypto::ed25519::derive_public_key_bytes(seed, mode).map_err(derive_error)?;
            encode_raw_or_hex(&raw, request.format)?
        }
        DeriveAlgorithm::Secp256k1 if request.format == DeriveFormat::Address => {
            crypto::secp256k1::derive_ethereum_address(seed, mode)
                .map_err(derive_error)?
                .into_bytes()
        }
        DeriveAlgorithm::Secp256k1 => {
            let raw = crypto::secp256k1::derive_public_key_sec1(seed, mode, request.compressed)
                .map_err(derive_error)?;
            encode_raw_or_hex(&raw, request.format)?
        }
    };
    Ok(Zeroizing::new(bytes))
}

fn derive_signature(
    request: &DeriveRequest,
    seed: &crypto::derive::SecretSeed,
    mode: &crypto::derive::DeriveMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let message = derive_sign_message_bytes(request)?;
    let bytes = match request.algorithm {
        DeriveAlgorithm::P256 => {
            let mut p1363 =
                crypto::p256::sign_message(seed, mode, &message).map_err(derive_error)?;
            let encoded = output::encode_p256_signature(&p1363, signature_format(request.format)?)?;
            p1363.zeroize();
            encoded
        }
        DeriveAlgorithm::Ed25519 => {
            let mut raw =
                crypto::ed25519::sign_message(seed, mode, &message).map_err(derive_error)?;
            let encoded = encode_raw_or_hex(&raw, request.format)?;
            raw.zeroize();
            encoded
        }
        DeriveAlgorithm::Secp256k1 => {
            let mut p1363 =
                crypto::secp256k1::sign_message(seed, mode, &message).map_err(derive_error)?;
            let encoded =
                output::encode_secp256k1_signature(&p1363, signature_format(request.format)?)?;
            p1363.zeroize();
            encoded
        }
    };
    Ok(Zeroizing::new(bytes))
}

fn derive_sign_message_bytes(request: &DeriveRequest) -> Result<Zeroizing<Vec<u8>>> {
    match request
        .input
        .as_ref()
        .expect("derive --use sign input was validated")
    {
        SignInput::Message(source) => {
            let bytes = read_input(source)?;
            if request.algorithm == DeriveAlgorithm::Ed25519 {
                Ok(Zeroizing::new(bytes))
            } else {
                Ok(Zeroizing::new(derive_hash(request).unwrap().digest(&bytes)))
            }
        }
        SignInput::Digest(source) => {
            let bytes = read_input(source)?;
            if request.algorithm != DeriveAlgorithm::Ed25519 {
                derive_hash(request).unwrap().validate_digest(&bytes)?;
            }
            Ok(Zeroizing::new(bytes))
        }
    }
}

fn encode_raw_or_hex(raw: &[u8], format: DeriveFormat) -> Result<Vec<u8>> {
    match format {
        DeriveFormat::Raw => Ok(output::encode_binary(raw, BinaryTextFormat::Raw)),
        DeriveFormat::Hex => Ok(output::encode_binary(raw, BinaryTextFormat::Hex)),
        DeriveFormat::Der | DeriveFormat::Address => Err(Error::invalid(
            "format",
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
            "format",
            "derive --use sign does not support --format address",
        )),
    }
}

fn derive_hash(request: &DeriveRequest) -> Option<HashAlgorithm> {
    if request.usage == DeriveUse::Sign
        && matches!(
            request.algorithm,
            DeriveAlgorithm::P256 | DeriveAlgorithm::Secp256k1
        )
    {
        Some(request.hash.unwrap_or(HashAlgorithm::Sha256))
    } else {
        request.hash
    }
}

fn hash_selection(hash: HashAlgorithm) -> crypto::derive::HashSelection {
    match hash {
        HashAlgorithm::Sha256 => crypto::derive::HashSelection::Sha256,
        HashAlgorithm::Sha384 => crypto::derive::HashSelection::Sha384,
        HashAlgorithm::Sha512 => crypto::derive::HashSelection::Sha512,
    }
}

fn derive_error(error: impl std::fmt::Display) -> Error {
    Error::invalid("derive", error.to_string())
}

fn command_context(runtime: &RuntimeOptions) -> CommandContext {
    CommandContext {
        store: StoreOptions {
            root: Some(runtime.store.root.clone()),
        },
        tcti: None,
    }
}

fn material_selector(material: MaterialRef) -> Result<ObjectSelector> {
    match material {
        MaterialRef::Id(id) => Ok(ObjectSelector::Id(RegistryId::new(id)?)),
        MaterialRef::Handle(handle) => Ok(ObjectSelector::Handle(handle)),
    }
}

fn seal_destination_selector(destination: SealDestination) -> Result<ObjectSelector> {
    match destination {
        SealDestination::Id(id) => Ok(ObjectSelector::Id(RegistryId::new(id)?)),
        SealDestination::Handle(handle) => Ok(ObjectSelector::Handle(handle)),
    }
}

fn seal_target(destination: SealDestination) -> Result<SealTarget> {
    match destination {
        SealDestination::Id(id) => Ok(SealTarget::Id(RegistryId::new(id)?)),
        SealDestination::Handle(handle) => Ok(SealTarget::Handle(handle)),
    }
}

fn read_input(source: &InputSource) -> Result<Vec<u8>> {
    match source {
        InputSource::Stdin => {
            let mut bytes = Vec::new();
            io::stdin()
                .read_to_end(&mut bytes)
                .map_err(|source| CoreError::io("<stdin>", source))?;
            Ok(bytes)
        }
        InputSource::File(path) => fs::read(path).map_err(|source| CoreError::io(path, source)),
    }
}

fn write_output(target: &OutputTarget, bytes: &[u8], force: bool) -> Result<()> {
    match &target.path {
        None => io::stdout()
            .write_all(bytes)
            .map_err(|source| CoreError::io("<stdout>", source)),
        Some(path) => {
            if path.exists() && !force {
                return Err(CoreError::AlreadyExists(path.clone()));
            }
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                fs::create_dir_all(parent).map_err(|source| CoreError::io(parent, source))?;
            }
            fs::write(path, bytes).map_err(|source| CoreError::io(path, source))
        }
    }
}

fn write_hmac_sealed_result(
    runtime: &RuntimeOptions,
    target: &SealTarget,
    hash: HashAlgorithm,
) -> Result<()> {
    if runtime.json {
        let value = match target {
            SealTarget::Handle(handle) => serde_json::json!({
                "sealed_at": handle.to_string(),
                "hash": hash.to_string(),
            }),
            SealTarget::Id(id) => serde_json::json!({
                "sealed_id": id.to_string(),
                "hash": hash.to_string(),
            }),
        };
        println!("{value}");
    } else {
        match target {
            SealTarget::Handle(handle) => {
                println!("sealed {} bytes at {handle}", hash.digest_len())
            }
            SealTarget::Id(id) => println!("sealed {} bytes as {id}", hash.digest_len()),
        }
    }
    Ok(())
}

fn write_seal_result(
    runtime: &RuntimeOptions,
    selector: &ObjectSelector,
    hash: Option<HashAlgorithm>,
) -> Result<()> {
    if runtime.json {
        let value = match selector {
            ObjectSelector::Handle(handle) => {
                let mut value = serde_json::json!({ "sealed_at": handle.to_string() });
                if let Some(hash) = hash {
                    value["hash"] = serde_json::json!(hash.to_string());
                }
                value
            }
            ObjectSelector::Id(id) => {
                let mut value = serde_json::json!({ "sealed_id": id.to_string() });
                if let Some(hash) = hash {
                    value["hash"] = serde_json::json!(hash.to_string());
                }
                value
            }
        };
        println!("{value}");
    } else {
        match selector {
            ObjectSelector::Handle(handle) => println!("sealed at {handle}"),
            ObjectSelector::Id(id) => println!("sealed as {id}"),
        }
    }
    Ok(())
}
