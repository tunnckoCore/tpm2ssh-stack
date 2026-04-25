use std::{env, fmt, str::FromStr};

use crate::{
    CoreError, EccCurve, EccPublicKey, Error, HashAlgorithm, ObjectDescriptor, ObjectSelector,
    Result,
    store::{ObjectUsage, RegistryCollection, RegistryId, Store, StoreOptions, StoredObjectEntry},
};
use zeroize::Zeroizing;

use tss_esapi::{
    Context,
    attributes::ObjectAttributesBuilder,
    constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        dynamic_handles::Persistent,
        ecc::EccCurve as TpmEccCurve,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, Provision},
        session_handles::AuthSession,
    },
    structures::{
        Auth, Digest, EccParameter, EccPoint, HashScheme, HashcheckTicket, Name, Private, Public,
        PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, Signature,
        SignatureScheme, SymmetricDefinitionObject,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMT_TK_HASHCHECK,
};
/// Shared execution context passed into core operations.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CommandContext {
    /// Optional store configuration supplied by the caller.
    pub store: StoreOptions,
    /// Optional TCTI override. Environment fallback is handled by TPM helpers.
    pub tcti: Option<String>,
}

/// Supported TPM-backed object usages.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum KeyUsage {
    Sign,
    Ecdh,
    Hmac,
    Sealed,
}

pub const TCTI_ENV_PRECEDENCE: [&str; 3] = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"];

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TctiResolution {
    pub source: TctiSource,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TctiSource {
    Env(&'static str),
    DefaultDevice,
}

impl TctiResolution {
    pub fn from_environment() -> Self {
        for name in TCTI_ENV_PRECEDENCE {
            if let Ok(value) = env::var(name) {
                if !value.trim().is_empty() {
                    return Self {
                        source: TctiSource::Env(name),
                        value: Some(value),
                    };
                }
            }
        }

        Self {
            source: TctiSource::DefaultDevice,
            value: None,
        }
    }

    pub fn to_name_conf(&self) -> Result<TctiNameConf> {
        match (&self.source, &self.value) {
            (TctiSource::Env(name), Some(value)) => {
                value.parse::<TctiNameConf>().map_err(|source| {
                    CoreError::Tcti(format!(
                        "failed to parse {name}={value:?} as a TCTI configuration: {source}"
                    ))
                })
            }
            (TctiSource::DefaultDevice, None) => Ok(TctiNameConf::Device(DeviceConfig::default())),
            _ => Err(CoreError::Tcti("inconsistent TCTI resolution state".into())),
        }
    }
}

pub fn resolve_tcti_name_conf() -> Result<TctiNameConf> {
    TctiResolution::from_environment().to_name_conf()
}

pub fn tcti_name_conf_from_env() -> std::result::Result<TctiNameConf, String> {
    resolve_tcti_name_conf().map_err(|error| error.to_string())
}

pub fn parse_tpm_handle_literal(value: &str) -> std::result::Result<Option<TpmHandle>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("empty TPM handle".to_owned());
    }

    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(u32::from_str_radix(hex, 16).map_err(|error| error.to_string())?)
    } else if trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(
            trimmed
                .parse::<u32>()
                .map_err(|error: std::num::ParseIntError| error.to_string())?,
        )
    } else {
        None
    };

    match parsed {
        Some(raw) => TpmHandle::try_from(raw)
            .map(Some)
            .map_err(|error| format!("unsupported TPM handle {trimmed}: {error}")),
        None => Ok(None),
    }
}

pub fn resolve_tcti(override_value: Option<&str>) -> Result<String> {
    if let Some(value) = override_value {
        if value.trim().is_empty() {
            return Err(CoreError::Tcti("TCTI override is empty".into()));
        }
        return Ok(value.to_owned());
    }

    let resolution = TctiResolution::from_environment();
    Ok(resolution
        .value
        .unwrap_or_else(|| "device:/dev/tpmrm0".to_owned()))
}

pub fn create_context() -> Result<Context> {
    let tcti = resolve_tcti_name_conf()?;
    Context::new(tcti).map_err(|source| CoreError::tpm("Context::new", source))
}

pub const OWNER_STORAGE_PARENT_TEMPLATE: &str = "owner-rsa2048-aes128cfb-restricted-decrypt";

#[derive(Clone)]
pub struct CreatedChildKey {
    pub public: Public,
    pub private: Private,
}

impl fmt::Debug for CreatedChildKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedChildKey")
            .field("public", &self.public)
            .field("private", &"<redacted>")
            .finish()
    }
}

pub fn create_context_with_tcti(override_value: Option<&str>) -> Result<Context> {
    let tcti = match override_value {
        Some(value) if value.trim().is_empty() => {
            return Err(CoreError::Tcti("TCTI override is empty".into()));
        }
        Some(value) => value.parse::<TctiNameConf>().map_err(|source| {
            CoreError::Tcti(format!(
                "failed to parse TCTI override {value:?} as a TCTI configuration: {source}"
            ))
        })?,
        None => resolve_tcti_name_conf()?,
    };
    Context::new(tcti).map_err(|source| CoreError::tpm("Context::new", source))
}

pub fn create_context_for(command: &CommandContext) -> Result<Context> {
    create_context_with_tcti(command.tcti.as_deref())
}

pub fn hashing_algorithm(hash: HashAlgorithm) -> HashingAlgorithm {
    match hash {
        HashAlgorithm::Sha256 => HashingAlgorithm::Sha256,
        HashAlgorithm::Sha384 => HashingAlgorithm::Sha384,
        HashAlgorithm::Sha512 => HashingAlgorithm::Sha512,
    }
}

pub fn owner_storage_parent_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()
        .map_err(|source| CoreError::tpm("build owner storage parent attributes", source))?;

    let parameters = PublicRsaParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .build()
    .map_err(|source| CoreError::tpm("build owner storage parent parameters", source))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(parameters)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|source| CoreError::tpm("build owner storage parent template", source))
}

pub fn create_owner_storage_parent(context: &mut Context) -> Result<KeyHandle> {
    let public = owner_storage_parent_template()?;
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                public,
                Some(Auth::default()),
                None,
                None,
                None,
            )
        })
        .map(|result| result.key_handle)
        .map_err(|source| CoreError::tpm("CreatePrimary owner storage parent", source))
}

pub fn create_owner_primary(context: &mut Context) -> Result<KeyHandle> {
    create_owner_storage_parent(context)
}

pub fn create_child_key(
    context: &mut Context,
    parent_handle: KeyHandle,
    public: Public,
) -> Result<CreatedChildKey> {
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create(
                parent_handle,
                public,
                Some(Auth::default()),
                None,
                None,
                None,
            )
        })
        .map(|result| CreatedChildKey {
            public: result.out_public,
            private: result.out_private,
        })
        .map_err(|source| CoreError::tpm("Create child object", source))
}

pub fn load_created_child_key(
    context: &mut Context,
    parent_handle: KeyHandle,
    child: &CreatedChildKey,
) -> Result<KeyHandle> {
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(parent_handle, child.private.clone(), child.public.clone())
        })
        .map_err(|source| CoreError::tpm("Load child object", source))
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PersistentHandle {
    raw: u32,
    handle: PersistentTpmHandle,
}

impl PersistentHandle {
    pub fn new(raw: u32) -> Result<Self> {
        let handle = PersistentTpmHandle::new(raw).map_err(|error| {
            invalid_handle(
                &format!("0x{raw:08x}"),
                format!("not a persistent TPM handle: {error}"),
            )
        })?;
        Ok(Self { raw, handle })
    }

    pub fn parse(input: impl AsRef<str>) -> Result<Self> {
        input.as_ref().parse()
    }

    pub fn raw(self) -> u32 {
        self.raw
    }

    pub fn tpm_handle(self) -> TpmHandle {
        TpmHandle::Persistent(self.handle)
    }

    pub fn persistent_tpm_handle(self) -> PersistentTpmHandle {
        self.handle
    }
}

impl std::hash::Hash for PersistentHandle {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl std::fmt::Display for PersistentHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "0x{:08x}", self.raw)
    }
}

impl FromStr for PersistentHandle {
    type Err = CoreError;

    fn from_str(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(invalid_handle(input, "handle is empty"));
        }
        if trimmed != input {
            return Err(invalid_handle(
                input,
                "leading or trailing whitespace is not allowed",
            ));
        }

        let Some(hex) = trimmed.strip_prefix("0x") else {
            return Err(invalid_handle(
                input,
                "persistent handles must be hexadecimal and start with 0x",
            ));
        };
        if hex.is_empty() {
            return Err(invalid_handle(input, "hex digits are missing"));
        }
        if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_handle(
                input,
                "handle contains non-hexadecimal characters",
            ));
        }

        let raw = u32::from_str_radix(hex, 16)
            .map_err(|error| invalid_handle(input, format!("handle is out of range: {error}")))?;
        let handle = PersistentTpmHandle::new(raw).map_err(|error| {
            invalid_handle(input, format!("not a persistent TPM handle: {error}"))
        })?;

        Ok(Self { raw, handle })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ObjectBlobs {
    pub public: Vec<u8>,
    pub private: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ObjectBlobs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectBlobs")
            .field("public", &self.public)
            .field("private", &"<redacted>")
            .finish()
    }
}

impl ObjectBlobs {
    pub fn from_entry(entry: &StoredObjectEntry) -> Self {
        Self {
            public: entry.public_blob.clone(),
            private: entry.private_blob.clone(),
        }
    }
}

pub fn marshal_public(public: &Public) -> Result<Vec<u8>> {
    public
        .marshall()
        .map_err(|source| CoreError::tpm("marshal public object", source))
}

pub fn marshal_private(private: &Private) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(private.value().to_vec()))
}

pub fn unmarshal_public(bytes: &[u8]) -> Result<Public> {
    Public::unmarshall(bytes).map_err(|source| CoreError::tpm("unmarshal public object", source))
}

pub fn unmarshal_private(bytes: &[u8]) -> Result<Private> {
    Private::try_from(bytes).map_err(|source| CoreError::tpm("unmarshal private object", source))
}

pub fn load_object_from_blobs(
    context: &mut Context,
    parent_handle: KeyHandle,
    blobs: &ObjectBlobs,
) -> Result<KeyHandle> {
    let private = unmarshal_private(&blobs.private)?;
    let public = unmarshal_public(&blobs.public)?;
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(parent_handle, private, public)
        })
        .map_err(|source| CoreError::tpm("Load", source))
}

pub fn load_object_from_registry(
    context: &mut Context,
    store: &Store,
    collection: RegistryCollection,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<KeyHandle> {
    let entry = store.load_entry(collection, id)?;
    load_object_from_blobs(context, parent_handle, &ObjectBlobs::from_entry(&entry))
}

pub fn load_key_from_registry(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<KeyHandle> {
    load_object_from_registry(context, store, RegistryCollection::Keys, id, parent_handle)
}

pub fn load_key_from_registry_with_descriptor(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<(KeyHandle, ObjectDescriptor)> {
    let entry = store.load_entry(RegistryCollection::Keys, id)?;
    let descriptor = descriptor_from_registry_entry(RegistryCollection::Keys, id, &entry)?;
    let handle = load_object_from_blobs(context, parent_handle, &ObjectBlobs::from_entry(&entry))?;
    Ok((handle, descriptor))
}

pub fn load_sealed_from_registry(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<KeyHandle> {
    load_object_from_registry(
        context,
        store,
        RegistryCollection::Sealed,
        id,
        parent_handle,
    )
}

pub fn load_sealed_from_registry_with_descriptor(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<(KeyHandle, ObjectDescriptor)> {
    let entry = store.load_entry(RegistryCollection::Sealed, id)?;
    let descriptor = descriptor_from_registry_entry(RegistryCollection::Sealed, id, &entry)?;
    let handle = load_object_from_blobs(context, parent_handle, &ObjectBlobs::from_entry(&entry))?;
    Ok((handle, descriptor))
}

pub fn load_persistent_object(
    context: &mut Context,
    handle: PersistentHandle,
) -> Result<ObjectHandle> {
    context
        .tr_from_tpm_public(handle.tpm_handle())
        .map_err(|source| CoreError::tpm("TR_FromTPMPublic", source))
}

pub fn read_public(
    context: &mut Context,
    object_handle: ObjectHandle,
) -> Result<(Public, Name, Name)> {
    context
        .read_public(KeyHandle::from(object_handle))
        .map_err(|source| CoreError::tpm("ReadPublic", source))
}

pub fn persist_object(
    context: &mut Context,
    object_handle: ObjectHandle,
    destination: PersistentHandle,
) -> Result<ObjectHandle> {
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                object_handle,
                Persistent::from(destination.persistent_tpm_handle()),
            )
        })
        .map_err(|source| CoreError::tpm("EvictControl persist object", source))
}

pub fn evict_persistent_object(
    context: &mut Context,
    object_handle: ObjectHandle,
    destination: PersistentHandle,
) -> Result<ObjectHandle> {
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                object_handle,
                Persistent::from(destination.persistent_tpm_handle()),
            )
        })
        .map_err(|source| CoreError::tpm("EvictControl evict persistent object", source))
}

pub fn create_default_parent(context: &mut Context) -> Result<KeyHandle> {
    create_owner_storage_parent(context)
}

pub fn load_key_by_id(context: &mut Context, store: &Store, id: &RegistryId) -> Result<LoadedKey> {
    let entry = store.load_key(id)?;
    let descriptor = descriptor_from_entry(ObjectSelector::Id(id.clone()), &entry)?;

    if let Some(handle) = registry_entry_handle(&entry)? {
        let object_handle = load_persistent_object(context, handle)?;
        let (public, _, _) = read_public(context, object_handle)?;
        let descriptor = descriptor.with_public_from_tpm(public)?;
        return Ok(LoadedKey {
            handle: KeyHandle::from(object_handle),
            descriptor,
        });
    }

    let parent_handle = create_default_parent(context)?;
    let handle = load_object_from_blobs(context, parent_handle, &ObjectBlobs::from_entry(&entry))?;
    Ok(LoadedKey { handle, descriptor })
}

pub fn load_key_by_handle(context: &mut Context, handle: PersistentHandle) -> Result<LoadedKey> {
    let object_handle = load_persistent_object(context, handle)?;
    let (public, _, _) = read_public(context, object_handle)?;
    Ok(LoadedKey {
        handle: KeyHandle::from(object_handle),
        descriptor: descriptor_from_tpm_public(ObjectSelector::Handle(handle), public)?,
    })
}

#[derive(Debug)]
pub struct LoadedKey {
    pub handle: KeyHandle,
    pub descriptor: ObjectDescriptor,
}

pub fn sign_digest(
    context: &mut Context,
    key_handle: KeyHandle,
    digest: &[u8],
    hash: HashAlgorithm,
) -> Result<Vec<u8>> {
    let digest = Digest::try_from(digest.to_vec())
        .map_err(|source| CoreError::tpm("build Sign digest", source))?;
    let scheme = SignatureScheme::EcDsa {
        hash_scheme: HashScheme::new(hash.to_tpm_hash()),
    };
    let validation = null_hashcheck_ticket()?;
    let signature = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.sign(key_handle, digest, scheme, validation)
        })
        .map_err(|source| CoreError::tpm("Sign", source))?;
    p1363_from_tpm_signature(signature)
}

pub fn ecdh_z_gen(
    context: &mut Context,
    key_handle: KeyHandle,
    peer_public_key: &EccPublicKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let point = ecc_point_from_public_key(peer_public_key)?;
    let z = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.ecdh_z_gen(key_handle, point)
        })
        .map_err(|source| CoreError::tpm("ECDH_ZGen", source))?;
    let mut x = Zeroizing::new(vec![0_u8; 32]);
    left_pad_copy(z.x().value(), x.as_mut_slice(), "ECDH_ZGen x coordinate")?;
    Ok(x)
}

pub fn ecc_public_key_from_public(public: &Public) -> Result<EccPublicKey> {
    match public {
        Public::Ecc {
            parameters, unique, ..
        } => {
            if parameters.ecc_curve() != TpmEccCurve::NistP256 {
                return Err(CoreError::invalid(
                    "curve",
                    format!("expected NIST P-256, got {:?}", parameters.ecc_curve()),
                ));
            }
            ecc_public_key_from_point(unique)
        }
        _ => Err(CoreError::invalid(
            "public",
            "expected an ECC public object",
        )),
    }
}

pub fn descriptor_from_tpm_public(
    selector: ObjectSelector,
    public: Public,
) -> Result<ObjectDescriptor> {
    let usage = usage_from_public(&public)?;
    let public_key = match usage {
        KeyUsage::Sign | KeyUsage::Ecdh => Some(ecc_public_key_from_public(&public)?),
        KeyUsage::Hmac | KeyUsage::Sealed => None,
    };
    Ok(ObjectDescriptor {
        selector,
        usage,
        curve: public_key.as_ref().map(|_| crate::EccCurve::P256),
        hash: None,
        public_key,
    })
}

pub(crate) fn descriptor_from_entry(
    selector: ObjectSelector,
    entry: &StoredObjectEntry,
) -> Result<ObjectDescriptor> {
    let usage = match entry.record.usage {
        ObjectUsage::Sign => KeyUsage::Sign,
        ObjectUsage::Ecdh => KeyUsage::Ecdh,
        ObjectUsage::Hmac => KeyUsage::Hmac,
        ObjectUsage::Sealed => KeyUsage::Sealed,
    };
    let curve = match entry.record.curve.as_deref() {
        Some("p256" | "P-256" | "nistp256" | "NIST P-256") => Some(crate::EccCurve::P256),
        Some(other) => {
            return Err(CoreError::invalid(
                "curve",
                format!("unsupported curve {other:?}"),
            ));
        }
        None => None,
    };
    let hash = match entry.record.hash.as_deref() {
        Some("sha256") => Some(HashAlgorithm::Sha256),
        Some("sha384") => Some(HashAlgorithm::Sha384),
        Some("sha512") => Some(HashAlgorithm::Sha512),
        Some(other) => {
            return Err(CoreError::invalid(
                "hash",
                format!("unsupported hash {other:?}"),
            ));
        }
        None => None,
    };
    let public_key = cached_public_key(entry)?.or_else(|| {
        unmarshal_public(&entry.public_blob)
            .ok()
            .and_then(|public| ecc_public_key_from_public(&public).ok())
    });

    Ok(ObjectDescriptor {
        selector,
        usage,
        curve,
        hash,
        public_key,
    })
}

fn cached_public_key(entry: &StoredObjectEntry) -> Result<Option<EccPublicKey>> {
    if let Some(public_key) = &entry.record.public_key {
        let hex = public_key
            .strip_prefix("hex:")
            .unwrap_or(public_key.as_str());
        let bytes = hex::decode(hex)
            .map_err(|source| CoreError::invalid("public_key", source.to_string()))?;
        return EccPublicKey::p256_sec1(bytes).map(Some);
    }

    if let Some(public_pem) = &entry.public_pem {
        if let Ok(pem) = std::str::from_utf8(public_pem) {
            let key = <p256::PublicKey as p256::pkcs8::DecodePublicKey>::from_public_key_pem(pem)
                .map_err(|source| CoreError::invalid("public_key", source.to_string()))?;
            let point = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&key, false);
            return EccPublicKey::p256_sec1(point.as_bytes().to_vec()).map(Some);
        }
    }

    Ok(None)
}

fn registry_entry_handle(entry: &StoredObjectEntry) -> Result<Option<PersistentHandle>> {
    if !entry.record.persistent {
        return Ok(None);
    }
    entry
        .record
        .handle
        .as_deref()
        .map(PersistentHandle::parse)
        .transpose()
}

fn usage_from_public(public: &Public) -> Result<KeyUsage> {
    let attrs = public.object_attributes();
    match public {
        Public::Ecc { .. } if attrs.sign_encrypt() && !attrs.decrypt() && !attrs.restricted() => {
            Ok(KeyUsage::Sign)
        }
        Public::Ecc { .. } if attrs.decrypt() && !attrs.sign_encrypt() && !attrs.restricted() => {
            Ok(KeyUsage::Ecdh)
        }
        Public::KeyedHash { .. } => Ok(KeyUsage::Hmac),
        _ => Err(CoreError::invalid(
            "usage",
            "unable to infer supported key usage from TPM public area",
        )),
    }
}

fn ecc_public_key_from_point(point: &EccPoint) -> Result<EccPublicKey> {
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(pad_coordinate(point.x().value(), "public key x coordinate")?.as_ref());
    sec1.extend_from_slice(pad_coordinate(point.y().value(), "public key y coordinate")?.as_ref());
    EccPublicKey::p256_sec1(sec1)
}

pub fn ecc_point_from_public_key(public_key: &EccPublicKey) -> Result<EccPoint> {
    let key = p256::PublicKey::from_sec1_bytes(public_key.sec1())
        .map_err(|source| CoreError::invalid("public_key", source.to_string()))?;
    let point = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&key, false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(CoreError::invalid(
            "public_key",
            "expected uncompressed P-256 SEC1 point",
        ));
    }
    Ok(EccPoint::new(
        EccParameter::try_from(bytes[1..33].to_vec())
            .map_err(|source| CoreError::tpm("build ECC x coordinate", source))?,
        EccParameter::try_from(bytes[33..65].to_vec())
            .map_err(|source| CoreError::tpm("build ECC y coordinate", source))?,
    ))
}

fn p1363_from_tpm_signature(signature: Signature) -> Result<Vec<u8>> {
    let Signature::EcDsa(signature) = signature else {
        return Err(CoreError::invalid(
            "signature",
            format!(
                "expected TPM ECDSA signature, got {:?}",
                signature.algorithm()
            ),
        ));
    };
    let mut p1363 = vec![0_u8; 64];
    left_pad_copy(
        signature.signature_r().value(),
        &mut p1363[..32],
        "signature r",
    )?;
    left_pad_copy(
        signature.signature_s().value(),
        &mut p1363[32..],
        "signature s",
    )?;
    Ok(p1363)
}

fn pad_coordinate(value: &[u8], field: &'static str) -> Result<[u8; 32]> {
    let mut out = [0_u8; 32];
    left_pad_copy(value, &mut out, field)?;
    Ok(out)
}

fn left_pad_copy(value: &[u8], out: &mut [u8], field: &'static str) -> Result<()> {
    if value.len() > out.len() {
        return Err(CoreError::invalid(
            field,
            format!("expected at most {} bytes, got {}", out.len(), value.len()),
        ));
    }
    let offset = out.len() - value.len();
    out[offset..].copy_from_slice(value);
    Ok(())
}

fn null_hashcheck_ticket() -> Result<HashcheckTicket> {
    let validation = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    };
    validation
        .try_into()
        .map_err(|source| CoreError::tpm("build hashcheck ticket", source))
}

impl HashAlgorithm {
    pub(crate) fn to_tpm_hash(self) -> HashingAlgorithm {
        match self {
            Self::Sha256 => HashingAlgorithm::Sha256,
            Self::Sha384 => HashingAlgorithm::Sha384,
            Self::Sha512 => HashingAlgorithm::Sha512,
        }
    }
}

impl ObjectDescriptor {
    fn with_public_from_tpm(mut self, public: Public) -> Result<Self> {
        let tpm_usage = usage_from_public(&public)?;
        if tpm_usage != self.usage {
            return Err(CoreError::invalid(
                "usage",
                format!(
                    "registry says {} but persistent handle contains {} object",
                    self.usage, tpm_usage
                ),
            ));
        }
        if matches!(self.usage, KeyUsage::Sign | KeyUsage::Ecdh) {
            self.public_key = Some(ecc_public_key_from_public(&public)?);
        }
        Ok(self)
    }
}

pub fn descriptor_from_registry_entry(
    collection: RegistryCollection,
    id: &RegistryId,
    entry: &StoredObjectEntry,
) -> Result<ObjectDescriptor> {
    let usage = key_usage_from_record(entry.record.usage);
    let expected_kind = match collection {
        RegistryCollection::Keys => crate::store::StoredObjectKind::Key,
        RegistryCollection::Sealed => crate::store::StoredObjectKind::Sealed,
    };
    if entry.record.kind != expected_kind {
        return Err(Error::invalid(
            "kind",
            format!(
                "registry entry {id} is {:?}, expected {:?}",
                entry.record.kind, expected_kind
            ),
        ));
    }

    Ok(ObjectDescriptor {
        selector: ObjectSelector::Id(id.clone()),
        usage,
        curve: entry
            .record
            .curve
            .as_deref()
            .map(curve_from_record)
            .transpose()?,
        hash: entry.record.hash.as_deref().map(str::parse).transpose()?,
        public_key: None,
    })
}

pub fn descriptor_from_public(
    selector: ObjectSelector,
    public: &Public,
) -> Result<ObjectDescriptor> {
    let usage = match public {
        Public::KeyedHash {
            object_attributes, ..
        } if object_attributes.sign_encrypt() => crate::KeyUsage::Hmac,
        Public::KeyedHash { .. } => crate::KeyUsage::Sealed,
        Public::Ecc { .. } | Public::Rsa { .. } => {
            return Err(Error::invalid(
                "usage",
                "object is not a keyed-hash HMAC key or sealed data object",
            ));
        }
        Public::SymCipher { .. } => {
            return Err(Error::invalid(
                "usage",
                "symmetric-cipher objects are not supported by this operation",
            ));
        }
    };

    Ok(ObjectDescriptor {
        selector,
        usage,
        curve: None,
        hash: None,
        public_key: None,
    })
}

fn key_usage_from_record(usage: ObjectUsage) -> crate::KeyUsage {
    match usage {
        ObjectUsage::Sign => crate::KeyUsage::Sign,
        ObjectUsage::Ecdh => crate::KeyUsage::Ecdh,
        ObjectUsage::Hmac => crate::KeyUsage::Hmac,
        ObjectUsage::Sealed => crate::KeyUsage::Sealed,
    }
}

fn curve_from_record(curve: &str) -> Result<EccCurve> {
    match curve {
        "p256" | "P-256" | "nistp256" => Ok(EccCurve::P256),
        other => Err(Error::invalid(
            "curve",
            format!("unsupported curve in registry record: {other:?}"),
        )),
    }
}

fn invalid_handle(input: &str, reason: impl Into<String>) -> CoreError {
    CoreError::InvalidHandle {
        input: input.to_owned(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn handle_parses_persistent_hex() {
        let handle = PersistentHandle::parse("0x81010010").unwrap();
        assert_eq!(handle.raw(), 0x8101_0010);
        assert_eq!(handle.to_string(), "0x81010010");
    }

    #[test]
    fn handle_rejects_non_persistent_or_non_hex_forms() {
        for input in [
            "",
            "81010010",
            "2164326416",
            "0x",
            "0xzzzzzzzz",
            "0X81010010",
            "0x80000000",
            " 0x81010010",
            "0x81010010 ",
        ] {
            assert!(
                PersistentHandle::parse(input).is_err(),
                "{input} should be rejected"
            );
        }
    }

    #[test]
    fn tcti_uses_documented_env_precedence() {
        let _guard = env_lock();
        unsafe {
            env::set_var("TPM2TOOLS_TCTI", "device:/dev/tpmrm0");
            env::set_var("TCTI", "swtpm:port=2321");
            env::set_var("TEST_TCTI", "mssim:host=localhost,port=2321");
        }

        let resolution = TctiResolution::from_environment();
        assert_eq!(resolution.source, TctiSource::Env("TPM2TOOLS_TCTI"));
        assert_eq!(resolution.value.as_deref(), Some("device:/dev/tpmrm0"));

        unsafe {
            env::remove_var("TPM2TOOLS_TCTI");
            env::remove_var("TCTI");
            env::remove_var("TEST_TCTI");
        }
    }

    #[test]
    fn tcti_falls_back_to_device() {
        let _guard = env_lock();
        unsafe {
            env::remove_var("TPM2TOOLS_TCTI");
            env::remove_var("TCTI");
            env::remove_var("TEST_TCTI");
        }

        let resolution = TctiResolution::from_environment();
        assert_eq!(resolution.source, TctiSource::DefaultDevice);
        assert_eq!(resolution.value, None);
    }
}
