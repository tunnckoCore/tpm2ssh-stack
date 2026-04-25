use tss_esapi::{
    Context,
    attributes::ObjectAttributesBuilder,
    constants::response_code::Tss2ResponseCodeKind,
    handles::ObjectHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve as TpmEccCurve,
    },
    structures::{
        Digest, EccPoint, EccScheme, HashScheme, HmacScheme, KeyDerivationFunctionScheme,
        KeyedHashScheme, Public, PublicBuilder, PublicEccParameters, PublicEccParametersBuilder,
        PublicKeyedHashParameters, SymmetricDefinitionObject,
    },
};

use crate::{
    CommandContext, CoreError, EccPublicKey, KeyUsage, ObjectSelector, PersistentHandle,
    RegistryId, Result,
    output::{PublicKeyFormat, encode_public_key},
    store::{
        ObjectUsage, ParentRecord, RegistryCollection, RegistryRecord, Store, StoredObjectEntry,
        StoredObjectKind,
    },
    tpm,
};

/// Domain request for creating and registering a TPM-backed key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenRequest {
    /// Intended usage for the new key.
    pub usage: KeygenUsage,
    /// Registry ID under which the key is stored.
    pub id: RegistryId,
    /// Optional persistent handle for the created key.
    pub persist_at: Option<PersistentHandle>,
    /// Whether existing registry entries or handles may be replaced.
    pub force: bool,
}

/// Key capabilities supported by key generation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeygenUsage {
    /// P-256 signing key.
    Sign,
    /// P-256 ECDH key-agreement key.
    Ecdh,
    /// Keyed-hash HMAC key.
    Hmac,
}

impl KeygenUsage {
    /// Convert this generation usage into runtime object usage.
    pub fn object_usage(self) -> KeyUsage {
        match self {
            Self::Sign => KeyUsage::Sign,
            Self::Ecdh => KeyUsage::Ecdh,
            Self::Hmac => KeyUsage::Hmac,
        }
    }

    fn registry_usage(self) -> ObjectUsage {
        match self {
            Self::Sign => ObjectUsage::Sign,
            Self::Ecdh => ObjectUsage::Ecdh,
            Self::Hmac => ObjectUsage::Hmac,
        }
    }
}

/// Planned key generation operation after request normalization.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenPlan {
    /// Intended usage for the generated key.
    pub usage: KeygenUsage,
    /// Selector where the key will be addressable.
    pub selector: ObjectSelector,
    /// Optional persistent handle destination.
    pub persistent_handle: Option<PersistentHandle>,
    /// Whether replacement is allowed.
    pub force: bool,
    /// TPM public template selected for the key.
    pub template: KeyTemplate,
}

/// TPM public templates used by key generation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyTemplate {
    /// Unrestricted P-256 signing key template.
    EccP256Sign,
    /// Unrestricted P-256 ECDH key template.
    EccP256Ecdh,
    /// Keyed-hash HMAC-SHA256 key template.
    KeyedHashHmac,
}

impl KeyTemplate {
    fn template_name(self) -> &'static str {
        match self {
            Self::EccP256Sign => "ecc-p256-sign",
            Self::EccP256Ecdh => "ecc-p256-ecdh",
            Self::KeyedHashHmac => "keyed-hash-hmac-sha256",
        }
    }
}

impl KeygenRequest {
    /// Build a normalized generation plan without touching the TPM.
    pub fn plan(&self) -> Result<KeygenPlan> {
        Ok(KeygenPlan {
            usage: self.usage,
            selector: ObjectSelector::Id(self.id.clone()),
            persistent_handle: self.persist_at,
            force: self.force,
            template: template_for_usage(self.usage),
        })
    }

    /// Execute key generation using the default store and command context.
    pub fn execute(&self) -> Result<KeygenResult> {
        let store = Store::resolve::<&std::path::Path>(None)?;
        self.execute_with_store(&store)
    }

    /// Execute key generation using an explicit store.
    pub fn execute_with_store(&self, store: &Store) -> Result<KeygenResult> {
        self.execute_with_store_and_context(store, &CommandContext::default())
    }

    /// Execute key generation using a command context and its resolved store.
    pub fn execute_with_context(&self, command: &CommandContext) -> Result<KeygenResult> {
        let store = Store::resolve(command.store.root.as_deref())?;
        self.execute_with_store_and_context(&store, command)
    }

    /// Execute key generation with explicit store and command context.
    pub fn execute_with_store_and_context(
        &self,
        store: &Store,
        command: &CommandContext,
    ) -> Result<KeygenResult> {
        let plan = self.plan()?;
        reject_duplicate_id(store, &self.id, self.force)?;

        let mut context = tpm::create_context_for(command)?;
        if let Some(handle) = plan.persistent_handle {
            reject_occupied_persistent_handle(&mut context, handle, self.force)?;
        }

        let parent = tpm::create_owner_storage_parent(&mut context)?;
        let child_public_template = public_template_for_usage(self.usage)?;
        let child = tpm::create_child_key(&mut context, parent, child_public_template)?;
        let child_handle = tpm::load_created_child_key(&mut context, parent, &child)?;

        if let Some(handle) = plan.persistent_handle {
            tpm::persist_object(&mut context, ObjectHandle::from(child_handle), handle)?;
        }

        let public_key = ecc_public_key_from_tpm_public(&child.public)?;
        let entry = stored_key_entry(self, &plan, &child, public_key.as_ref())?;
        store.save_key(&entry, self.force)?;

        Ok(KeygenResult {
            id: self.id.clone(),
            usage: self.usage,
            persistent_handle: plan.persistent_handle,
        })
    }
}

/// Result metadata for a successfully generated key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenResult {
    /// Registry ID where the key was stored.
    pub id: RegistryId,
    /// Usage selected for the generated key.
    pub usage: KeygenUsage,
    /// Persistent handle used for the key, if requested.
    pub persistent_handle: Option<PersistentHandle>,
}

fn template_for_usage(usage: KeygenUsage) -> KeyTemplate {
    match usage {
        KeygenUsage::Sign => KeyTemplate::EccP256Sign,
        KeygenUsage::Ecdh => KeyTemplate::EccP256Ecdh,
        KeygenUsage::Hmac => KeyTemplate::KeyedHashHmac,
    }
}

fn public_template_for_usage(usage: KeygenUsage) -> Result<Public> {
    match usage {
        KeygenUsage::Sign => ecc_p256_sign_template(),
        KeygenUsage::Ecdh => ecc_p256_ecdh_template(),
        KeygenUsage::Hmac => keyed_hash_hmac_template(),
    }
}

fn ecc_p256_sign_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .map_err(|source| CoreError::tpm("build ECC signing attributes", source))?;

    let parameters = PublicEccParameters::new(
        SymmetricDefinitionObject::Null,
        EccScheme::Null,
        TpmEccCurve::NistP256,
        KeyDerivationFunctionScheme::Null,
    );

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|source| CoreError::tpm("build ECC signing public template", source))
}

fn ecc_p256_ecdh_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(false)
        .build()
        .map_err(|source| CoreError::tpm("build ECC ECDH attributes", source))?;

    let parameters = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(TpmEccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(|source| CoreError::tpm("build ECC ECDH parameters", source))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|source| CoreError::tpm("build ECC ECDH public template", source))
}

fn keyed_hash_hmac_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .map_err(|source| CoreError::tpm("build HMAC attributes", source))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Hmac {
            hmac_scheme: HmacScheme::new(HashingAlgorithm::Sha256),
        }))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|source| CoreError::tpm("build HMAC public template", source))
}

fn reject_duplicate_id(store: &Store, id: &RegistryId, force: bool) -> Result<()> {
    if !force && store.exists(RegistryCollection::Keys, id) {
        Err(CoreError::AlreadyExists(
            store.path_for(RegistryCollection::Keys, id),
        ))
    } else {
        Ok(())
    }
}

fn reject_occupied_persistent_handle(
    context: &mut Context,
    handle: PersistentHandle,
    force: bool,
) -> Result<()> {
    match tpm::load_persistent_object(context, handle) {
        Ok(existing) if force => {
            tpm::evict_persistent_object(context, existing, handle)?;
            Ok(())
        }
        Ok(_) => Err(CoreError::AlreadyExists(std::path::PathBuf::from(
            handle.to_string(),
        ))),
        Err(CoreError::Tpm { source, .. })
            if tpm_error_kind(source) == Some(Tss2ResponseCodeKind::Handle) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn tpm_error_kind(error: tss_esapi::Error) -> Option<Tss2ResponseCodeKind> {
    match error {
        tss_esapi::Error::Tss2Error(code) => code.kind(),
        tss_esapi::Error::WrapperError(_) => None,
    }
}

fn stored_key_entry(
    request: &KeygenRequest,
    plan: &KeygenPlan,
    child: &tpm::CreatedChildKey,
    public_key: Option<&EccPublicKey>,
) -> Result<StoredObjectEntry> {
    let mut metadata = RegistryRecord::new(
        &request.id,
        StoredObjectKind::Key,
        request.usage.registry_usage(),
    );
    metadata.handle = plan.persistent_handle.map(|handle| handle.to_string());
    metadata.persistent = plan.persistent_handle.is_some();
    metadata.curve = public_key.map(|_| "nistp256".to_owned());
    metadata.hash = Some("sha256".to_owned());
    metadata.parent = Some(ParentRecord {
        hierarchy: "owner".to_owned(),
        template: tpm::OWNER_STORAGE_PARENT_TEMPLATE.to_owned(),
    });
    metadata.template = Some(plan.template.template_name().to_owned());
    metadata.public_key = public_key.map(|key| hex::encode(key.sec1()));

    let public_pem = public_key
        .map(|key| encode_public_key(key, PublicKeyFormat::Pem, None))
        .transpose()?;

    Ok(StoredObjectEntry {
        record: metadata,
        public_blob: tpm::marshal_public(&child.public)?,
        private_blob: tpm::marshal_private(&child.private)?,
        public_pem,
    })
}

fn ecc_public_key_from_tpm_public(public: &Public) -> Result<Option<EccPublicKey>> {
    let Public::Ecc { unique, .. } = public else {
        return Ok(None);
    };

    let x = unique.x().value();
    let y = unique.y().value();
    if x.is_empty() || y.is_empty() {
        return Ok(None);
    }

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    push_fixed_32(&mut sec1, x, "x")?;
    push_fixed_32(&mut sec1, y, "y")?;
    EccPublicKey::p256_sec1(sec1).map(Some)
}

fn push_fixed_32(out: &mut Vec<u8>, value: &[u8], coordinate: &'static str) -> Result<()> {
    if value.len() > 32 {
        return Err(CoreError::invalid(
            "public_key",
            format!("P-256 {coordinate} coordinate is {} bytes", value.len()),
        ));
    }
    out.extend(std::iter::repeat_n(0, 32 - value.len()));
    out.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
#[path = "mod.test.rs"]
mod keygen_tests;
