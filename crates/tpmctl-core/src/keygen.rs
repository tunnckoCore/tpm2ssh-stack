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
        KeyedHashScheme, Public, PublicBuilder, PublicEccParametersBuilder,
        PublicKeyedHashParameters,
    },
};

use crate::{
    CoreError, EccPublicKey, KeyUsage, ObjectSelector, PersistentHandle, RegistryId, Result,
    output::{PublicKeyFormat, encode_public_key},
    store::{
        ObjectUsage, ParentMetadata, RegistryCollection, RegistryMetadata, Store,
        StoredObjectEntry, StoredObjectKind,
    },
    tpm,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenRequest {
    pub usage: KeygenUsage,
    pub id: RegistryId,
    pub persist_at: Option<PersistentHandle>,
    pub force: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeygenUsage {
    Sign,
    Ecdh,
    Hmac,
}

impl KeygenUsage {
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenPlan {
    pub usage: KeygenUsage,
    pub selector: ObjectSelector,
    pub persistent_handle: Option<PersistentHandle>,
    pub force: bool,
    pub template: KeyTemplate,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyTemplate {
    EccP256Sign,
    EccP256Ecdh,
    KeyedHashHmac,
}

impl KeyTemplate {
    fn metadata_name(self) -> &'static str {
        match self {
            Self::EccP256Sign => "ecc-p256-sign",
            Self::EccP256Ecdh => "ecc-p256-ecdh",
            Self::KeyedHashHmac => "keyed-hash-hmac-sha256",
        }
    }
}

impl KeygenRequest {
    pub fn plan(&self) -> Result<KeygenPlan> {
        Ok(KeygenPlan {
            usage: self.usage,
            selector: ObjectSelector::Id(self.id.clone()),
            persistent_handle: self.persist_at,
            force: self.force,
            template: template_for_usage(self.usage),
        })
    }

    pub fn execute(&self) -> Result<KeygenResult> {
        let store = Store::resolve::<&std::path::Path>(None)?;
        self.execute_with_store(&store)
    }

    pub fn execute_with_store(&self, store: &Store) -> Result<KeygenResult> {
        let plan = self.plan()?;
        reject_duplicate_id(store, &self.id, self.force)?;

        let mut context = tpm::create_context()?;
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenResult {
    pub id: RegistryId,
    pub usage: KeygenUsage,
    pub persistent_handle: Option<PersistentHandle>,
}

pub fn template_for_usage(usage: KeygenUsage) -> KeyTemplate {
    match usage {
        KeygenUsage::Sign => KeyTemplate::EccP256Sign,
        KeygenUsage::Ecdh => KeyTemplate::EccP256Ecdh,
        KeygenUsage::Hmac => KeyTemplate::KeyedHashHmac,
    }
}

pub fn public_template_for_usage(usage: KeygenUsage) -> Result<Public> {
    match usage {
        KeygenUsage::Sign => ecc_p256_sign_template(),
        KeygenUsage::Ecdh => ecc_p256_ecdh_template(),
        KeygenUsage::Hmac => keyed_hash_hmac_template(),
    }
}

pub fn ecc_p256_sign_template() -> Result<Public> {
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

    let parameters = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(TpmEccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(|source| CoreError::tpm("build ECC signing parameters", source))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|source| CoreError::tpm("build ECC signing public template", source))
}

pub fn ecc_p256_ecdh_template() -> Result<Public> {
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

pub fn keyed_hash_hmac_template() -> Result<Public> {
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
    let mut metadata = RegistryMetadata::new(
        &request.id,
        StoredObjectKind::Key,
        request.usage.registry_usage(),
    );
    metadata.handle = plan.persistent_handle.map(|handle| handle.to_string());
    metadata.persistent = plan.persistent_handle.is_some();
    metadata.curve = public_key.map(|_| "nistp256".to_owned());
    metadata.hash = Some("sha256".to_owned());
    metadata.parent = Some(ParentMetadata {
        hierarchy: "owner".to_owned(),
        template: tpm::OWNER_STORAGE_PARENT_TEMPLATE.to_owned(),
    });
    metadata.template = Some(plan.template.metadata_name().to_owned());
    metadata.public_key = public_key.map(|key| hex::encode(key.sec1()));

    let public_pem = public_key
        .map(|key| encode_public_key(key, PublicKeyFormat::Pem, None))
        .transpose()?;

    Ok(StoredObjectEntry {
        metadata,
        public_blob: tpm::marshal_public(&child.public)?,
        private_blob: tpm::marshal_private(&child.private)?,
        public_pem,
    })
}

pub fn ecc_public_key_from_tpm_public(public: &Public) -> Result<Option<EccPublicKey>> {
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
mod keygen_tests {
    use super::*;
    use tss_esapi::{
        interface_types::algorithm::EccSchemeAlgorithm,
        structures::{KeyedHashScheme, Public},
    };

    #[test]
    fn keygen_supports_sign_ecdh_and_hmac_usages() {
        assert_eq!(
            template_for_usage(KeygenUsage::Sign),
            KeyTemplate::EccP256Sign
        );
        assert_eq!(
            template_for_usage(KeygenUsage::Ecdh),
            KeyTemplate::EccP256Ecdh
        );
        assert_eq!(
            template_for_usage(KeygenUsage::Hmac),
            KeyTemplate::KeyedHashHmac
        );
    }

    #[test]
    fn template_selection_sets_expected_tpm_attributes() {
        let sign = public_template_for_usage(KeygenUsage::Sign).unwrap();
        let Public::Ecc {
            object_attributes,
            parameters,
            ..
        } = sign
        else {
            panic!("sign template must be ECC");
        };
        assert!(object_attributes.sign_encrypt());
        assert!(!object_attributes.decrypt());
        assert_eq!(
            parameters.ecc_scheme().algorithm(),
            EccSchemeAlgorithm::EcDsa
        );

        let ecdh = public_template_for_usage(KeygenUsage::Ecdh).unwrap();
        let Public::Ecc {
            object_attributes,
            parameters,
            ..
        } = ecdh
        else {
            panic!("ECDH template must be ECC");
        };
        assert!(!object_attributes.sign_encrypt());
        assert!(object_attributes.decrypt());
        assert_eq!(
            parameters.ecc_scheme().algorithm(),
            EccSchemeAlgorithm::EcDh
        );

        let hmac = public_template_for_usage(KeygenUsage::Hmac).unwrap();
        let Public::KeyedHash { parameters, .. } = hmac else {
            panic!("HMAC template must be keyed hash");
        };
        assert_eq!(
            parameters,
            PublicKeyedHashParameters::new(KeyedHashScheme::Hmac {
                hmac_scheme: HmacScheme::new(HashingAlgorithm::Sha256),
            })
        );
    }

    #[test]
    fn duplicate_id_rejected_unless_force_before_tpm_access() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path());
        let id = RegistryId::new("org/acme/alice/main").unwrap();
        let request = KeygenRequest {
            usage: KeygenUsage::Sign,
            id: id.clone(),
            persist_at: None,
            force: false,
        };
        let metadata = RegistryMetadata::new(&id, StoredObjectKind::Key, ObjectUsage::Sign);
        let entry = StoredObjectEntry {
            metadata,
            public_blob: b"public".to_vec(),
            private_blob: b"private".to_vec(),
            public_pem: None,
        };
        store.save_key(&entry, false).unwrap();

        let error = request.execute_with_store(&store).unwrap_err();
        assert!(matches!(error, CoreError::AlreadyExists(_)));

        reject_duplicate_id(&store, &id, true).unwrap();
    }

    #[test]
    fn stored_entry_contains_blobs_metadata_and_cached_public_key() {
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_sign_encrypt(true)
                    .build()
                    .unwrap(),
            )
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                    .with_curve(TpmEccCurve::NistP256)
                    .with_is_signing_key(true)
                    .with_is_decryption_key(false)
                    .with_restricted(false)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()
                    .unwrap(),
            )
            .with_ecc_unique_identifier(EccPoint::new(
                tss_esapi::structures::EccParameter::try_from(
                    hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                        .unwrap(),
                )
                .unwrap(),
                tss_esapi::structures::EccParameter::try_from(
                    hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
                        .unwrap(),
                )
                .unwrap(),
            ))
            .build()
            .unwrap();
        let private = tss_esapi::structures::Private::try_from(vec![0xaa; 8]).unwrap();
        let child = tpm::CreatedChildKey { public, private };
        let request = KeygenRequest {
            usage: KeygenUsage::Sign,
            id: RegistryId::new("org/acme/alice/main").unwrap(),
            persist_at: Some(PersistentHandle::new(0x8101_0010).unwrap()),
            force: false,
        };
        let plan = request.plan().unwrap();
        let public_key = ecc_public_key_from_tpm_public(&child.public).unwrap();

        let entry = stored_key_entry(&request, &plan, &child, public_key.as_ref()).unwrap();

        assert_eq!(entry.metadata.id, "org/acme/alice/main");
        assert_eq!(entry.metadata.handle.as_deref(), Some("0x81010010"));
        assert!(entry.metadata.persistent);
        assert_eq!(entry.metadata.public_key.as_ref().unwrap().len(), 130);
        assert!(!entry.public_blob.is_empty());
        assert_eq!(entry.private_blob, vec![0xaa; 8]);
        assert!(entry.public_pem.is_some());
    }

    #[test]
    fn simulator_keygen_smoke_is_gated_by_test_tcti() {
        if std::env::var("TEST_TCTI")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .is_none()
        {
            eprintln!("skipping simulator keygen smoke test: TEST_TCTI is not set");
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path());
        let request = KeygenRequest {
            usage: KeygenUsage::Sign,
            id: RegistryId::new("sim/keygen/sign").unwrap(),
            persist_at: None,
            force: false,
        };

        let result = request.execute_with_store(&store).unwrap();
        assert_eq!(result.usage, KeygenUsage::Sign);
        assert!(store.exists(RegistryCollection::Keys, &request.id));
    }
}
