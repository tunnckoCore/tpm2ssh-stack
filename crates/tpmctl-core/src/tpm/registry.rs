use crate::{
    CoreError, EccCurve, EccPublicKey, Error, HashAlgorithm, ObjectDescriptor, ObjectSelector,
    Result,
    store::{ObjectUsage, RegistryCollection, RegistryId, StoredObjectEntry},
};

use tss_esapi::{
    interface_types::ecc::EccCurve as TpmEccCurve,
    structures::{EccParameter, EccPoint, Public},
};

use super::{KeyUsage, PersistentHandle, unmarshal_public};

fn ecc_public_key_from_public(public: &Public) -> Result<EccPublicKey> {
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

/// Build an object descriptor from TPM public-area metadata.
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

pub(super) fn registry_entry_handle(entry: &StoredObjectEntry) -> Result<Option<PersistentHandle>> {
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

pub(super) fn usage_from_public(public: &Public) -> Result<KeyUsage> {
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

pub(crate) fn ecc_point_from_public_key(public_key: &EccPublicKey) -> Result<EccPoint> {
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

fn pad_coordinate(value: &[u8], field: &'static str) -> Result<[u8; 32]> {
    let mut out = [0_u8; 32];
    left_pad_copy(value, &mut out, field)?;
    Ok(out)
}

pub(super) fn left_pad_copy(value: &[u8], out: &mut [u8], field: &'static str) -> Result<()> {
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

impl ObjectDescriptor {
    pub(super) fn with_public_from_tpm(mut self, public: Public) -> Result<Self> {
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

pub(in crate::tpm) fn descriptor_from_registry_entry(
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

/// Build an object descriptor directly from a TPM public area.
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

#[cfg(test)]
mod tests {
    use super::super::object::owner_storage_parent_template;
    use super::*;
    use crate::store::{ObjectUsage, RegistryId, RegistryRecord, StoredObjectKind};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{algorithm::PublicAlgorithm, ecc::EccCurve as TpmEccCurve},
        structures::{
            Digest, EccPoint, KeyDerivationFunctionScheme, PublicBuilder, PublicEccParameters,
            PublicKeyedHashParameters,
        },
    };

    fn registry_entry() -> StoredObjectEntry {
        let id = RegistryId::new("test/key").unwrap();
        StoredObjectEntry {
            record: RegistryRecord::new(&id, StoredObjectKind::Key, ObjectUsage::Sign),
            public_blob: Vec::new(),
            private_blob: zeroize::Zeroizing::new(Vec::new()),
            public_pem: None,
        }
    }

    fn hmac_public() -> Public {
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .unwrap();
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
            )
            .with_object_attributes(attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                tss_esapi::structures::KeyedHashScheme::Hmac {
                    hmac_scheme: tss_esapi::structures::HashScheme::new(
                        tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                    )
                    .into(),
                },
            ))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .unwrap()
    }

    fn ecc_public(curve: TpmEccCurve, sign_encrypt: bool, decrypt: bool) -> Public {
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(decrypt)
            .with_sign_encrypt(sign_encrypt)
            .with_restricted(false)
            .build()
            .unwrap();

        let parameters = PublicEccParameters::new(
            tss_esapi::structures::SymmetricDefinitionObject::Null,
            tss_esapi::structures::EccScheme::Null,
            curve,
            KeyDerivationFunctionScheme::Null,
        );

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
            )
            .with_object_attributes(attributes)
            .with_ecc_parameters(parameters)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .unwrap()
    }

    #[test]
    fn descriptor_from_tpm_public_rejects_non_p256_ecc_objects() {
        let error = descriptor_from_tpm_public(
            ObjectSelector::Id(RegistryId::new("test/key").unwrap()),
            ecc_public(TpmEccCurve::NistP384, true, false),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("expected NIST P-256"));
    }

    #[test]
    fn descriptor_from_tpm_public_rejects_unsupported_rsa_object() {
        let error = descriptor_from_tpm_public(
            ObjectSelector::Id(RegistryId::new("test/key").unwrap()),
            owner_storage_parent_template().unwrap(),
        )
        .unwrap_err()
        .to_string();

        assert_eq!(
            error,
            "invalid usage: unable to infer supported key usage from TPM public area"
        );
    }

    #[test]
    fn descriptor_from_entry_rejects_unsupported_curve_hash_and_cached_public_key() {
        let mut entry = registry_entry();
        entry.record.curve = Some("p384".to_owned());
        let curve_error = descriptor_from_entry(
            ObjectSelector::Id(RegistryId::new("test/key").unwrap()),
            &entry,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(curve_error, "invalid curve: unsupported curve \"p384\"");

        let mut entry = registry_entry();
        entry.record.hash = Some("sha1".to_owned());
        let hash_error = descriptor_from_entry(
            ObjectSelector::Id(RegistryId::new("test/key").unwrap()),
            &entry,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(hash_error, "invalid hash: unsupported hash \"sha1\"");

        let mut entry = registry_entry();
        entry.record.public_key = Some("hex:not-hex".to_owned());
        let public_key_error = descriptor_from_entry(
            ObjectSelector::Id(RegistryId::new("test/key").unwrap()),
            &entry,
        )
        .unwrap_err()
        .to_string();
        assert!(public_key_error.starts_with("invalid public_key:"));
    }

    #[test]
    fn descriptor_from_public_rejects_ecc_and_rsa_objects() {
        let selector = ObjectSelector::Id(RegistryId::new("test/key").unwrap());

        let ecc_public = ecc_public(TpmEccCurve::NistP256, true, false);
        let ecc_error = descriptor_from_public(selector.clone(), &ecc_public)
            .unwrap_err()
            .to_string();
        assert_eq!(
            ecc_error,
            "invalid usage: object is not a keyed-hash HMAC key or sealed data object"
        );

        let rsa_error = descriptor_from_public(selector, &owner_storage_parent_template().unwrap())
            .unwrap_err()
            .to_string();
        assert_eq!(
            rsa_error,
            "invalid usage: object is not a keyed-hash HMAC key or sealed data object"
        );
    }

    #[test]
    fn descriptor_from_public_maps_hmac_and_sealed_keyed_hash_objects() {
        let selector = ObjectSelector::Id(RegistryId::new("test/key").unwrap());
        let hmac = descriptor_from_public(selector.clone(), &hmac_public()).unwrap();
        assert_eq!(hmac.usage, KeyUsage::Hmac);

        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .build()
            .unwrap();
        let sealed_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
            )
            .with_object_attributes(attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                tss_esapi::structures::KeyedHashScheme::Null,
            ))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .unwrap();
        let sealed = descriptor_from_public(selector, &sealed_public).unwrap();
        assert_eq!(sealed.usage, KeyUsage::Sealed);
    }

    #[test]
    fn left_pad_copy_rejects_oversized_coordinate() {
        let mut out = [0_u8; 32];
        let error = left_pad_copy(&[7_u8; 33], &mut out, "coordinate")
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "invalid coordinate: expected at most 32 bytes, got 33"
        );
    }

    #[test]
    fn registry_entry_handle_handles_non_persistent_missing_and_invalid_handle() {
        let mut entry = registry_entry();
        assert_eq!(registry_entry_handle(&entry).unwrap(), None);

        entry.record.persistent = true;
        assert_eq!(registry_entry_handle(&entry).unwrap(), None);

        entry.record.handle = Some("0x81010010".to_owned());
        assert_eq!(
            registry_entry_handle(&entry).unwrap().unwrap(),
            PersistentHandle::parse("0x81010010").unwrap()
        );

        entry.record.handle = Some("not-a-handle".to_owned());
        assert!(
            registry_entry_handle(&entry)
                .unwrap_err()
                .to_string()
                .contains("invalid persistent TPM handle")
        );
    }

    #[test]
    fn descriptor_from_registry_entry_validates_kind_and_curve_aliases() {
        let id = RegistryId::new("test/key").unwrap();
        let mut entry = registry_entry();
        entry.record.curve = Some("nistp256".to_owned());
        let descriptor =
            descriptor_from_registry_entry(RegistryCollection::Keys, &id, &entry).unwrap();
        assert_eq!(descriptor.usage, KeyUsage::Sign);
        assert_eq!(descriptor.curve, Some(EccCurve::P256));

        entry.record.kind = StoredObjectKind::Sealed;
        let error = descriptor_from_registry_entry(RegistryCollection::Keys, &id, &entry)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "invalid kind: registry entry test/key is Sealed, expected Key"
        );
    }

    #[test]
    fn usage_and_public_updates_cover_ecdh_and_usage_mismatch() {
        let selector = ObjectSelector::Id(RegistryId::new("test/key").unwrap());
        let ecdh_public = ecc_public(TpmEccCurve::NistP256, false, true);
        assert_eq!(usage_from_public(&ecdh_public).unwrap(), KeyUsage::Ecdh);

        let descriptor = ObjectDescriptor {
            selector,
            usage: KeyUsage::Sign,
            curve: None,
            hash: None,
            public_key: None,
        };
        let error = descriptor
            .with_public_from_tpm(ecdh_public)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "invalid usage: registry says sign but persistent handle contains ecdh object"
        );
    }

    #[test]
    fn with_public_from_tpm_attaches_public_key_for_sign_objects() {
        let selector = ObjectSelector::Id(RegistryId::new("test/key").unwrap());
        let secret = p256::SecretKey::from_slice(&[7_u8; 32]).unwrap();
        let encoded = secret.public_key().to_encoded_point(false);
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
            )
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_decrypt(false)
                    .with_sign_encrypt(true)
                    .with_restricted(false)
                    .build()
                    .unwrap(),
            )
            .with_ecc_parameters(PublicEccParameters::new(
                tss_esapi::structures::SymmetricDefinitionObject::Null,
                tss_esapi::structures::EccScheme::Null,
                TpmEccCurve::NistP256,
                KeyDerivationFunctionScheme::Null,
            ))
            .with_ecc_unique_identifier(EccPoint::new(
                tss_esapi::structures::EccParameter::try_from(encoded.x().unwrap().to_vec())
                    .unwrap(),
                tss_esapi::structures::EccParameter::try_from(encoded.y().unwrap().to_vec())
                    .unwrap(),
            ))
            .build()
            .unwrap();

        let descriptor = ObjectDescriptor {
            selector,
            usage: KeyUsage::Sign,
            curve: None,
            hash: None,
            public_key: None,
        }
        .with_public_from_tpm(public)
        .unwrap();

        assert_eq!(descriptor.curve, None);
        assert_eq!(descriptor.public_key.unwrap().sec1(), encoded.as_bytes());
    }
}
