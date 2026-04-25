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
    assert_eq!(parameters.ecc_scheme(), EccScheme::Null);

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
    let metadata = RegistryRecord::new(&id, StoredObjectKind::Key, ObjectUsage::Sign);
    let entry = StoredObjectEntry {
        record: metadata,
        public_blob: b"public".to_vec(),
        private_blob: zeroize::Zeroizing::new(b"private".to_vec()),
        public_pem: None,
    };
    store.save_key(&entry, false).unwrap();

    let error = request.execute_with_store(&store).unwrap_err();
    assert!(matches!(error, CoreError::AlreadyExists(_)));

    reject_duplicate_id(&store, &id, true).unwrap();
}

#[test]
fn stored_entry_contains_blobs_registry_record_and_cached_public_key() {
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

    assert_eq!(entry.record.id, "org/acme/alice/main");
    assert_eq!(entry.record.handle.as_deref(), Some("0x81010010"));
    assert!(entry.record.persistent);
    assert_eq!(entry.record.public_key.as_ref().unwrap().len(), 130);
    assert!(!entry.public_blob.is_empty());
    assert_eq!(entry.private_blob.as_slice(), &[0xaa; 8]);
    assert!(entry.public_pem.is_some());
}
