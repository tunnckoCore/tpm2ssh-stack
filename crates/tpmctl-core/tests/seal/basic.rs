use super::support::*;
use tpmctl_core::store::{ObjectUsage, StoredObjectKind};

#[test]
fn simulator_seal_rejects_existing_registry_target_without_overwrite_and_preserves_original() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let sealed_id = RegistryId::new("sim/negative/sealed-duplicate").unwrap();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"first sealed secret".to_vec()),
            overwrite: true,
        },
    )
    .unwrap();

    let store = Store::new(temp_store.path());
    let original_entry = store.load_sealed(&sealed_id).unwrap();
    assert_eq!(original_entry.record.kind, StoredObjectKind::Sealed);
    assert_eq!(original_entry.record.usage, ObjectUsage::Sealed);
    assert_eq!(original_entry.record.hash, None);
    assert_eq!(
        original_entry.record.template.as_deref(),
        Some("keyedhash-sealed-null-sha256")
    );
    let parent = original_entry
        .record
        .parent
        .as_ref()
        .expect("sealed registry entry should record its parent metadata");
    assert_eq!(parent.hierarchy, "owner");
    assert_eq!(
        parent.template,
        "rsa2048-restricted-decrypt-aes128cfb-sha256"
    );
    assert!(!original_entry.public_blob.is_empty());
    assert!(!original_entry.private_blob.is_empty());
    assert!(original_entry.public_pem.is_none());

    let duplicate = api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"second sealed secret".to_vec()),
            overwrite: false,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(duplicate.contains("already exists"));

    let preserved_entry = store.load_sealed(&sealed_id).unwrap();
    assert_eq!(preserved_entry, original_entry);

    let unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), b"first sealed secret");
}

#[test]
fn simulator_api_seal_then_unseal_roundtrips_exact_bytes() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let sealed_id = RegistryId::new("sim/api/seal-roundtrip/exact-bytes").unwrap();
    let expected = Zeroizing::new(vec![0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, b's', b'e', 0x00]);

    let sealed = api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: expected.clone(),
            overwrite: false,
        },
    )
    .unwrap();
    assert_eq!(sealed.selector, ObjectSelector::Id(sealed_id.clone()));
    assert_eq!(sealed.hash, None);

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let unsealed = api::unseal(
        &reloaded_context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), expected.as_slice());
}

#[test]
fn simulator_api_seal_overwrite_replaces_unsealed_value() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let sealed_id = RegistryId::new("sim/api/seal-overwrite/replaced-value").unwrap();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"first sealed bytes".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();
    let first_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id.clone()),
        },
    )
    .unwrap();
    assert_eq!(first_unsealed.as_slice(), b"first sealed bytes");

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"second sealed bytes".to_vec()),
            overwrite: true,
        },
    )
    .unwrap();
    let replaced_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(replaced_unsealed.as_slice(), b"second sealed bytes");
    assert_ne!(replaced_unsealed.as_slice(), first_unsealed.as_slice());
}
