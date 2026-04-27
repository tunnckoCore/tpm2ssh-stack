use super::support::*;

#[test]
fn simulator_api_seal_handle_selector_and_overwrite_preserve_then_replace_unsealed_bytes() {
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
    let handle = PersistentHandle::new(0x8101_0049).unwrap();
    cleanup_persistent_handle(handle);

    let first = Zeroizing::new(vec![
        0x00, 0x10, 0x20, 0x30, b'h', b'a', b'n', b'd', b'l', b'e',
    ]);
    let first_result = api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Handle(handle),
            input: first.clone(),
            overwrite: false,
        },
    )
    .unwrap();
    assert_eq!(first_result.selector, ObjectSelector::Handle(handle));
    assert_eq!(first_result.hash, None);
    assert!(
        !temp_store.path().join("sealed").exists(),
        "sealing to a persistent handle should not create registry-backed sealed entries"
    );

    let first_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Handle(handle),
        },
    )
    .unwrap();
    assert_eq!(first_unsealed.as_slice(), first.as_slice());

    let duplicate_error = api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Handle(handle),
            input: Zeroizing::new(b"second handle sealed bytes".to_vec()),
            overwrite: false,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(duplicate_error.contains("already exists"));

    let preserved_unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Handle(handle),
        },
    )
    .unwrap();
    assert_eq!(preserved_unsealed.as_slice(), first.as_slice());

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Handle(handle),
            input: Zeroizing::new(b"replacement handle sealed bytes".to_vec()),
            overwrite: true,
        },
    )
    .unwrap();

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let replaced_unsealed = api::unseal(
        &reloaded_context,
        UnsealParams {
            material: ObjectSelector::Handle(handle),
        },
    )
    .unwrap();
    assert_eq!(
        replaced_unsealed.as_slice(),
        b"replacement handle sealed bytes"
    );
    assert_ne!(replaced_unsealed.as_slice(), first.as_slice());
    assert!(
        !temp_store.path().join("sealed").exists(),
        "overwriting a persistent sealed handle should not create registry-backed sealed entries"
    );

    cleanup_persistent_handle(handle);
}
