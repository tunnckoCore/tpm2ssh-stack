use super::support::*;
use tpmctl_core::{seal::SealRequest, store::STORE_ENV};

#[test]
fn simulator_native_seal_and_unseal_execute_use_default_context_and_store_env() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let previous_store_env = env::var(STORE_ENV).ok();
    unsafe {
        env::set_var(STORE_ENV, temp_store.path());
    }

    let sealed_id = RegistryId::new("sim/native/seal/default-context-roundtrip").unwrap();
    let expected = Zeroizing::new(b"default context seal bytes".to_vec());

    let seal_result = SealRequest {
        selector: ObjectSelector::Id(sealed_id.clone()),
        input: expected.clone(),
        force: false,
    }
    .execute();

    match previous_store_env {
        Some(previous) => unsafe { env::set_var(STORE_ENV, previous) },
        None => unsafe { env::remove_var(STORE_ENV) },
    }

    let seal_result = seal_result.unwrap();
    assert_eq!(seal_result.selector, ObjectSelector::Id(sealed_id.clone()));
    assert_eq!(seal_result.hash, None);

    let previous_store_env = env::var(STORE_ENV).ok();
    unsafe {
        env::set_var(STORE_ENV, temp_store.path());
    }

    let unsealed = UnsealRequest {
        selector: ObjectSelector::Id(sealed_id),
        force_binary_stdout: false,
    }
    .execute();

    match previous_store_env {
        Some(previous) => unsafe { env::set_var(STORE_ENV, previous) },
        None => unsafe { env::remove_var(STORE_ENV) },
    }

    let unsealed = unsealed.unwrap();
    assert_eq!(unsealed.as_slice(), expected.as_slice());
}

#[test]
fn simulator_native_seal_rejects_invalid_tcti_before_tpm_create() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let error = SealRequest {
        selector: ObjectSelector::Id(RegistryId::new("sim/native/seal/invalid-tcti").unwrap()),
        input: Zeroizing::new(b"invalid tcti seal bytes".to_vec()),
        force: false,
    }
    .execute_with_context(&CommandContext {
        store: StoreOptions::default(),
        tcti: Some("not-a-valid-tcti".to_string()),
    })
    .unwrap_err();
    assert!(matches!(error, tpmctl_core::Error::Tcti(_)));
}

#[test]
fn simulator_native_unseal_rejects_invalid_tcti_before_lookup() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let error = UnsealRequest {
        selector: ObjectSelector::Id(RegistryId::new("sim/native/unseal/invalid-tcti").unwrap()),
        force_binary_stdout: false,
    }
    .execute_with_context(&CommandContext {
        store: StoreOptions::default(),
        tcti: Some("not-a-valid-tcti".to_string()),
    })
    .unwrap_err();
    assert!(matches!(error, tpmctl_core::Error::Tcti(_)));
}
