use super::*;
use std::{
    collections::hash_map::DefaultHasher,
    env,
    hash::{Hash, Hasher},
    sync::{Mutex, OnceLock},
};

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

#[test]
fn handle_new_round_trips_display_hash_and_conversions() {
    let handle = PersistentHandle::new(0x8101_0010).unwrap();
    assert_eq!(handle.to_string(), "0x81010010");
    assert_eq!(
        handle.tpm_handle(),
        tss_esapi::handles::TpmHandle::try_from(0x8101_0010).unwrap()
    );
    assert_eq!(
        handle.persistent_tpm_handle(),
        tss_esapi::handles::PersistentTpmHandle::new(0x8101_0010).unwrap()
    );

    let mut left = DefaultHasher::new();
    handle.hash(&mut left);
    let mut right = DefaultHasher::new();
    PersistentHandle::parse("0x81010010")
        .unwrap()
        .hash(&mut right);
    assert_eq!(left.finish(), right.finish());
}

#[test]
fn handle_reports_specific_parse_errors() {
    assert_eq!(
        PersistentHandle::parse(" 0x81010010")
            .unwrap_err()
            .to_string(),
        "invalid persistent TPM handle \" 0x81010010\": leading or trailing whitespace is not allowed"
    );
    assert_eq!(
        PersistentHandle::parse("81010010").unwrap_err().to_string(),
        "invalid persistent TPM handle \"81010010\": persistent handles must be hexadecimal and start with 0x"
    );
    assert_eq!(
        PersistentHandle::parse("0xzzzzzzzz")
            .unwrap_err()
            .to_string(),
        "invalid persistent TPM handle \"0xzzzzzzzz\": handle contains non-hexadecimal characters"
    );
}
