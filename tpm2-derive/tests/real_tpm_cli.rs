mod support;

use std::ffi::OsString;
use std::fs;

use serde_json::Value;
use support::{RealTpmHarness, os_arg};

#[test]
fn inspect_smoke_reports_real_swtpm_capabilities() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");

    let output = harness.run_cli_json([
        OsString::from("inspect"),
        OsString::from("--algorithm"),
        OsString::from("p256"),
        OsString::from("--use"),
        OsString::from("sign"),
        OsString::from("--use"),
        OsString::from("verify"),
    ]);
    let result = output.assert_ok();

    assert_eq!(result["tpm"]["present"], Value::Bool(true));
    assert_eq!(result["tpm"]["accessible"], Value::Bool(true));
    assert_eq!(result["prf_available"], Value::Bool(true));
    assert_eq!(result["seed_available"], Value::Bool(true));
    assert_eq!(
        result["recommended_mode"],
        Value::String("native".to_string())
    );

    let algorithms = result["native"]["algorithms"]
        .as_array()
        .expect("native algorithms array");
    let p256 = algorithms
        .iter()
        .find(|entry| entry["algorithm"] == Value::String("p256".to_string()))
        .expect("p256 capability entry");
    assert_eq!(p256["sign"], Value::Bool(true));
    assert_eq!(p256["verify"], Value::Bool(true));
}

#[test]
fn native_identity_sign_verify_round_trip_uses_real_tpm_commands() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");
    let message_path = harness.workspace_path("native-message.bin");
    let signature_path = harness.workspace_path("native-message.sig");
    fs::write(&message_path, b"native integration message\n").expect("write native input");

    let create = harness.run_cli_json([
        OsString::from("identity"),
        OsString::from("native-smoke"),
        OsString::from("--mode"),
        OsString::from("native"),
        OsString::from("--algorithm"),
        OsString::from("p256"),
        OsString::from("--use"),
        OsString::from("sign"),
        OsString::from("--use"),
        OsString::from("verify"),
        OsString::from("--state-dir"),
        os_arg(harness.state_dir()),
    ]);
    let create_result = create.assert_ok();
    assert_eq!(create_result["persisted"], Value::Bool(true));
    assert_eq!(
        create_result["identity"]["mode"]["resolved"],
        Value::String("native".to_string())
    );

    let sign = harness.run_cli_json([
        OsString::from("sign"),
        OsString::from("--with"),
        OsString::from("native-smoke"),
        OsString::from("--input"),
        os_arg(&message_path),
        OsString::from("--format"),
        OsString::from("der"),
        OsString::from("--output"),
        os_arg(&signature_path),
        OsString::from("--state-dir"),
        os_arg(harness.state_dir()),
    ]);
    let sign_result = sign.assert_ok();
    assert_eq!(sign_result["mode"], Value::String("native".to_string()));
    assert_eq!(sign_result["state"], Value::String("executed".to_string()));
    assert_eq!(
        sign_result["signature_format"],
        Value::String("der".to_string())
    );
    let signature_len = fs::read(&signature_path)
        .expect("read native signature")
        .len();
    assert!(
        signature_len > 60,
        "expected DER signature bytes, got {signature_len}"
    );

    let verify = harness.run_cli_json([
        OsString::from("verify"),
        OsString::from("--with"),
        OsString::from("native-smoke"),
        OsString::from("--input"),
        os_arg(&message_path),
        OsString::from("--signature"),
        os_arg(&signature_path),
        OsString::from("--format"),
        OsString::from("der"),
        OsString::from("--state-dir"),
        os_arg(harness.state_dir()),
    ]);
    let verify_result = verify.assert_ok();
    assert_eq!(verify_result["mode"], Value::String("native".to_string()));
    assert_eq!(verify_result["verified"], Value::Bool(true));
    assert_eq!(
        verify_result["signature_input_format"],
        Value::String("der".to_string())
    );
}

#[test]
fn seed_identity_sign_verify_round_trip_uses_real_tpm_commands() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");
    let message_path = harness.workspace_path("seed-message.bin");
    let signature_path = harness.workspace_path("seed-message.sig");
    fs::write(&message_path, b"seed integration message\n").expect("write seed input");

    let create = harness.run_cli_json([
        OsString::from("identity"),
        OsString::from("seed-smoke"),
        OsString::from("--mode"),
        OsString::from("seed"),
        OsString::from("--algorithm"),
        OsString::from("p256"),
        OsString::from("--use"),
        OsString::from("sign"),
        OsString::from("--use"),
        OsString::from("verify"),
        OsString::from("--state-dir"),
        os_arg(harness.state_dir()),
    ]);
    let create_result = create.assert_ok();
    assert_eq!(create_result["persisted"], Value::Bool(true));
    assert_eq!(
        create_result["identity"]["mode"]["resolved"],
        Value::String("seed".to_string())
    );

    let sign = harness.run_cli_json([
        OsString::from("sign"),
        OsString::from("--with"),
        OsString::from("seed-smoke"),
        OsString::from("--input"),
        os_arg(&message_path),
        OsString::from("--format"),
        OsString::from("der"),
        OsString::from("--output"),
        os_arg(&signature_path),
        OsString::from("--state-dir"),
        os_arg(harness.state_dir()),
    ]);
    let sign_result = sign.assert_ok();
    assert_eq!(sign_result["mode"], Value::String("seed".to_string()));
    assert_eq!(
        sign_result["signature_format"],
        Value::String("der".to_string())
    );
    let signature_len = fs::read(&signature_path)
        .expect("read seed signature")
        .len();
    assert!(
        signature_len > 60,
        "expected DER signature bytes, got {signature_len}"
    );

    let verify = harness.run_cli_json([
        OsString::from("verify"),
        OsString::from("--with"),
        OsString::from("seed-smoke"),
        OsString::from("--input"),
        os_arg(&message_path),
        OsString::from("--signature"),
        os_arg(&signature_path),
        OsString::from("--format"),
        OsString::from("der"),
        OsString::from("--state-dir"),
        os_arg(harness.state_dir()),
    ]);
    let verify_result = verify.assert_ok();
    assert_eq!(verify_result["mode"], Value::String("seed".to_string()));
    assert_eq!(verify_result["verified"], Value::Bool(true));
    assert_eq!(
        verify_result["signature_input_format"],
        Value::String("der".to_string())
    );
}
