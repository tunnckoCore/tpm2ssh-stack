mod support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use support::{RealTpmHarness, hex_decode, hex_encode, normalize_openssh_public_key};
use tpm2_derive::backend::{ProcessCommandRunner, default_probe};
use tpm2_derive::error::Error;
use tpm2_derive::model::{
    Algorithm, DerivationOverrides, ExportKind, Format, Identity, IdentityCreateRequest,
    InputFormat, InputSource, InspectRequest, Mode, ModePreference, SshAddRequest, UseCase,
    VerifyRequest,
};
use tpm2_derive::ops;
use tpm2_derive::ops::encrypt;
use tpm2_derive::ops::sign::{self, SignOperationResult};
use tpm2_derive::ops::ssh;
use tpm2_derive::ops::verify;

#[test]
fn inspect_reports_real_swtpm_capabilities_via_library_api() {
    let _harness = RealTpmHarness::start().expect("start swtpm harness");
    let probe = default_probe();

    let report = ops::inspect(
        &probe,
        &InspectRequest {
            algorithm: Some(Algorithm::P256),
            uses: vec![UseCase::Sign, UseCase::Verify],
        },
    );

    assert_eq!(report.tpm.present, Some(true));
    assert_eq!(report.tpm.accessible, Some(true));
    assert_eq!(report.prf_available, Some(true));
    assert_eq!(report.seed_available, Some(true));
    assert_eq!(report.recommended_mode, Some(Mode::Native));

    let p256 = report
        .native
        .for_algorithm(Algorithm::P256)
        .expect("p256 capability entry");
    assert!(p256.sign);
    assert!(p256.verify);
    assert!(!p256.encrypt);
    assert!(!p256.decrypt);
}

#[test]
fn native_identity_library_round_trip_covers_create_sign_verify_and_export() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");
    let identity = create_identity(
        &harness,
        "native-real",
        Algorithm::P256,
        ModePreference::Auto,
        vec![UseCase::Sign, UseCase::Verify],
        DerivationOverrides::default(),
    );
    assert_eq!(identity.mode.resolved, Mode::Native);

    let message_path = write_workspace_file(
        &harness,
        "native-message.bin",
        b"native integration message\n",
    );
    let signature_path = harness.workspace_path("native-message.sig");
    let public_key_path = harness.workspace_path("native-message.pub");

    let (sign_result, _diagnostics) = sign::execute_with_defaults(
        &identity,
        &tpm2_derive::model::SignRequest {
            identity: identity.name.clone(),
            input: path_input(&message_path),
            format: Format::Der,
            output: Some(signature_path.clone()),
        },
        &DerivationOverrides::default(),
    )
    .expect("native sign through library API");
    let SignOperationResult::Native(native_sign) = sign_result else {
        panic!("expected native sign result");
    };
    assert_eq!(native_sign.mode, Mode::Native);
    assert_eq!(native_sign.state, "executed");
    assert!(native_sign.signature_bytes.unwrap_or_default() > 60);
    assert!(signature_path.is_file());

    let (verify_result, _diagnostics) = verify::execute_with_defaults(
        &identity,
        &VerifyRequest {
            identity: identity.name.clone(),
            input: path_input(&message_path),
            signature: path_input(&signature_path),
            format: InputFormat::Der,
        },
        &DerivationOverrides::default(),
    )
    .expect("native verify through library API");
    assert_eq!(verify_result.mode, Mode::Native);
    assert!(verify_result.verified);

    let export_result = ops::export(&tpm2_derive::model::ExportRequest {
        identity: identity.name.clone(),
        kind: ExportKind::PublicKey,
        output: Some(public_key_path.clone()),
        format: Some(Format::Openssh),
        state_dir: Some(harness.state_dir().to_path_buf()),
        reason: None,
        confirm: false,
        derivation: DerivationOverrides::default(),
    })
    .expect("native public-key export");
    assert_eq!(export_result.mode, Mode::Native);
    assert_eq!(export_result.kind, ExportKind::PublicKey);

    let public_key = fs::read_to_string(&public_key_path).expect("read exported public key");
    assert!(public_key.starts_with("ecdsa-sha2-nistp256 "));
}

#[test]
fn seed_identity_library_round_trip_covers_encrypt_export_and_ssh_add() {
    let mut harness = RealTpmHarness::start().expect("start swtpm harness");
    let identity = create_identity(
        &harness,
        "seed-real",
        Algorithm::Ed25519,
        ModePreference::Seed,
        vec![
            UseCase::Sign,
            UseCase::Verify,
            UseCase::Encrypt,
            UseCase::Decrypt,
            UseCase::Ssh,
            UseCase::ExportSecret,
        ],
        DerivationOverrides {
            org: Some("com.example.tests".to_string()),
            purpose: Some("seed-default".to_string()),
            context: BTreeMap::from([("tenant".to_string(), "alpha".to_string())]),
        },
    );
    assert_eq!(identity.mode.resolved, Mode::Seed);

    let message_path =
        write_workspace_file(&harness, "seed-message.bin", b"seed integration message\n");
    let signature_path = harness.workspace_path("seed-message.sig.hex");
    let public_key_path = harness.workspace_path("seed-export.pub");
    let secret_key_path = harness.workspace_path("seed-export.key");
    let keypair_path = harness.workspace_path("seed-keypair.json");

    let (sign_result, _diagnostics) = sign::execute_with_defaults(
        &identity,
        &tpm2_derive::model::SignRequest {
            identity: identity.name.clone(),
            input: path_input(&message_path),
            format: Format::Hex,
            output: None,
        },
        &DerivationOverrides::default(),
    )
    .expect("seed sign through library API");
    let SignOperationResult::Derived(seed_sign) = sign_result else {
        panic!("expected derived sign result");
    };
    assert_eq!(seed_sign.mode, Mode::Seed);
    let signature_hex = seed_sign.signature.expect("inline signature");
    fs::write(&signature_path, &signature_hex).expect("write seed signature");

    let (verify_result, _diagnostics) = verify::execute_with_defaults(
        &identity,
        &VerifyRequest {
            identity: identity.name.clone(),
            input: path_input(&message_path),
            signature: path_input(&signature_path),
            format: InputFormat::Hex,
        },
        &DerivationOverrides::default(),
    )
    .expect("seed verify through library API");
    assert_eq!(verify_result.mode, Mode::Seed);
    assert!(verify_result.verified);

    let runner = ProcessCommandRunner;
    let plaintext = b"seed encrypt/decrypt coverage";
    let encrypted = encrypt::encrypt_with_defaults(
        &identity,
        plaintext,
        &DerivationOverrides::default(),
        &runner,
    )
    .expect("seed encrypt with real TPM-sealed seed");
    let ciphertext = hex_decode(
        encrypted
            .ciphertext
            .as_deref()
            .expect("inline seed ciphertext"),
    );
    let decrypted = encrypt::decrypt_with_defaults(
        &identity,
        &ciphertext,
        &DerivationOverrides::default(),
        &runner,
    )
    .expect("seed decrypt with real TPM-sealed seed");
    assert_eq!(decrypted.mode, Mode::Seed);
    assert_eq!(
        decrypted.plaintext.as_deref(),
        Some(hex_encode(plaintext).as_str())
    );

    let missing_confirm = ops::export(&tpm2_derive::model::ExportRequest {
        identity: identity.name.clone(),
        kind: ExportKind::SecretKey,
        output: Some(secret_key_path.clone()),
        format: Some(Format::Openssh),
        state_dir: Some(harness.state_dir().to_path_buf()),
        reason: Some("seed backup".to_string()),
        confirm: false,
        derivation: DerivationOverrides::default(),
    })
    .expect_err("secret export should require explicit confirmation");
    assert!(matches!(missing_confirm, Error::Validation(message) if message.contains("--confirm")));

    let public_export = ops::export(&tpm2_derive::model::ExportRequest {
        identity: identity.name.clone(),
        kind: ExportKind::PublicKey,
        output: Some(public_key_path.clone()),
        format: Some(Format::Openssh),
        state_dir: Some(harness.state_dir().to_path_buf()),
        reason: None,
        confirm: false,
        derivation: DerivationOverrides::default(),
    })
    .expect("seed public-key export");
    assert_eq!(public_export.mode, Mode::Seed);

    let secret_export = ops::export(&tpm2_derive::model::ExportRequest {
        identity: identity.name.clone(),
        kind: ExportKind::SecretKey,
        output: Some(secret_key_path.clone()),
        format: Some(Format::Openssh),
        state_dir: Some(harness.state_dir().to_path_buf()),
        reason: Some("seed backup".to_string()),
        confirm: true,
        derivation: DerivationOverrides::default(),
    })
    .expect("seed secret-key export");
    assert_eq!(secret_export.mode, Mode::Seed);
    assert_secret_permissions(&secret_key_path);

    let keypair_export = ops::export(&tpm2_derive::model::ExportRequest {
        identity: identity.name.clone(),
        kind: ExportKind::Keypair,
        output: Some(keypair_path.clone()),
        format: Some(Format::Openssh),
        state_dir: Some(harness.state_dir().to_path_buf()),
        reason: Some("seed backup".to_string()),
        confirm: true,
        derivation: DerivationOverrides::default(),
    })
    .expect("seed keypair export");
    assert_eq!(keypair_export.mode, Mode::Seed);
    assert_secret_permissions(&keypair_path);

    let public_key = fs::read_to_string(&public_key_path).expect("read seed public key");
    assert!(public_key.starts_with("ssh-ed25519 "));
    let secret_key = fs::read_to_string(&secret_key_path).expect("read seed secret key");
    assert!(secret_key.contains("BEGIN OPENSSH PRIVATE KEY"));
    let keypair_payload: Value =
        serde_json::from_slice(&fs::read(&keypair_path).expect("read seed keypair payload"))
            .expect("parse seed keypair payload");
    assert_eq!(keypair_payload["mode"], Value::String("seed".to_string()));
    assert_eq!(
        keypair_payload["private_key"]["format"],
        Value::String("openssh".to_string())
    );
    assert_eq!(
        normalize_openssh_public_key(
            keypair_payload["public_key"]["value"]
                .as_str()
                .expect("seed keypair public key"),
        ),
        normalize_openssh_public_key(&public_key),
    );

    let socket = harness.start_ssh_agent().expect("start ssh-agent");
    let ssh_result = ssh::add_with_defaults(
        &identity,
        &SshAddRequest {
            identity: identity.name.clone(),
            comment: Some("seed@test".to_string()),
            socket: Some(socket.clone()),
            state_dir: Some(harness.state_dir().to_path_buf()),
            derivation: DerivationOverrides::default(),
        },
    )
    .expect("seed ssh-add through library API");
    assert_eq!(ssh_result.mode, Mode::Seed);

    let listed = harness
        .list_ssh_agent_keys(&socket)
        .expect("list ssh-agent keys");
    assert!(
        listed.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        listed.stdout,
        listed.stderr
    );
    let listed_key = listed.stdout.lines().next().expect("agent key line");
    assert_eq!(
        normalize_openssh_public_key(listed_key),
        normalize_openssh_public_key(&public_key)
    );
    assert_eq!(
        normalize_openssh_public_key(&ssh_result.public_key_openssh),
        normalize_openssh_public_key(&public_key),
    );
}

#[test]
fn prf_identity_library_round_trip_covers_derivation_overrides_encrypt_export_and_ssh_add() {
    let mut harness = RealTpmHarness::start().expect("start swtpm harness");
    let identity = create_identity(
        &harness,
        "prf-real",
        Algorithm::P256,
        ModePreference::Prf,
        vec![
            UseCase::Sign,
            UseCase::Verify,
            UseCase::Encrypt,
            UseCase::Decrypt,
            UseCase::Ssh,
            UseCase::ExportSecret,
        ],
        DerivationOverrides {
            org: Some("com.example.tests".to_string()),
            purpose: Some("payments".to_string()),
            context: BTreeMap::from([
                ("tenant".to_string(), "alpha".to_string()),
                ("region".to_string(), "us-east-1".to_string()),
            ]),
        },
    );
    assert_eq!(identity.mode.resolved, Mode::Prf);

    let override_inputs = DerivationOverrides {
        org: None,
        purpose: Some("session".to_string()),
        context: BTreeMap::from([
            ("tenant".to_string(), "beta".to_string()),
            ("channel".to_string(), "mobile".to_string()),
        ]),
    };

    let default_public_path = harness.workspace_path("prf-default.pub");
    let overridden_public_path = harness.workspace_path("prf-overridden.pub");
    let signature_path = harness.workspace_path("prf-message.sig");
    let secret_key_path = harness.workspace_path("prf-secret.pem");
    let keypair_path = harness.workspace_path("prf-keypair.json");
    let message_path =
        write_workspace_file(&harness, "prf-message.bin", b"prf integration message\n");

    ops::export(&tpm2_derive::model::ExportRequest {
        identity: identity.name.clone(),
        kind: ExportKind::PublicKey,
        output: Some(default_public_path.clone()),
        format: Some(Format::Openssh),
        state_dir: Some(harness.state_dir().to_path_buf()),
        reason: None,
        confirm: false,
        derivation: DerivationOverrides::default(),
    })
    .expect("default prf public export");
    ops::export(&tpm2_derive::model::ExportRequest {
        identity: identity.name.clone(),
        kind: ExportKind::PublicKey,
        output: Some(overridden_public_path.clone()),
        format: Some(Format::Openssh),
        state_dir: Some(harness.state_dir().to_path_buf()),
        reason: None,
        confirm: false,
        derivation: override_inputs.clone(),
    })
    .expect("overridden prf public export");

    let default_public =
        fs::read_to_string(&default_public_path).expect("read default prf public key");
    let overridden_public =
        fs::read_to_string(&overridden_public_path).expect("read overridden prf public key");
    assert!(default_public.starts_with("ecdsa-sha2-nistp256 "));
    assert!(overridden_public.starts_with("ecdsa-sha2-nistp256 "));
    assert_ne!(
        normalize_openssh_public_key(&default_public),
        normalize_openssh_public_key(&overridden_public),
        "derivation overrides should change the effective PRF-derived key"
    );

    let (sign_result, _diagnostics) = sign::execute_with_defaults(
        &identity,
        &tpm2_derive::model::SignRequest {
            identity: identity.name.clone(),
            input: path_input(&message_path),
            format: Format::Der,
            output: Some(signature_path.clone()),
        },
        &override_inputs,
    )
    .expect("prf sign with derivation overrides");
    let SignOperationResult::Derived(prf_sign) = sign_result else {
        panic!("expected derived PRF sign result");
    };
    assert_eq!(prf_sign.mode, Mode::Prf);
    assert!(signature_path.is_file());

    let (verified_with_override, _diagnostics) = verify::execute_with_defaults(
        &identity,
        &VerifyRequest {
            identity: identity.name.clone(),
            input: path_input(&message_path),
            signature: path_input(&signature_path),
            format: InputFormat::Der,
        },
        &override_inputs,
    )
    .expect("prf verify with same derivation overrides");
    assert!(verified_with_override.verified);

    let (verified_without_override, _diagnostics) = verify::execute_with_defaults(
        &identity,
        &VerifyRequest {
            identity: identity.name.clone(),
            input: path_input(&message_path),
            signature: path_input(&signature_path),
            format: InputFormat::Der,
        },
        &DerivationOverrides::default(),
    )
    .expect("prf verify with default derivation should still execute");
    assert!(
        !verified_without_override.verified,
        "verifying with different effective derivation inputs should fail"
    );

    let runner = ProcessCommandRunner;
    let plaintext = b"prf encrypt/decrypt coverage";
    let encrypted = encrypt::encrypt_with_defaults(&identity, plaintext, &override_inputs, &runner)
        .expect("prf encrypt with derivation overrides");
    let ciphertext = hex_decode(
        encrypted
            .ciphertext
            .as_deref()
            .expect("inline prf ciphertext"),
    );
    let decrypted =
        encrypt::decrypt_with_defaults(&identity, &ciphertext, &override_inputs, &runner)
            .expect("prf decrypt with matching derivation overrides");
    assert_eq!(decrypted.mode, Mode::Prf);
    assert_eq!(
        decrypted.plaintext.as_deref(),
        Some(hex_encode(plaintext).as_str())
    );

    let mismatched_decrypt = encrypt::decrypt_with_defaults(
        &identity,
        &ciphertext,
        &DerivationOverrides::default(),
        &runner,
    )
    .expect_err("decrypting with different derivation inputs should fail");
    assert!(
        matches!(mismatched_decrypt, Error::Validation(message) if message.contains("AEAD decryption failed"))
    );

    let secret_export = ops::export(&tpm2_derive::model::ExportRequest {
        identity: identity.name.clone(),
        kind: ExportKind::SecretKey,
        output: Some(secret_key_path.clone()),
        format: Some(Format::Pem),
        state_dir: Some(harness.state_dir().to_path_buf()),
        reason: Some("session escrow".to_string()),
        confirm: true,
        derivation: override_inputs.clone(),
    })
    .expect("prf secret-key export");
    assert_eq!(secret_export.mode, Mode::Prf);
    assert_secret_permissions(&secret_key_path);

    let keypair_export = ops::export(&tpm2_derive::model::ExportRequest {
        identity: identity.name.clone(),
        kind: ExportKind::Keypair,
        output: Some(keypair_path.clone()),
        format: Some(Format::Pem),
        state_dir: Some(harness.state_dir().to_path_buf()),
        reason: Some("session escrow".to_string()),
        confirm: true,
        derivation: override_inputs.clone(),
    })
    .expect("prf keypair export");
    assert_eq!(keypair_export.mode, Mode::Prf);
    assert_secret_permissions(&keypair_path);

    let secret_key = fs::read_to_string(&secret_key_path).expect("read prf secret key");
    assert!(secret_key.contains("BEGIN EC PRIVATE KEY"));
    let keypair_payload: Value =
        serde_json::from_slice(&fs::read(&keypair_path).expect("read prf keypair payload"))
            .expect("parse prf keypair payload");
    assert_eq!(keypair_payload["mode"], Value::String("prf".to_string()));
    assert_eq!(
        keypair_payload["private_key"]["format"],
        Value::String("sec1-pem".to_string())
    );
    let keypair_public = keypair_payload["public_key"]["value"]
        .as_str()
        .expect("prf keypair public key");
    assert!(keypair_public.contains("BEGIN PUBLIC KEY"));

    let socket = harness.start_ssh_agent().expect("start ssh-agent");
    let ssh_result = ssh::add_with_defaults(
        &identity,
        &SshAddRequest {
            identity: identity.name.clone(),
            comment: Some("prf@test".to_string()),
            socket: Some(socket.clone()),
            state_dir: Some(harness.state_dir().to_path_buf()),
            derivation: override_inputs.clone(),
        },
    )
    .expect("prf ssh-add through library API");
    assert_eq!(ssh_result.mode, Mode::Prf);

    let listed = harness
        .list_ssh_agent_keys(&socket)
        .expect("list ssh-agent keys");
    assert!(
        listed.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        listed.stdout,
        listed.stderr
    );
    let listed_key = listed.stdout.lines().next().expect("agent key line");
    assert_eq!(
        normalize_openssh_public_key(listed_key),
        normalize_openssh_public_key(&overridden_public),
    );
    assert_eq!(
        normalize_openssh_public_key(&ssh_result.public_key_openssh),
        normalize_openssh_public_key(&overridden_public),
    );
}

fn create_identity(
    harness: &RealTpmHarness,
    name: &str,
    algorithm: Algorithm,
    requested_mode: ModePreference,
    uses: Vec<UseCase>,
    defaults: DerivationOverrides,
) -> Identity {
    let probe = default_probe();
    let created = ops::resolve_identity(
        &probe,
        &IdentityCreateRequest {
            identity: name.to_string(),
            algorithm,
            uses,
            requested_mode,
            defaults,
            state_dir: Some(harness.state_dir().to_path_buf()),
            dry_run: false,
        },
    )
    .expect("create identity against swtpm-backed TPM tools");
    assert!(created.persisted);

    ops::load_identity(name, Some(harness.state_dir().to_path_buf()))
        .expect("reload persisted identity from isolated state")
}

fn path_input(path: &Path) -> InputSource {
    InputSource::Path {
        path: path.to_path_buf(),
    }
}

fn write_workspace_file(harness: &RealTpmHarness, name: &str, bytes: &[u8]) -> PathBuf {
    let path = harness.workspace_path(name);
    fs::write(&path, bytes).expect("write workspace file");
    path
}

#[cfg(unix)]
fn assert_secret_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = fs::metadata(path)
        .expect("secret export metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode,
        0o600,
        "secret export {} should be mode 0600",
        path.display()
    );
}

#[cfg(not(unix))]
fn assert_secret_permissions(_path: &Path) {}
