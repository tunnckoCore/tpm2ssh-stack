mod support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use serde_json::Value;
use support::{
    RealTpmHarness, hex_decode, hex_encode, normalize_openssh_public_key, run_cli, run_cli_json,
};
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
    assert_eq!(
        report.native.supported_uses(Algorithm::P256),
        vec![UseCase::Sign, UseCase::Verify]
    );
}

#[test]
fn ssh_add_requires_secret_egress_policy_with_real_swtpm() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");
    let identity_without_export = create_identity(
        &harness,
        "seed-ssh-policy",
        Algorithm::Ed25519,
        ModePreference::Seed,
        vec![UseCase::Sign, UseCase::Ssh],
        DerivationOverrides::default(),
    );

    let missing_use = ssh::add_with_defaults(
        &identity_without_export,
        &SshAddRequest {
            identity: identity_without_export.name.clone(),
            comment: Some("seed@test".to_string()),
            socket: None,
            state_dir: Some(harness.state_dir().to_path_buf()),
            reason: Some("load deployment key into agent".to_string()),
            confirm: true,
            derivation: DerivationOverrides::default(),
        },
    )
    .expect_err("ssh-add should require export-secret");
    assert!(
        matches!(missing_use, Error::PolicyRefusal(message) if message.contains("use=export-secret"))
    );

    let identity = create_identity(
        &harness,
        "seed-ssh-policy-confirm",
        Algorithm::Ed25519,
        ModePreference::Seed,
        vec![UseCase::Sign, UseCase::Ssh, UseCase::ExportSecret],
        DerivationOverrides::default(),
    );

    let missing_confirm = ssh::add_with_defaults(
        &identity,
        &SshAddRequest {
            identity: identity.name.clone(),
            comment: Some("seed@test".to_string()),
            socket: None,
            state_dir: Some(harness.state_dir().to_path_buf()),
            reason: Some("load deployment key into agent".to_string()),
            confirm: false,
            derivation: DerivationOverrides::default(),
        },
    )
    .expect_err("ssh-add should require confirm");
    assert!(matches!(missing_confirm, Error::Validation(message) if message.contains("--confirm")));

    let missing_reason = ssh::add_with_defaults(
        &identity,
        &SshAddRequest {
            identity: identity.name.clone(),
            comment: Some("seed@test".to_string()),
            socket: None,
            state_dir: Some(harness.state_dir().to_path_buf()),
            reason: None,
            confirm: true,
            derivation: DerivationOverrides::default(),
        },
    )
    .expect_err("ssh-add should require reason");
    assert!(matches!(missing_reason, Error::Validation(message) if message.contains("--reason")));
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
fn native_identity_supports_parallel_sign_for_same_identity() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");
    let identity = create_identity(
        &harness,
        "native-parallel",
        Algorithm::P256,
        ModePreference::Native,
        vec![UseCase::Sign, UseCase::Verify],
        DerivationOverrides::default(),
    );

    let message_one = write_workspace_file(&harness, "parallel-one.bin", b"parallel message one\n");
    let message_two = write_workspace_file(&harness, "parallel-two.bin", b"parallel message two\n");
    let signature_one = harness.workspace_path("parallel-one.sig");
    let signature_two = harness.workspace_path("parallel-two.sig");
    let barrier = Arc::new(Barrier::new(2));

    let barrier_one = barrier.clone();
    let identity_one = identity.clone();
    let message_one_path = message_one.clone();
    let signature_one_path = signature_one.clone();
    let worker_one = thread::spawn(move || {
        barrier_one.wait();
        sign::execute_with_defaults(
            &identity_one,
            &tpm2_derive::model::SignRequest {
                identity: identity_one.name.clone(),
                input: path_input(&message_one_path),
                format: Format::Der,
                output: Some(signature_one_path),
            },
            &DerivationOverrides::default(),
        )
    });

    let barrier_two = barrier.clone();
    let identity_two = identity.clone();
    let message_two_path = message_two.clone();
    let signature_two_path = signature_two.clone();
    let worker_two = thread::spawn(move || {
        barrier_two.wait();
        sign::execute_with_defaults(
            &identity_two,
            &tpm2_derive::model::SignRequest {
                identity: identity_two.name.clone(),
                input: path_input(&message_two_path),
                format: Format::Der,
                output: Some(signature_two_path),
            },
            &DerivationOverrides::default(),
        )
    });

    let result_one = worker_one
        .join()
        .expect("first native sign thread should not panic")
        .expect("first native sign should succeed");
    let result_two = worker_two
        .join()
        .expect("second native sign thread should not panic")
        .expect("second native sign should succeed");

    let SignOperationResult::Native(native_one) = result_one.0 else {
        panic!("expected first native sign result");
    };
    let SignOperationResult::Native(native_two) = result_two.0 else {
        panic!("expected second native sign result");
    };
    assert_eq!(native_one.state, "executed");
    assert_eq!(native_two.state, "executed");
    assert!(signature_one.is_file());
    assert!(signature_two.is_file());
    assert_ne!(
        fs::read(&signature_one).expect("read first signature"),
        fs::read(&signature_two).expect("read second signature")
    );

    for (message_path, signature_path) in [
        (&message_one, &signature_one),
        (&message_two, &signature_two),
    ] {
        let (verify_result, _diagnostics) = verify::execute_with_defaults(
            &identity,
            &VerifyRequest {
                identity: identity.name.clone(),
                input: path_input(message_path),
                signature: path_input(signature_path),
                format: InputFormat::Der,
            },
            &DerivationOverrides::default(),
        )
        .expect("parallel native verify");
        assert!(verify_result.verified);
    }
}

#[test]
fn concurrent_native_setup_same_identity_allows_only_one_winner() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");
    let state_dir = harness.state_dir().to_path_buf();
    let barrier = Arc::new(Barrier::new(2));

    let barrier_one = barrier.clone();
    let state_dir_one = state_dir.clone();
    let worker_one = thread::spawn(move || {
        let probe = default_probe();
        barrier_one.wait();
        ops::resolve_identity(
            &probe,
            &IdentityCreateRequest {
                identity: "native-race".to_string(),
                algorithm: Algorithm::P256,
                uses: vec![UseCase::Sign, UseCase::Verify],
                requested_mode: ModePreference::Native,
                defaults: DerivationOverrides::default(),
                state_dir: Some(state_dir_one),
                dry_run: false,
            },
        )
    });

    let barrier_two = barrier.clone();
    let state_dir_two = state_dir.clone();
    let worker_two = thread::spawn(move || {
        let probe = default_probe();
        barrier_two.wait();
        ops::resolve_identity(
            &probe,
            &IdentityCreateRequest {
                identity: "native-race".to_string(),
                algorithm: Algorithm::P256,
                uses: vec![UseCase::Sign, UseCase::Verify],
                requested_mode: ModePreference::Native,
                defaults: DerivationOverrides::default(),
                state_dir: Some(state_dir_two),
                dry_run: false,
            },
        )
    });

    let first = worker_one
        .join()
        .expect("first native setup thread should not panic");
    let second = worker_two
        .join()
        .expect("second native setup thread should not panic");
    let results = [first, second];

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert!(results.iter().any(|result| {
        matches!(result, Err(Error::State(message)) if message.contains("already exists"))
    }));

    let loaded = ops::load_identity("native-race", Some(state_dir.clone()))
        .expect("winner identity should persist cleanly");
    assert_eq!(loaded.mode.resolved, Mode::Native);
}

#[test]
fn native_sign_fails_closed_when_serialized_handle_file_is_removed() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");
    let identity = create_identity(
        &harness,
        "native-missing-handle",
        Algorithm::P256,
        ModePreference::Native,
        vec![UseCase::Sign, UseCase::Verify],
        DerivationOverrides::default(),
    );
    let handle_path = harness
        .state_dir()
        .join("objects")
        .join(&identity.name)
        .join("native")
        .join(format!("{}-signing-key.handle", identity.name));
    fs::remove_file(&handle_path).expect("remove serialized handle file");

    let message_path = write_workspace_file(&harness, "missing-handle.bin", b"fail closed\n");
    let error = sign::execute_with_defaults(
        &identity,
        &tpm2_derive::model::SignRequest {
            identity: identity.name.clone(),
            input: path_input(&message_path),
            format: Format::Hex,
            output: None,
        },
        &DerivationOverrides::default(),
    )
    .expect_err("native sign should fail closed without serialized handle state");
    assert!(
        matches!(error, Error::State(message) if message.contains("serialized handle state") || message.contains("no serialized handle state"))
    );
}

#[test]
fn decrypt_cli_requires_explicit_plaintext_egress_with_real_swtpm() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");
    let identity = create_identity(
        &harness,
        "seed-decrypt-cli",
        Algorithm::Ed25519,
        ModePreference::Seed,
        vec![UseCase::Encrypt, UseCase::Decrypt],
        DerivationOverrides::default(),
    );

    let runner = ProcessCommandRunner;
    let plaintext = b"seed decrypt cli coverage";
    let encrypted = encrypt::encrypt_with_defaults(
        &identity,
        plaintext,
        &DerivationOverrides::default(),
        &runner,
    )
    .expect("seed encrypt with real TPM-sealed seed");
    let ciphertext_path = write_workspace_file(
        &harness,
        "seed-decrypt-cli.ciphertext.hex",
        encrypted
            .ciphertext
            .as_deref()
            .expect("inline seed ciphertext")
            .as_bytes(),
    );

    let state_dir = harness.state_dir().display().to_string();
    let ciphertext_arg = ciphertext_path.display().to_string();

    let refusal = run_cli_json(vec![
        "tpm2-derive".to_string(),
        "--json".to_string(),
        "decrypt".to_string(),
        "--with".to_string(),
        identity.name.clone(),
        "--input".to_string(),
        ciphertext_arg.clone(),
        "--state-dir".to_string(),
        state_dir.clone(),
    ]);
    assert_eq!(refusal["ok"], Value::Bool(false));
    assert!(
        refusal["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("--allow-plaintext-output")
    );

    let inline = run_cli_json(vec![
        "tpm2-derive".to_string(),
        "--json".to_string(),
        "decrypt".to_string(),
        "--with".to_string(),
        identity.name.clone(),
        "--input".to_string(),
        ciphertext_arg.clone(),
        "--state-dir".to_string(),
        state_dir.clone(),
        "--allow-plaintext-output".to_string(),
    ]);
    assert_eq!(inline["ok"], Value::Bool(true));
    assert_eq!(
        inline["result"]["plaintext"],
        Value::String(hex_encode(plaintext))
    );

    let output_path = harness.workspace_path("seed-decrypt-cli.plaintext.bin");
    let file_output = run_cli_json(vec![
        "tpm2-derive".to_string(),
        "--json".to_string(),
        "decrypt".to_string(),
        "--with".to_string(),
        identity.name.clone(),
        "--input".to_string(),
        ciphertext_arg,
        "--state-dir".to_string(),
        state_dir,
        "--output".to_string(),
        output_path.display().to_string(),
    ]);
    assert_eq!(file_output["ok"], Value::Bool(true));
    assert!(file_output["result"]["plaintext"].is_null());
    assert_eq!(fs::read(&output_path).expect("plaintext file"), plaintext);
}

#[test]
fn encrypt_and_decrypt_cli_reject_oversized_buffered_inputs_with_real_swtpm() {
    let harness = RealTpmHarness::start().expect("start swtpm harness");
    let identity = create_identity(
        &harness,
        "seed-buffer-limit-cli",
        Algorithm::Ed25519,
        ModePreference::Seed,
        vec![UseCase::Encrypt, UseCase::Decrypt],
        DerivationOverrides::default(),
    );

    let oversized_bytes = (8 * 1024 * 1024 + 1) as u64;
    let encrypt_input = harness.workspace_path("oversized-encrypt.bin");
    fs::File::create(&encrypt_input)
        .expect("create oversized encrypt input")
        .set_len(oversized_bytes)
        .expect("size oversized encrypt input");

    let state_dir = harness.state_dir().display().to_string();
    let encrypt_error = run_cli(vec![
        "tpm2-derive".to_string(),
        "--json".to_string(),
        "encrypt".to_string(),
        "--with".to_string(),
        identity.name.clone(),
        "--input".to_string(),
        encrypt_input.display().to_string(),
        "--state-dir".to_string(),
        state_dir.clone(),
    ])
    .expect_err("oversized encrypt input should fail before TPM work");
    assert!(encrypt_error.contains("encrypt input"));
    assert!(encrypt_error.contains("limit"));

    let decrypt_input = harness.workspace_path("oversized-decrypt.hex");
    fs::File::create(&decrypt_input)
        .expect("create oversized decrypt input")
        .set_len(oversized_bytes)
        .expect("size oversized decrypt input");
    let decrypt_output = harness.workspace_path("oversized-decrypt.out");

    let decrypt_error = run_cli(vec![
        "tpm2-derive".to_string(),
        "--json".to_string(),
        "decrypt".to_string(),
        "--with".to_string(),
        identity.name.clone(),
        "--input".to_string(),
        decrypt_input.display().to_string(),
        "--output".to_string(),
        decrypt_output.display().to_string(),
        "--state-dir".to_string(),
        state_dir,
    ])
    .expect_err("oversized decrypt input should fail before TPM work");
    assert!(decrypt_error.contains("decrypt input"));
    assert!(decrypt_error.contains("limit"));
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
            reason: Some("load seed key into deployment agent".to_string()),
            confirm: true,
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
            reason: Some("load prf key into deployment agent".to_string()),
            confirm: true,
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
