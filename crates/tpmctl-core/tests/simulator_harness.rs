use std::{
    env,
    io::Read as _,
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use p256::ecdsa::{
    Signature, VerifyingKey,
    signature::{Verifier as _, hazmat::PrehashVerifier as _},
};
use sha2::{Digest as _, Sha256};
use tss_esapi::constants::StartupType;
use zeroize::Zeroizing;

use tpmctl_core::{
    DeriveAlgorithm, DeriveFormat, DeriveUse, HashAlgorithm, ObjectSelector, PersistentHandle,
    RegistryId, SealTarget, Store, StoreOptions,
    api::{
        self, Context as ApiContext, EcdhParams, HmacParams, KeygenParams, PubkeyParams,
        SealParams, SignParams, SignPayload, UnsealParams,
        derive::{DeriveParams, SignPayload as DeriveSignPayload},
    },
    hmac::HmacResult,
    keygen::{KeygenRequest, KeygenUsage},
    output::{BinaryFormat, PublicKeyFormat, SignatureFormat},
    pubkey::PublicKeyInput,
    sign::{SignInput, SignRequest},
};

const TCTI_ENV_PRECEDENCE: [&str; 3] = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"];

fn simulator_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn simulator_or_test_tcti_opens_esapi_context_and_gets_random() {
    let _guard = simulator_test_lock().lock().unwrap();
    let Some(_tcti) = SimulatorTcti::activate() else {
        eprintln!(
            "skipping TPM simulator integration test: install swtpm or set TPMCTL_TEST_EXTERNAL_TCTI=1 with TEST_TCTI/TCTI/TPM2TOOLS_TCTI"
        );
        return;
    };

    startup_and_get_random();
}

#[test]
fn simulator_non_persistent_keygen_sign_reload_supports_sha512() {
    let _guard = simulator_test_lock().lock().unwrap();
    let Some(_tcti) = SimulatorTcti::activate() else {
        eprintln!(
            "skipping TPM simulator integration test: install swtpm or set TPMCTL_TEST_EXTERNAL_TCTI=1 with TEST_TCTI/TCTI/TPM2TOOLS_TCTI"
        );
        return;
    };
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let id = RegistryId::new("sim/keygen/reload-sign-sha512").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    let signature = SignRequest {
        selector: ObjectSelector::Id(id),
        input: SignInput::Message(Zeroizing::new(b"parent and hash flexibility".to_vec())),
        hash: HashAlgorithm::Sha512,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();

    assert_eq!(signature.len(), 64);
}

#[test]
fn simulator_persistent_handle_keygen_loads_by_handle_and_enforces_lifecycle() {
    let _guard = simulator_test_lock().lock().unwrap();
    let Some(_tcti) = SimulatorTcti::activate() else {
        eprintln!(
            "skipping TPM simulator integration test: install swtpm or set TPMCTL_TEST_EXTERNAL_TCTI=1 with TEST_TCTI/TCTI/TPM2TOOLS_TCTI"
        );
        return;
    };
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0040).unwrap();
    let first_id = RegistryId::new("sim/keygen/persistent-first").unwrap();
    let second_id = RegistryId::new("sim/keygen/persistent-second").unwrap();

    let first = KeygenRequest {
        usage: KeygenUsage::Sign,
        id: first_id,
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_store(&store)
    .unwrap();
    assert_eq!(first.persistent_handle, Some(handle));

    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"persistent simulator signing by handle".to_vec());
    let signature = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let signature = Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();

    let duplicate = KeygenRequest {
        usage: KeygenUsage::Sign,
        id: second_id.clone(),
        persist_at: Some(handle),
        force: false,
    }
    .execute_with_store(&store);
    assert!(
        duplicate.is_err(),
        "occupied persistent handle should reject duplicate keygen without force"
    );

    let replacement = KeygenRequest {
        usage: KeygenUsage::Sign,
        id: second_id,
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_store(&store)
    .unwrap();
    assert_eq!(replacement.persistent_handle, Some(handle));

    let replacement_signature = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let replacement_signature = Signature::from_slice(&replacement_signature).unwrap();
    assert!(
        verifying_key
            .verify(message.as_slice(), &replacement_signature)
            .is_err(),
        "force should evict the old persistent object before persisting replacement"
    );
}

#[test]
fn simulator_api_signs_message_and_digest_bytes_with_exported_p256_public_key() {
    let _guard = simulator_test_lock().lock().unwrap();
    let Some(_tcti) = SimulatorTcti::activate() else {
        eprintln!(
            "skipping TPM simulator integration test: install swtpm or set TPMCTL_TEST_EXTERNAL_TCTI=1 with TEST_TCTI/TCTI/TPM2TOOLS_TCTI"
        );
        return;
    };
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let sign_id = RegistryId::new("sim/api/sign-message-and-digest").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(sign_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"api simulator message bytes".to_vec());
    let message_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let message_signature = Signature::from_slice(&message_signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &message_signature)
        .unwrap();

    let digest = Zeroizing::new(Sha256::digest(b"api simulator digest bytes").to_vec());
    let digest_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id),
            payload: SignPayload::Digest(digest.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let digest_signature = Signature::from_slice(&digest_signature).unwrap();
    verifying_key
        .verify_prehash(digest.as_slice(), &digest_signature)
        .unwrap();
}

#[test]
fn simulator_api_hmac_seal_target_seals_and_emits_prf() {
    let _guard = simulator_test_lock().lock().unwrap();
    let Some(_tcti) = SimulatorTcti::activate() else {
        eprintln!(
            "skipping TPM simulator integration test: install swtpm or set TPMCTL_TEST_EXTERNAL_TCTI=1 with TEST_TCTI/TCTI/TPM2TOOLS_TCTI"
        );
        return;
    };
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let hmac_id = RegistryId::new("sim/api/hmac-seal-target/key").unwrap();
    let sealed_id = RegistryId::new("sim/api/hmac-seal-target/prf").unwrap();
    let input = Zeroizing::new(b"seal target integration input".to_vec());

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let sealed = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input,
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: Some(SealTarget::Id(sealed_id.clone())),
            emit_prf_when_sealing: true,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::SealedWithOutput {
        target,
        hash,
        output: expected_prf,
    } = sealed
    else {
        panic!("expected sealed HMAC output")
    };
    assert_eq!(target, SealTarget::Id(sealed_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);
    assert_eq!(expected_prf.len(), HashAlgorithm::Sha256.digest_len());

    let unsealed_prf = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed_prf.as_slice(), expected_prf.as_slice());
}

#[test]
fn simulator_api_derive_from_sealed_seed_emits_p256_pubkey_and_signature() {
    let _guard = simulator_test_lock().lock().unwrap();
    let Some(_tcti) = SimulatorTcti::activate() else {
        eprintln!(
            "skipping TPM simulator integration test: install swtpm or set TPMCTL_TEST_EXTERNAL_TCTI=1 with TEST_TCTI/TCTI/TPM2TOOLS_TCTI"
        );
        return;
    };
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let seed_id = RegistryId::new("sim/api/derive/sealed-seed").unwrap();
    let label = b"simulator sealed seed p256 derivation".to_vec();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(seed_id.clone()),
            input: Zeroizing::new(b"sealed derive integration seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let public_sec1 = api::derive::derive(
        &context,
        api::derive::DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::P256,
            usage: api::derive::DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(public_sec1.len(), 65);
    assert_eq!(public_sec1[0], 0x04);
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"api derive simulator signature payload".to_vec());
    let signature = api::derive::derive(
        &context,
        api::derive::DeriveParams {
            material: ObjectSelector::Id(seed_id),
            label: Some(label),
            algorithm: DeriveAlgorithm::P256,
            usage: api::derive::DeriveUse::Sign,
            payload: Some(api::derive::SignPayload::Message(message.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(signature.len(), 64);
    let signature = Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();
}

#[test]
fn simulator_api_derive_uses_hmac_identity_seed_fallback_deterministically() {
    let _guard = simulator_test_lock().lock().unwrap();
    let Some(_tcti) = SimulatorTcti::activate() else {
        eprintln!(
            "skipping TPM simulator integration test: install swtpm or set TPMCTL_TEST_EXTERNAL_TCTI=1 with TEST_TCTI/TCTI/TPM2TOOLS_TCTI"
        );
        return;
    };
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let hmac_id = RegistryId::new("sim/api/derive-hmac-seed/key").unwrap();
    let label = b"simulator derive hmac fallback label".to_vec();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let address_params = DeriveParams {
        material: ObjectSelector::Id(hmac_id.clone()),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Secp256k1,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Address,
        compressed: false,
        entropy: None,
    };
    let first_address = api::derive::derive(&context, address_params.clone()).unwrap();
    let second_address = api::derive::derive(&context, address_params).unwrap();
    assert_eq!(first_address, second_address);
    assert_eq!(first_address.len(), 42);
    assert!(first_address.starts_with(b"0x"));

    let pubkey_params = DeriveParams {
        material: ObjectSelector::Id(hmac_id.clone()),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Secp256k1,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let first_pubkey = api::derive::derive(&context, pubkey_params.clone()).unwrap();
    let second_pubkey = api::derive::derive(&context, pubkey_params).unwrap();
    assert_eq!(first_pubkey, second_pubkey);
    assert_eq!(first_pubkey.len(), 65);
    assert_eq!(first_pubkey[0], 0x04);

    let signature_params = DeriveParams {
        material: ObjectSelector::Id(hmac_id),
        label: Some(label),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Sign,
        payload: Some(DeriveSignPayload::Message(Zeroizing::new(
            b"derive with hmac identity seed fallback".to_vec(),
        ))),
        hash: Some(HashAlgorithm::Sha256),
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let first_signature = api::derive::derive(&context, signature_params.clone()).unwrap();
    let second_signature = api::derive::derive(&context, signature_params).unwrap();
    assert_eq!(first_signature, second_signature);
    assert_eq!(first_signature.len(), 64);
}

#[test]
fn simulator_api_facade_keygen_pubkey_sign_hmac_seal_and_ecdh_roundtrip() {
    let _guard = simulator_test_lock().lock().unwrap();
    let Some(_tcti) = SimulatorTcti::activate() else {
        eprintln!(
            "skipping TPM simulator integration test: install swtpm or set TPMCTL_TEST_EXTERNAL_TCTI=1 with TEST_TCTI/TCTI/TPM2TOOLS_TCTI"
        );
        return;
    };
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };

    let sign_id = RegistryId::new("sim/api/sign").unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(sign_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"api facade simulator signing".to_vec());
    let signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id),
            payload: SignPayload::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let signature = Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();

    let hmac_id = RegistryId::new("sim/api/hmac").unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();
    let hmac = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(b"context".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(mac) = hmac else {
        panic!("expected HMAC output")
    };
    assert_eq!(mac.len(), HashAlgorithm::Sha256.digest_len());

    let sealed_id = RegistryId::new("sim/api/sealed").unwrap();
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"sealed secret".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();
    let unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), b"sealed secret");

    let ecdh_id = RegistryId::new("sim/api/ecdh").unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: ecdh_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();
    let shared_secret = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(ecdh_id),
            peer_public_key: PublicKeyInput::Sec1(public_sec1),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(shared_secret.len(), 32);
}

fn startup_and_get_random() {
    let mut context =
        tpmctl_core::tpm::create_context().expect("configured TCTI should open an ESAPI context");

    let random = match context.get_random(8) {
        Ok(random) => random,
        Err(first_error) => {
            context
                .startup(StartupType::Clear)
                .unwrap_or_else(|startup_error| {
                    panic!(
                        "TPM get_random failed ({first_error}); startup also failed ({startup_error})"
                    )
                });
            context
                .get_random(8)
                .expect("TPM get_random should succeed after startup")
        }
    };

    assert_eq!(random.value().len(), 8);
}

struct SimulatorTcti {
    _child: Option<Child>,
    _state_dir: Option<tempfile::TempDir>,
    previous_tcti_env: Vec<(&'static str, Option<String>)>,
    restore_tcti_env: bool,
}

impl SimulatorTcti {
    fn activate() -> Option<Self> {
        if allow_external_tcti() && existing_tcti().is_some() {
            return Some(Self {
                _child: None,
                _state_dir: None,
                previous_tcti_env: Vec::new(),
                restore_tcti_env: false,
            });
        }

        let swtpm = find_on_path("swtpm")?;
        let state_dir = tempfile::tempdir().expect("create swtpm state directory");
        let (server_port, ctrl_port) = free_adjacent_local_ports();

        let mut child = Command::new(swtpm)
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state_dir.path().display()),
                "--server",
                &format!("type=tcp,bindaddr=127.0.0.1,port={server_port}"),
                "--ctrl",
                &format!("type=tcp,bindaddr=127.0.0.1,port={ctrl_port}"),
                "--flags",
                "not-need-init",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start swtpm simulator");

        wait_for_tcp_port(SocketAddr::from(([127, 0, 0, 1], server_port)), &mut child);

        let tcti = format!("swtpm:host=127.0.0.1,port={server_port}");
        let previous_tcti_env = capture_tcti_env();
        unsafe {
            for name in TCTI_ENV_PRECEDENCE {
                env::remove_var(name);
            }
            env::set_var("TEST_TCTI", tcti);
        }

        Some(Self {
            _child: Some(child),
            _state_dir: Some(state_dir),
            previous_tcti_env,
            restore_tcti_env: true,
        })
    }
}

impl Drop for SimulatorTcti {
    fn drop(&mut self) {
        if self.restore_tcti_env {
            unsafe {
                for (name, previous) in &self.previous_tcti_env {
                    if let Some(previous) = previous {
                        env::set_var(name, previous);
                    } else {
                        env::remove_var(name);
                    }
                }
            }
        }

        if let Some(child) = &mut self._child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn allow_external_tcti() -> bool {
    env::var("TPMCTL_TEST_EXTERNAL_TCTI")
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn existing_tcti() -> Option<String> {
    TCTI_ENV_PRECEDENCE
        .iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
}

fn capture_tcti_env() -> Vec<(&'static str, Option<String>)> {
    TCTI_ENV_PRECEDENCE
        .iter()
        .map(|name| (*name, env::var(name).ok()))
        .collect()
}

fn find_on_path(binary: &str) -> Option<std::path::PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

fn free_adjacent_local_ports() -> (u16, u16) {
    for _ in 0..100 {
        let first = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral local TCP port");
        let server_port = first.local_addr().expect("read local TCP port").port();
        let Some(ctrl_port) = server_port.checked_add(1) else {
            continue;
        };
        if TcpListener::bind(("127.0.0.1", ctrl_port)).is_ok() {
            drop(first);
            return (server_port, ctrl_port);
        }
    }
    panic!("failed to find adjacent free local TCP ports for swtpm");
}

fn wait_for_tcp_port(addr: SocketAddr, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll swtpm child") {
            let stderr = read_child_stderr(child);
            panic!("swtpm exited before accepting connections: {status}; stderr:\n{stderr}");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = read_child_stderr(child);
            panic!("timed out waiting for swtpm at {addr}; stderr:\n{stderr}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn read_child_stderr(child: &mut Child) -> String {
    let Some(mut stderr) = child.stderr.take() else {
        return "<stderr unavailable>".to_string();
    };
    let mut output = String::new();
    match stderr.read_to_string(&mut output) {
        Ok(_) if output.trim().is_empty() => "<empty>".to_string(),
        Ok(_) => output,
        Err(error) => format!("<failed to read stderr: {error}>"),
    }
}
