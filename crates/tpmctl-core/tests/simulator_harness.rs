use std::{
    env,
    io::Read as _,
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use tss_esapi::constants::StartupType;
use zeroize::Zeroizing;

use tpmctl_core::{
    CommandContext, HashAlgorithm, ObjectSelector, RegistryId, Store, StoreOptions,
    hmac::{HmacRequest, HmacResult},
    keygen::{KeygenRequest, KeygenUsage},
    output::{BinaryFormat, PublicKeyFormat, SignatureFormat},
    pubkey::PubkeyRequest,
    seal::{SealRequest, UnsealRequest},
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
fn simulator_keygen_pubkey_sign_hmac_and_seal_roundtrip() {
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
    let command = CommandContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };

    let sign_id = RegistryId::new("sim/sign").unwrap();
    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: sign_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    let public_sec1 = PubkeyRequest {
        selector: ObjectSelector::Id(sign_id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"library-first simulator signing".to_vec());
    let signature = SignRequest {
        selector: ObjectSelector::Id(sign_id),
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

    let hmac_id = RegistryId::new("sim/hmac").unwrap();
    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();
    let hmac = HmacRequest {
        selector: ObjectSelector::Id(hmac_id),
        input: Zeroizing::new(b"context".to_vec()),
        hash: Some(HashAlgorithm::Sha256),
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();
    let HmacResult::Output(mac) = hmac else {
        panic!("expected HMAC output")
    };
    assert_eq!(mac.len(), HashAlgorithm::Sha256.digest_len());

    let sealed_id = RegistryId::new("sim/sealed").unwrap();
    SealRequest {
        selector: ObjectSelector::Id(sealed_id.clone()),
        input: Zeroizing::new(b"sealed secret".to_vec()),
        force: false,
    }
    .execute_with_context(&command)
    .unwrap();
    let unsealed = UnsealRequest {
        selector: ObjectSelector::Id(sealed_id),
        force_binary_stdout: true,
    }
    .execute_with_context(&command)
    .unwrap();
    assert_eq!(unsealed.as_slice(), b"sealed secret");
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
