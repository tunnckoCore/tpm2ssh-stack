use std::{
    env,
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use tss_esapi::constants::StartupType;

const TCTI_ENV_PRECEDENCE: [&str; 3] = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"];

#[test]
fn simulator_or_test_tcti_opens_esapi_context_and_gets_random() {
    let Some(_tcti) = SimulatorTcti::activate() else {
        eprintln!(
            "skipping TPM simulator integration test: set TEST_TCTI/TCTI/TPM2TOOLS_TCTI or install swtpm"
        );
        return;
    };

    let mut context =
        tpmctl_core::tpm::create_context().expect("configured TCTI should open an ESAPI context");

    let random = match context.get_random(8) {
        Ok(random) => random,
        Err(first_error) => {
            // Fresh swtpm instances require TPM2_Startup before normal commands.
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
    previous_test_tcti: Option<String>,
    set_test_tcti: bool,
}

impl SimulatorTcti {
    fn activate() -> Option<Self> {
        if existing_tcti().is_some() {
            return Some(Self {
                _child: None,
                _state_dir: None,
                previous_test_tcti: None,
                set_test_tcti: false,
            });
        }

        let swtpm = find_on_path("swtpm")?;
        let state_dir = tempfile::tempdir().expect("create swtpm state directory");
        let server_port = free_local_port();
        let ctrl_port = free_local_port();

        let mut child = Command::new(swtpm)
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state_dir.path().display()),
                "--server",
                &format!("type=tcp,host=127.0.0.1,port={server_port}"),
                "--ctrl",
                &format!("type=tcp,host=127.0.0.1,port={ctrl_port}"),
                "--flags",
                "not-need-init",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start swtpm simulator");

        wait_for_tcp_port(SocketAddr::from(([127, 0, 0, 1], server_port)), &mut child);

        let tcti = format!("swtpm:host=127.0.0.1,port={server_port}");
        let previous_test_tcti = env::var("TEST_TCTI").ok();
        unsafe {
            env::set_var("TEST_TCTI", tcti);
        }

        Some(Self {
            _child: Some(child),
            _state_dir: Some(state_dir),
            previous_test_tcti,
            set_test_tcti: true,
        })
    }
}

impl Drop for SimulatorTcti {
    fn drop(&mut self) {
        if self.set_test_tcti {
            unsafe {
                if let Some(previous) = &self.previous_test_tcti {
                    env::set_var("TEST_TCTI", previous);
                } else {
                    env::remove_var("TEST_TCTI");
                }
            }
        }

        if let Some(child) = &mut self._child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn existing_tcti() -> Option<String> {
    TCTI_ENV_PRECEDENCE
        .iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
}

fn find_on_path(binary: &str) -> Option<std::path::PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

fn free_local_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral local TCP port")
        .local_addr()
        .expect("read local TCP port")
        .port()
}

fn wait_for_tcp_port(addr: SocketAddr, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll swtpm child") {
            panic!("swtpm exited before accepting connections: {status}");
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for swtpm at {addr}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}
