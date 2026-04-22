use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

pub struct RealTpmHarness {
    workspace: TempDir,
    state_dir: PathBuf,
    tcti: String,
    swtpm: Child,
}

pub struct CliJsonOutput {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub json: Value,
}

impl CliJsonOutput {
    pub fn assert_ok(&self) -> &Value {
        assert!(
            self.status.success(),
            "expected successful process exit, got {:?}\nstdout:\n{}\nstderr:\n{}",
            self.status,
            self.stdout,
            self.stderr,
        );
        assert_eq!(
            self.json.get("ok").and_then(Value::as_bool),
            Some(true),
            "expected success envelope\nstdout:\n{}\nstderr:\n{}",
            self.stdout,
            self.stderr,
        );
        self.json
            .get("result")
            .expect("success envelopes always include a result")
    }
}

impl RealTpmHarness {
    pub fn start() -> io::Result<Self> {
        let workspace = tempfile::tempdir()?;
        let tpm_state_dir = workspace.path().join("swtpm");
        let state_dir = workspace.path().join("state");
        fs::create_dir_all(&tpm_state_dir)?;
        fs::create_dir_all(&state_dir)?;

        let swtpm_bin = resolve_tool("swtpm")?;
        let (command_port, control_port) = reserve_ports()?;
        let tcti = format!("swtpm:host=127.0.0.1,port={command_port}");

        let swtpm = Command::new(&swtpm_bin)
            .arg("socket")
            .arg("--tpm2")
            .arg("--tpmstate")
            .arg(format!("dir={}", tpm_state_dir.display()))
            .arg("--server")
            .arg(format!("type=tcp,port={command_port},bindaddr=127.0.0.1"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={control_port},bindaddr=127.0.0.1"))
            .arg("--flags")
            .arg("startup-clear")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let mut harness = Self {
            workspace,
            state_dir,
            tcti,
            swtpm,
        };
        harness.wait_until_ready()?;
        Ok(harness)
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn workspace_path(&self, name: &str) -> PathBuf {
        self.workspace.path().join(name)
    }

    pub fn run_cli_json<I, S>(&self, args: I) -> CliJsonOutput
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let binary = PathBuf::from(env!("CARGO_BIN_EXE_tpm2-derive"));
        let output = Command::new(binary)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("TPM2TOOLS_TCTI", &self.tcti)
            .arg("--json")
            .args(args)
            .output()
            .expect("run tpm2-derive CLI under test");

        let stdout = String::from_utf8(output.stdout.clone()).expect("stdout utf-8");
        let stderr = String::from_utf8(output.stderr.clone()).expect("stderr utf-8");
        let json = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!(
                "expected JSON stdout, got parse error: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            )
        });

        CliJsonOutput {
            status: output.status,
            stdout,
            stderr,
            json,
        }
    }

    fn wait_until_ready(&mut self) -> io::Result<()> {
        let getcap = resolve_tool("tpm2_getcap")?;
        let deadline = Instant::now() + Duration::from_secs(10);

        loop {
            if let Some(status) = self.swtpm.try_wait()? {
                return Err(io::Error::other(format!(
                    "swtpm exited before becoming ready with status {status}"
                )));
            }

            let output = Command::new(&getcap)
                .arg("properties-fixed")
                .env("TPM2TOOLS_TCTI", &self.tcti)
                .output()?;
            if output.status.success() {
                return Ok(());
            }

            let last_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "timed out waiting for swtpm to accept TPM commands via {tcti}; last tpm2_getcap stderr: {last_stderr}",
                    tcti = self.tcti,
                )));
            }

            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for RealTpmHarness {
    fn drop(&mut self) {
        let _ = self.swtpm.kill();
        let _ = self.swtpm.wait();
    }
}

fn reserve_ports() -> io::Result<(u16, u16)> {
    for _ in 0..32 {
        let command_listener = TcpListener::bind(("127.0.0.1", 0))?;
        let command_port = command_listener.local_addr()?.port();
        let Some(control_port) = command_port.checked_add(1) else {
            continue;
        };

        if let Ok(control_listener) = TcpListener::bind(("127.0.0.1", control_port)) {
            drop(command_listener);
            drop(control_listener);
            return Ok((command_port, control_port));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "failed to reserve consecutive TCP ports for swtpm command/control sockets",
    ))
}

fn resolve_tool(tool: &str) -> io::Result<PathBuf> {
    let override_var = format!(
        "TPM2_DERIVE_{}_BIN",
        tool.replace('-', "_").to_ascii_uppercase()
    );
    if let Some(path) = env::var_os(&override_var) {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Ok(candidate);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{override_var} was set to '{}' but that file does not exist",
                candidate.display()
            ),
        ));
    }

    find_on_path(tool).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "required test dependency '{tool}' was not found on PATH; install it or run via `nix shell nixpkgs#swtpm` before `cargo test --features real-tpm-tests --test real_tpm_cli`"
            ),
        )
    })
}

fn find_on_path(tool: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    env::split_paths(&path_var).find_map(|directory| {
        let candidate = directory.join(tool);
        is_executable(&candidate).then_some(candidate)
    })
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

pub fn os_arg(path: &Path) -> OsString {
    path.as_os_str().to_os_string()
}
