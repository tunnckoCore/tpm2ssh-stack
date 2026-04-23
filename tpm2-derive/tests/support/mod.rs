use std::collections::BTreeMap;
use std::env;

use clap::Parser as _;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const TOOL_OVERRIDE_NAMES: &[&str] = &[
    "tpm2_getcap",
    "tpm2_createprimary",
    "tpm2_create",
    "tpm2_load",
    "tpm2_unseal",
    "tpm2_getrandom",
    "tpm2_hmac",
    "tpm2_sign",
    "tpm2_verifysignature",
    "tpm2_testparms",
    "tpm2_readpublic",
    "tpm2_evictcontrol",
    "tpm2_flushcontext",
    "ssh-add",
];

pub struct RealTpmHarness {
    _environment_lock: MutexGuard<'static, ()>,
    previous_env: BTreeMap<OsString, Option<OsString>>,
    workspace: TempDir,
    state_dir: PathBuf,
    tool_paths: ToolPaths,
    tcti: String,
    swtpm: Child,
    swtpm_log_path: PathBuf,
    ssh_agent: Option<SshAgentProcess>,
}

struct ToolPaths {
    swtpm: PathBuf,
    ssh_add: PathBuf,
    ssh_agent: PathBuf,
    tpm2_getcap: PathBuf,
    overrides: Vec<(OsString, OsString)>,
}

struct SshAgentProcess {
    child: Child,
    socket: PathBuf,
    log_path: PathBuf,
}

pub struct SshAddListOutput {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl RealTpmHarness {
    pub fn start() -> io::Result<Self> {
        let environment_lock = environment_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tool_paths = ToolPaths::resolve()?;
        let workspace = tempfile::tempdir()?;
        let tpm_state_dir = workspace.path().join("swtpm");
        let state_dir = workspace.path().join("state");
        fs::create_dir_all(&tpm_state_dir)?;
        fs::create_dir_all(&state_dir)?;

        let (command_port, control_port) = reserve_ports()?;
        let tcti = format!("swtpm:host=127.0.0.1,port={command_port}");
        let previous_env = apply_process_environment(&tool_paths, &tcti)?;

        let swtpm_log_path = workspace.path().join("swtpm.log");
        let swtpm_log = File::create(&swtpm_log_path)?;
        let swtpm_log_stderr = swtpm_log.try_clone()?;
        let swtpm = Command::new(&tool_paths.swtpm)
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
            .stdout(Stdio::from(swtpm_log))
            .stderr(Stdio::from(swtpm_log_stderr))
            .spawn()?;

        let mut harness = Self {
            _environment_lock: environment_lock,
            previous_env,
            workspace,
            state_dir,
            tool_paths,
            tcti,
            swtpm,
            swtpm_log_path,
            ssh_agent: None,
        };
        if let Err(error) = harness.wait_until_ready() {
            harness.cleanup_processes();
            harness.restore_environment();
            return Err(error);
        }

        Ok(harness)
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn workspace_path(&self, name: &str) -> PathBuf {
        self.workspace.path().join(name)
    }

    pub fn start_ssh_agent(&mut self) -> io::Result<PathBuf> {
        if let Some(agent) = &self.ssh_agent {
            return Ok(agent.socket.clone());
        }

        let agent_dir = self.workspace.path().join("ssh-agent");
        fs::create_dir_all(&agent_dir)?;
        let socket = agent_dir.join("agent.sock");
        let log_path = agent_dir.join("ssh-agent.log");
        let log = File::create(&log_path)?;
        let log_stderr = log.try_clone()?;
        let child = Command::new(&self.tool_paths.ssh_agent)
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_stderr))
            .spawn()?;

        self.ssh_agent = Some(SshAgentProcess {
            child,
            socket: socket.clone(),
            log_path,
        });
        self.wait_until_ssh_agent_ready()?;
        Ok(socket)
    }

    pub fn list_ssh_agent_keys(&self, socket: &Path) -> io::Result<SshAddListOutput> {
        let output = Command::new(&self.tool_paths.ssh_add)
            .arg("-L")
            .env("SSH_AUTH_SOCK", socket)
            .output()?;

        Ok(SshAddListOutput {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn wait_until_ready(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);

        loop {
            if let Some(status) = self.swtpm.try_wait()? {
                return Err(io::Error::other(format!(
                    "swtpm exited before becoming ready with status {status}; log:\n{}",
                    read_log(&self.swtpm_log_path)
                )));
            }

            let output = Command::new(&self.tool_paths.tpm2_getcap)
                .arg("properties-fixed")
                .env("TPM2TOOLS_TCTI", &self.tcti)
                .output()?;
            if output.status.success() {
                return Ok(());
            }

            let last_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "timed out waiting for swtpm to accept TPM commands via {tcti}; last tpm2_getcap stderr: {last_stderr}\nswtpm log:\n{log}",
                    tcti = self.tcti,
                    log = read_log(&self.swtpm_log_path),
                )));
            }

            thread::sleep(Duration::from_millis(100));
        }
    }

    fn wait_until_ssh_agent_ready(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);

        loop {
            let Some(agent) = self.ssh_agent.as_mut() else {
                return Err(io::Error::other("ssh-agent was not started"));
            };

            if let Some(status) = agent.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "ssh-agent exited before becoming ready with status {status}; log:\n{}",
                    read_log(&agent.log_path)
                )));
            }

            if agent.socket.exists() {
                let socket = agent.socket.clone();
                let output = Command::new(&self.tool_paths.ssh_add)
                    .arg("-L")
                    .env("SSH_AUTH_SOCK", &socket)
                    .output()?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if output.status.success()
                    || stdout
                        .trim()
                        .eq_ignore_ascii_case("The agent has no identities.")
                    || stderr
                        .trim()
                        .eq_ignore_ascii_case("The agent has no identities.")
                {
                    return Ok(());
                }
            }

            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "timed out waiting for ssh-agent socket '{}'; log:\n{}",
                    agent.socket.display(),
                    read_log(&agent.log_path)
                )));
            }

            thread::sleep(Duration::from_millis(100));
        }
    }

    fn cleanup_processes(&mut self) {
        if let Some(agent) = self.ssh_agent.as_mut() {
            let _ = agent.child.kill();
            let _ = agent.child.wait();
        }
        let _ = self.swtpm.kill();
        let _ = self.swtpm.wait();
    }

    fn restore_environment(&mut self) {
        restore_process_environment(&self.previous_env);
        self.previous_env.clear();
    }
}

impl Drop for RealTpmHarness {
    fn drop(&mut self) {
        self.cleanup_processes();
        self.restore_environment();
    }
}

impl ToolPaths {
    fn resolve() -> io::Result<Self> {
        let swtpm = resolve_tool("swtpm")?;
        let ssh_add = resolve_tool("ssh-add")?;
        let ssh_agent = resolve_tool("ssh-agent")?;
        let tpm2_getcap = resolve_tool("tpm2_getcap")?;
        let overrides = TOOL_OVERRIDE_NAMES
            .iter()
            .map(|tool| Ok((tool_override_var(tool), os_arg(&resolve_tool(tool)?))))
            .collect::<io::Result<Vec<_>>>()?;

        Ok(Self {
            swtpm,
            ssh_add,
            ssh_agent,
            tpm2_getcap,
            overrides,
        })
    }
}

fn environment_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn apply_process_environment(
    tool_paths: &ToolPaths,
    tcti: &str,
) -> io::Result<BTreeMap<OsString, Option<OsString>>> {
    let mut previous = BTreeMap::new();
    set_env_var(
        &mut previous,
        OsStr::new("TPM2TOOLS_TCTI"),
        OsStr::new(tcti),
    )?;
    for (name, value) in &tool_paths.overrides {
        set_env_var(&mut previous, name.as_os_str(), value.as_os_str())?;
    }
    Ok(previous)
}

fn restore_process_environment(previous: &BTreeMap<OsString, Option<OsString>>) {
    for (name, value) in previous {
        match value {
            Some(original) => {
                // SAFETY: real TPM integration tests serialize all environment mutation behind a
                // process-wide mutex, so no concurrent environment access occurs while values are
                // restored.
                unsafe { env::set_var(name, original) };
            }
            None => {
                // SAFETY: guarded by the same process-wide mutex as `set_var` above.
                unsafe { env::remove_var(name) };
            }
        }
    }
}

fn set_env_var(
    previous: &mut BTreeMap<OsString, Option<OsString>>,
    name: &OsStr,
    value: &OsStr,
) -> io::Result<()> {
    if !previous.contains_key(name) {
        previous.insert(name.to_os_string(), env::var_os(name));
    }

    // SAFETY: real TPM integration tests serialize all environment mutation behind a process-wide
    // mutex, so no concurrent environment access occurs while test-specific overrides are active.
    unsafe { env::set_var(name, value) };
    Ok(())
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
    let override_var = tool_override_var(tool);
    if let Some(path) = env::var_os(&override_var) {
        let candidate = PathBuf::from(path);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} was set to '{}' but that file is not an executable regular file",
                override_var.to_string_lossy(),
                candidate.display()
            ),
        ));
    }

    if let Some(path) = find_on_path(tool) {
        return Ok(path);
    }

    if let Some(path) = find_via_nix(tool)? {
        return Ok(path);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "required test dependency '{tool}' was not found on PATH and could not be resolved via nix; install it or run `nix shell nixpkgs#swtpm nixpkgs#tpm2-tools -c cargo test --features real-tpm-tests --test real_tpm_cli`"
        ),
    ))
}

fn find_via_nix(tool: &str) -> io::Result<Option<PathBuf>> {
    let Some(nix) = find_on_path("nix") else {
        return Ok(None);
    };
    let packages = nix_packages_for_tool(tool);
    if packages.is_empty() {
        return Ok(None);
    }

    let output = Command::new(nix)
        .arg("shell")
        .args(packages)
        .arg("-c")
        .arg("sh")
        .arg("-lc")
        .arg(format!("command -v {tool}"))
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let candidate = stdout.lines().next().map(str::trim).unwrap_or_default();
    if candidate.is_empty() {
        return Ok(None);
    }

    let path = PathBuf::from(candidate);
    Ok(is_executable(&path).then_some(path))
}

fn nix_packages_for_tool(tool: &str) -> &'static [&'static str] {
    match tool {
        "swtpm" => &["nixpkgs#swtpm"],
        "ssh-add" | "ssh-agent" => &["nixpkgs#openssh"],
        _ if tool.starts_with("tpm2_") => &["nixpkgs#tpm2-tools"],
        _ => &[],
    }
}

fn tool_override_var(tool: &str) -> OsString {
    OsString::from(format!(
        "TPM2_DERIVE_{}_BIN",
        tool.replace('-', "_").to_ascii_uppercase()
    ))
}

fn find_on_path(tool: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    env::split_paths(&path_var).find_map(|directory| {
        let candidate = directory.join(tool);
        is_executable(&candidate).then_some(candidate)
    })
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn read_log(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|_| String::from("<log unavailable>"))
}

pub fn os_arg(path: &Path) -> OsString {
    path.as_os_str().to_os_string()
}

pub fn normalize_openssh_public_key(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn hex_decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("utf-8 hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

pub fn run_cli<I, T>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = tpm2_derive::cli::Cli::try_parse_from(args).map_err(|error| error.to_string())?;
    tpm2_derive::run_cli(cli).map_err(|error| error.to_string())
}

pub fn run_cli_json<I, T>(args: I) -> serde_json::Value
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let output = run_cli(args).expect("cli command should execute");
    serde_json::from_str(&output).expect("cli output should be valid json")
}
