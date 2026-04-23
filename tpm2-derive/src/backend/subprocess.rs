use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::model::{Algorithm, CapabilityReport, Diagnostic, DiagnosticLevel, UseCase};

use super::CapabilityProbe;
use super::parser::{
    AlgorithmCapability, CommandCapability, EccCurveCapability, FixedProperty, parse_algorithms,
    parse_commands, parse_ecc_curves, parse_properties_fixed,
};
use super::recommend;

pub fn default_probe() -> SubprocessCapabilityProbe {
    SubprocessCapabilityProbe::default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityGroup {
    Algorithms,
    Commands,
    EccCurves,
    PropertiesFixed,
}

impl CapabilityGroup {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Algorithms => "algorithms",
            Self::Commands => "commands",
            Self::EccCurves => "ecc-curves",
            Self::PropertiesFixed => "properties-fixed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandInvocation {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandInvocation {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    fn for_group(group: CapabilityGroup) -> Self {
        Self::new("tpm2_getcap", [group.as_arg()])
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

impl CommandOutput {
    fn success(&self) -> bool {
        self.error.is_none() && self.exit_code == Some(0)
    }
}

pub trait CommandRunner {
    fn run(&self, invocation: &CommandInvocation) -> CommandOutput;
}

impl<R> CommandRunner for &R
where
    R: CommandRunner + ?Sized,
{
    fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
        (**self).run(invocation)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessCommandRunner;

pub fn resolve_trusted_program_path(program: &str) -> std::io::Result<PathBuf> {
    if let Some(override_path) = resolve_program_override(program)? {
        return Ok(override_path);
    }

    if program.contains(std::path::MAIN_SEPARATOR) {
        return Ok(PathBuf::from(program));
    }

    for directory in [
        "/run/current-system/sw/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ] {
        let candidate = Path::new(directory).join(program);
        if is_executable_file(&candidate) {
            return Ok(candidate);
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("trusted executable '{program}' was not found in the allowed search paths"),
    ))
}

#[cfg(any(test, feature = "real-tpm-tests"))]
fn resolve_program_override(program: &str) -> std::io::Result<Option<PathBuf>> {
    let override_var = program_override_var(program);
    let Some(path) = std::env::var_os(&override_var) else {
        return Ok(None);
    };

    let candidate = PathBuf::from(path);
    if is_executable_file(&candidate) {
        return Ok(Some(candidate));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "{override_var} was set to '{}' but that file is not an executable regular file",
            candidate.display()
        ),
    ))
}

#[cfg(not(any(test, feature = "real-tpm-tests")))]
fn resolve_program_override(_program: &str) -> std::io::Result<Option<PathBuf>> {
    Ok(None)
}

#[cfg(any(test, feature = "real-tpm-tests"))]
fn program_override_var(program: &str) -> String {
    format!(
        "TPM2_DERIVE_{}_BIN",
        program.replace('-', "_").to_ascii_uppercase()
    )
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
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

impl CommandRunner for ProcessCommandRunner {
    fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
        let program = match resolve_trusted_program_path(&invocation.program) {
            Ok(path) => path,
            Err(error) => {
                return CommandOutput {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    error: Some(error.to_string()),
                };
            }
        };

        let mut command = Command::new(&program);
        command.env_clear();
        if let Some(tcti) = trusted_tpm2tools_tcti_env() {
            command.env("TPM2TOOLS_TCTI", tcti);
        }

        match command.args(&invocation.args).output() {
            Ok(output) => CommandOutput {
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                error: None,
            },
            Err(error) => CommandOutput {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(error.to_string()),
            },
        }
    }
}

#[cfg(any(test, feature = "real-tpm-tests"))]
fn trusted_tpm2tools_tcti_env() -> Option<OsString> {
    std::env::var_os("TPM2TOOLS_TCTI")
}

#[cfg(not(any(test, feature = "real-tpm-tests")))]
fn trusted_tpm2tools_tcti_env() -> Option<OsString> {
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAvailability {
    pub program: &'static str,
    pub available: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ProbeSnapshot {
    pub algorithms: Vec<AlgorithmCapability>,
    pub commands: Vec<CommandCapability>,
    pub ecc_curves: Vec<EccCurveCapability>,
    pub fixed_properties: Vec<FixedProperty>,
    pub tool_probes: Vec<ToolAvailability>,
    pub diagnostics: Vec<Diagnostic>,
    pub tpm_present: Option<bool>,
    pub tpm_accessible: Option<bool>,
}

impl ProbeSnapshot {
    pub fn has_algorithm(&self, name: &str) -> bool {
        let expected = name.to_ascii_lowercase();
        self.algorithms
            .iter()
            .any(|algorithm| algorithm.name == expected)
    }

    pub fn has_command(&self, name: &str) -> bool {
        let expected = name.to_ascii_lowercase();
        self.commands.iter().any(|command| command.name == expected)
    }

    pub fn has_curve(&self, name: &str) -> bool {
        let expected = name.to_ascii_lowercase();
        self.ecc_curves.iter().any(|curve| curve.name == expected)
    }

    pub fn tool_available(&self, program: &str) -> bool {
        self.tool_probes
            .iter()
            .find(|probe| probe.program == program)
            .is_some_and(|probe| probe.available)
    }

    pub fn property_value(&self, name: &str) -> Option<&str> {
        let expected = name.to_ascii_lowercase();
        self.fixed_properties
            .iter()
            .find(|property| property.name == expected)
            .and_then(|property| property.value.as_deref())
    }

    pub fn manufacturer_summary(&self) -> Option<String> {
        let manufacturer = self.property_value("tpm2_pt_manufacturer")?;
        let family = self.property_value("tpm2_pt_family_indicator");
        Some(match family {
            Some(family) => {
                format!("detected TPM family {family} from manufacturer {manufacturer}")
            }
            None => format!("detected TPM manufacturer {manufacturer}"),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SubprocessCapabilityProbe<R = ProcessCommandRunner> {
    runner: R,
}

impl<R> SubprocessCapabilityProbe<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R> CapabilityProbe for SubprocessCapabilityProbe<R>
where
    R: CommandRunner,
{
    fn detect(&self, algorithm: Option<Algorithm>, uses: &[UseCase]) -> CapabilityReport {
        let snapshot = self.probe_snapshot();
        recommend::build_report(&snapshot, algorithm, uses)
    }

    fn supports_mode(
        &self,
        algorithm: Algorithm,
        uses: &[UseCase],
        mode: crate::model::Mode,
    ) -> bool {
        let snapshot = self.probe_snapshot();
        recommend::snapshot_supports_mode(&snapshot, algorithm, uses, mode)
    }
}

impl<R> SubprocessCapabilityProbe<R>
where
    R: CommandRunner,
{
    pub fn probe_snapshot(&self) -> ProbeSnapshot {
        let mut snapshot = ProbeSnapshot {
            tool_probes: probe_tools(&self.runner),
            tpm_present: detect_tpm_device_presence(),
            ..ProbeSnapshot::default()
        };

        for tool in &snapshot.tool_probes {
            if !tool.available {
                snapshot.diagnostics.push(Diagnostic {
                    level: DiagnosticLevel::Warning,
                    code: "TPM2_TOOL_MISSING".to_string(),
                    message: format!(
                        "required subprocess tool '{}' is not available{}",
                        tool.program,
                        tool.detail
                            .as_deref()
                            .map(|detail| format!(": {detail}"))
                            .unwrap_or_default()
                    ),
                });
            }
        }

        if !snapshot.tool_available("tpm2_getcap") {
            snapshot.tpm_accessible = Some(false);
            snapshot.diagnostics.push(Diagnostic {
                level: DiagnosticLevel::Error,
                code: "TPM2_GETCAP_UNAVAILABLE".to_string(),
                message: "tpm2_getcap is required for subprocess capability probing".to_string(),
            });
            return snapshot;
        }

        let algorithms_output = self.run_group(CapabilityGroup::Algorithms);
        if !algorithms_output.success() {
            let (present, accessible) = infer_tpm_state(&algorithms_output);
            snapshot.tpm_present = snapshot.tpm_present.or(present);
            snapshot.tpm_accessible = accessible.or(Some(false));
            snapshot.diagnostics.push(group_failure_diagnostic(
                CapabilityGroup::Algorithms,
                &algorithms_output,
            ));
            return snapshot;
        }

        snapshot.tpm_present = Some(true);
        snapshot.tpm_accessible = Some(true);
        snapshot.algorithms = parse_algorithms(&algorithms_output.stdout);
        if snapshot.algorithms.is_empty() {
            snapshot.diagnostics.push(empty_parse_diagnostic(
                CapabilityGroup::Algorithms,
                &algorithms_output.stdout,
            ));
        }

        for group in [
            CapabilityGroup::Commands,
            CapabilityGroup::EccCurves,
            CapabilityGroup::PropertiesFixed,
        ] {
            let output = self.run_group(group);
            if !output.success() {
                snapshot
                    .diagnostics
                    .push(group_failure_diagnostic(group, &output));
                continue;
            }

            match group {
                CapabilityGroup::Algorithms => {}
                CapabilityGroup::Commands => {
                    snapshot.commands = parse_commands(&output.stdout);
                    if snapshot.commands.is_empty() {
                        snapshot
                            .diagnostics
                            .push(empty_parse_diagnostic(group, &output.stdout));
                    }
                }
                CapabilityGroup::EccCurves => {
                    snapshot.ecc_curves = parse_ecc_curves(&output.stdout);
                    if snapshot.ecc_curves.is_empty() {
                        snapshot
                            .diagnostics
                            .push(empty_parse_diagnostic(group, &output.stdout));
                    }
                }
                CapabilityGroup::PropertiesFixed => {
                    snapshot.fixed_properties = parse_properties_fixed(&output.stdout);
                    if snapshot.fixed_properties.is_empty() {
                        snapshot
                            .diagnostics
                            .push(empty_parse_diagnostic(group, &output.stdout));
                    }
                }
            }
        }

        snapshot
    }

    fn run_group(&self, group: CapabilityGroup) -> CommandOutput {
        self.runner.run(&CommandInvocation::for_group(group))
    }
}

fn probe_tools<R>(runner: &R) -> Vec<ToolAvailability>
where
    R: CommandRunner,
{
    [
        "tpm2_getcap",
        "tpm2_create",
        "tpm2_load",
        "tpm2_unseal",
        "tpm2_hmac",
        "tpm2_sign",
        "tpm2_verifysignature",
        "tpm2_testparms",
    ]
    .into_iter()
    .map(|program| {
        let output = runner.run(&CommandInvocation::new(program, ["--help"]));
        ToolAvailability {
            program,
            available: output.error.is_none(),
            detail: output.error,
        }
    })
    .collect()
}

fn group_failure_diagnostic(group: CapabilityGroup, output: &CommandOutput) -> Diagnostic {
    Diagnostic {
        level: DiagnosticLevel::Error,
        code: "TPM2_GETCAP_FAILED".to_string(),
        message: format!(
            "tpm2_getcap {} failed{}{}",
            group.as_arg(),
            output
                .exit_code
                .map(|code| format!(" with exit status {code}"))
                .unwrap_or_default(),
            render_command_detail(output),
        ),
    }
}

fn empty_parse_diagnostic(group: CapabilityGroup, stdout: &str) -> Diagnostic {
    Diagnostic {
        level: DiagnosticLevel::Warning,
        code: "TPM2_GETCAP_PARSE_EMPTY".to_string(),
        message: format!(
            "tpm2_getcap {} succeeded but produced no parseable capability entries: {}",
            group.as_arg(),
            preview(stdout),
        ),
    }
}

fn render_command_detail(output: &CommandOutput) -> String {
    if let Some(error) = output.error.as_deref() {
        return format!(" ({error})");
    }

    let detail = if !output.stderr.trim().is_empty() {
        output.stderr.trim()
    } else {
        output.stdout.trim()
    };

    if detail.is_empty() {
        String::new()
    } else {
        format!(": {}", preview(detail))
    }
}

fn preview(value: &str) -> String {
    let single_line = value.lines().map(str::trim).collect::<Vec<_>>().join(" ");
    let trimmed = single_line.trim();
    const LIMIT: usize = 180;
    if trimmed.len() > LIMIT {
        format!("{}…", &trimmed[..LIMIT])
    } else {
        trimmed.to_string()
    }
}

fn infer_tpm_state(output: &CommandOutput) -> (Option<bool>, Option<bool>) {
    let haystack = format!(
        "{}\n{}\n{}",
        output.stdout,
        output.stderr,
        output.error.as_deref().unwrap_or_default()
    );
    let lower = haystack.to_ascii_lowercase();

    let present = if lower.contains("permission denied")
        || lower.contains("/dev/tpmrm0")
        || lower.contains("/dev/tpm0")
    {
        Some(true)
    } else if lower.contains("no such file or directory")
        && (lower.contains("/dev/tpmrm0") || lower.contains("/dev/tpm0"))
    {
        Some(false)
    } else {
        detect_tpm_device_presence()
    };

    let accessible = if lower.contains("permission denied")
        || lower.contains("could not load tcti")
        || lower.contains("no standard tcti could be loaded")
        || lower.contains("connection refused")
    {
        Some(false)
    } else {
        None
    };

    (present, accessible)
}

fn detect_tpm_device_presence() -> Option<bool> {
    let has_tpm_device = Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists();
    if has_tpm_device { Some(true) } else { None }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crate::model::{Algorithm, Mode, UseCase};

    use super::{
        CommandInvocation, CommandOutput, CommandRunner, SubprocessCapabilityProbe, infer_tpm_state,
    };
    use crate::backend::CapabilityProbe;

    #[derive(Debug)]
    struct SeqRunner(std::cell::RefCell<VecDeque<CommandOutput>>);

    impl SeqRunner {
        fn new(outputs: Vec<CommandOutput>) -> Self {
            Self(std::cell::RefCell::new(outputs.into()))
        }
    }

    impl CommandRunner for SeqRunner {
        fn run(&self, _invocation: &CommandInvocation) -> CommandOutput {
            self.0
                .borrow_mut()
                .pop_front()
                .expect("test runner exhausted")
        }
    }

    fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            exit_code: Some(0),
            stdout: stdout.to_string(),
            stderr: String::new(),
            error: None,
        }
    }

    #[test]
    fn infers_permission_denied_as_present_but_inaccessible() {
        let (present, accessible) = infer_tpm_state(&CommandOutput {
            exit_code: Some(1),
            stdout: String::new(),
            stderr:
                "ERROR: Failed to open specified TCTI device file /dev/tpmrm0: Permission denied"
                    .to_string(),
            error: None,
        });

        assert_eq!(present, Some(true));
        assert_eq!(accessible, Some(false));
    }

    #[test]
    fn recommends_native_for_supported_p256_signing() {
        let runner = SeqRunner::new(vec![
            ok("help"),
            ok("help"),
            ok("help"),
            ok("help"),
            ok("help"),
            ok("help"),
            ok("help"),
            ok("help"),
            ok(
                "ecc:\n  value: 0x23\n  asymmetric: 1\n  symmetric: 0\n  hash: 0\n  object: 1\n  signing: 1\n  encrypting: 1\n  method: 0\nsha256:\n  value: 0x0B\n  asymmetric: 0\n  symmetric: 0\n  hash: 1\n  object: 0\n  signing: 0\n  encrypting: 0\n  method: 0\nhmac:\n  value: 0x05\n  asymmetric: 0\n  symmetric: 1\n  hash: 0\n  object: 0\n  signing: 1\n  encrypting: 0\n  method: 0\nkeyedhash:\n  value: 0x08\n  asymmetric: 0\n  symmetric: 0\n  hash: 0\n  object: 1\n  signing: 1\n  encrypting: 0\n  method: 0\n",
            ),
            ok(
                "TPM2_CC_Create:\n  value: 0x153\n  commandIndex: 0x153\n  nv: 0\n  extensive: 0\n  flushed: 0\n  cHandles: 0x1\n  rHandle: 0\nTPM2_CC_Load:\n  value: 0x157\n  commandIndex: 0x157\n  nv: 0\n  extensive: 0\n  flushed: 0\n  cHandles: 0x1\n  rHandle: 0\nTPM2_CC_HMAC:\n  value: 0x155\n  commandIndex: 0x155\n  nv: 0\n  extensive: 0\n  flushed: 0\n  cHandles: 0x1\n  rHandle: 0\nTPM2_CC_Sign:\n  value: 0x15d\n  commandIndex: 0x15d\n  nv: 0\n  extensive: 0\n  flushed: 0\n  cHandles: 0x1\n  rHandle: 0\nTPM2_CC_VerifySignature:\n  value: 0x177\n  commandIndex: 0x177\n  nv: 0\n  extensive: 0\n  flushed: 0\n  cHandles: 0x1\n  rHandle: 0\nTPM2_CC_Unseal:\n  value: 0x15e\n  commandIndex: 0x15e\n  nv: 0\n  extensive: 0\n  flushed: 0\n  cHandles: 0x1\n  rHandle: 0\n",
            ),
            ok("TPM2_ECC_NIST_P256: 0x3\n"),
            ok(
                "TPM2_PT_FAMILY_INDICATOR:\n  raw: 0x322E3000\n  value: \"2.0\"\nTPM2_PT_MANUFACTURER:\n  raw: 0x49424D00\n  value: \"IBM\"\n",
            ),
        ]);
        let probe = SubprocessCapabilityProbe::new(runner);

        let report = probe.detect(Some(Algorithm::P256), &[UseCase::Sign]);

        assert_eq!(report.recommended_mode, Some(Mode::Native));
        assert_eq!(report.tpm.accessible, Some(true));
        assert!(
            report
                .native
                .supported_algorithms()
                .contains(&Algorithm::P256)
        );
        let native = report
            .native
            .for_algorithm(Algorithm::P256)
            .expect("p256 native capability should exist");
        assert!(native.sign);
        assert!(native.verify);
        assert!(!native.encrypt);
        assert!(!native.decrypt);
    }
}
