use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};
use tempfile::{Builder as TempfileBuilder, TempDir};

use crate::backend::{CommandInvocation, CommandOutput, CommandRunner, ProcessCommandRunner};
use crate::crypto::{DerivationSpec, DerivationVersion, OutputKind};
use crate::error::{Error, Result};

pub const PRF_CONTEXT_PATH_METADATA_KEY: &str = "prf.context-path";
pub const PRF_PARENT_CONTEXT_PATH_METADATA_KEY: &str = "prf.parent-context-path";
pub const PRF_PUBLIC_PATH_METADATA_KEY: &str = "prf.public-path";
pub const PRF_PRIVATE_PATH_METADATA_KEY: &str = "prf.private-path";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PrfProtocolVersion {
    V1,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PrfRequest {
    pub identity: String,
    pub derivation: DerivationSpec,
}

impl PrfRequest {
    pub fn new(identity: impl Into<String>, derivation: DerivationSpec) -> Result<Self> {
        let request = Self {
            identity: identity.into(),
            derivation,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.identity.trim().is_empty() {
            return Err(Error::Validation(
                "identity must not be empty for PRF operations".to_string(),
            ));
        }

        let _ = self.derivation.canonical_bytes()?;
        Ok(())
    }

    pub fn protocol_version(&self) -> PrfProtocolVersion {
        match self.derivation.version() {
            DerivationVersion::V1 => PrfProtocolVersion::V1,
        }
    }

    pub fn tpm_input(&self) -> Result<Vec<u8>> {
        self.validate()?;
        self.derivation.prf_request_message()
    }

    pub fn output_len(&self) -> usize {
        usize::from(self.derivation.output().length)
    }
}

#[derive(Debug, Clone)]
pub struct RawPrfOutput {
    pub version: PrfProtocolVersion,
    material: SecretSlice<u8>,
}

impl RawPrfOutput {
    pub fn new(version: PrfProtocolVersion, material: Vec<u8>) -> Result<Self> {
        if material.is_empty() {
            return Err(Error::Validation(
                "raw PRF output must not be empty".to_string(),
            ));
        }

        Ok(Self {
            version,
            material: material.into(),
        })
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.material.expose_secret()
    }
}

#[derive(Debug, Clone)]
pub struct DerivedPrfOutput {
    pub version: PrfProtocolVersion,
    pub kind: OutputKind,
    bytes: SecretSlice<u8>,
}

impl DerivedPrfOutput {
    pub fn expose_secret(&self) -> &[u8] {
        self.bytes.expose_secret()
    }
}

#[derive(Debug, Clone)]
pub struct PrfResponse {
    pub request: PrfRequest,
    pub output: DerivedPrfOutput,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TpmPrfExecutionVersion {
    V1,
}

impl TpmPrfExecutionVersion {
    fn from_protocol(version: PrfProtocolVersion) -> Self {
        match version {
            PrfProtocolVersion::V1 => Self::V1,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TpmPrfHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl TpmPrfHashAlgorithm {
    fn as_tpm2_tools_arg(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TpmPrfKeyHandle {
    LoadedContext {
        context_path: PathBuf,
    },
    LoadableObject {
        parent_context_path: PathBuf,
        public_path: PathBuf,
        private_path: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TpmPrfExecutor {
    pub version: TpmPrfExecutionVersion,
    pub key_handle: TpmPrfKeyHandle,
    pub hash_algorithm: TpmPrfHashAlgorithm,
}

impl TpmPrfExecutor {
    pub fn v1(key_handle: TpmPrfKeyHandle) -> Self {
        Self {
            version: TpmPrfExecutionVersion::V1,
            key_handle,
            hash_algorithm: TpmPrfHashAlgorithm::Sha256,
        }
    }

    pub fn with_hash_algorithm(mut self, hash_algorithm: TpmPrfHashAlgorithm) -> Self {
        self.hash_algorithm = hash_algorithm;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TpmPrfWorkspace {
    pub root_dir: PathBuf,
    pub request_input_path: PathBuf,
    pub raw_output_path: PathBuf,
    pub transient_context_path: PathBuf,
}

impl TpmPrfWorkspace {
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        let root_dir = root_dir.into();
        Self {
            request_input_path: root_dir.join("prf-request.bin"),
            raw_output_path: root_dir.join("prf-raw-output.bin"),
            transient_context_path: root_dir.join("prf-key.ctx"),
            root_dir,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfRootLayout {
    pub object_dir: PathBuf,
    pub parent_context_path: PathBuf,
    pub public_path: PathBuf,
    pub private_path: PathBuf,
    pub loaded_context_path: PathBuf,
}

impl PrfRootLayout {
    pub fn for_profile(objects_dir: &Path, identity: &str) -> Self {
        Self::for_object_dir(objects_dir.join(identity))
    }

    fn for_object_dir(object_dir: PathBuf) -> Self {
        Self {
            parent_context_path: object_dir.join("parent.ctx"),
            public_path: object_dir.join("prf-root.pub"),
            private_path: object_dir.join("prf-root.priv"),
            loaded_context_path: object_dir.join("prf-root.ctx"),
            object_dir,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubprocessPrfBackend<R = ProcessCommandRunner> {
    objects_dir: PathBuf,
    runner: R,
}

impl SubprocessPrfBackend<ProcessCommandRunner> {
    pub fn new(objects_dir: impl Into<PathBuf>) -> Self {
        Self::with_runner(objects_dir, ProcessCommandRunner)
    }
}

impl<R> SubprocessPrfBackend<R> {
    pub fn with_runner(objects_dir: impl Into<PathBuf>, runner: R) -> Self {
        Self {
            objects_dir: objects_dir.into(),
            runner,
        }
    }

    pub fn objects_dir(&self) -> &Path {
        &self.objects_dir
    }

    pub fn root_layout(&self, identity: &str) -> PrfRootLayout {
        PrfRootLayout::for_profile(&self.objects_dir, identity)
    }
}

impl<R> SubprocessPrfBackend<R>
where
    R: CommandRunner,
{
    pub fn provision_root(&self, identity: &str) -> Result<PrfRootLayout> {
        fs::create_dir_all(&self.objects_dir).map_err(|error| {
            Error::State(format!(
                "failed to create PRF objects directory '{}': {error}",
                self.objects_dir.display()
            ))
        })?;

        let final_layout = self.root_layout(identity);
        if final_layout.object_dir.exists() {
            return Err(Error::State(format!(
                "PRF root material already exists for identity '{}' at '{}'",
                identity,
                final_layout.object_dir.display()
            )));
        }

        let staging = self.new_root_staging()?;
        self.run_checked(&create_primary_invocation(
            &staging.layout.parent_context_path,
        ))?;
        self.run_checked(&create_prf_root_invocation(
            &staging.layout.parent_context_path,
            &staging.layout.public_path,
            &staging.layout.private_path,
        ))?;
        self.run_checked(&load_prf_root_invocation(
            &staging.layout.parent_context_path,
            &staging.layout.public_path,
            &staging.layout.private_path,
            &staging.layout.loaded_context_path,
        ))?;

        self.commit_root_staging(staging, &final_layout)
    }

    fn new_root_staging(&self) -> Result<PrfRootStaging> {
        let tempdir = TempfileBuilder::new()
            .prefix("prf-root-")
            .tempdir_in(&self.objects_dir)
            .map_err(|error| {
                Error::State(format!(
                    "failed to create PRF staging directory under '{}': {error}",
                    self.objects_dir.display()
                ))
            })?;
        let layout = PrfRootLayout::for_object_dir(tempdir.path().to_path_buf());

        Ok(PrfRootStaging { layout, tempdir })
    }

    fn commit_root_staging(
        &self,
        staging: PrfRootStaging,
        final_layout: &PrfRootLayout,
    ) -> Result<PrfRootLayout> {
        let staging_path = staging.tempdir.keep();
        fs::rename(&staging_path, &final_layout.object_dir).map_err(|error| {
            Error::State(format!(
                "failed to persist PRF root material '{}' -> '{}': {error}",
                staging_path.display(),
                final_layout.object_dir.display()
            ))
        })?;

        Ok(final_layout.clone())
    }

    fn run_checked(&self, invocation: &CommandInvocation) -> Result<CommandOutput> {
        let output = self.runner.run(invocation);
        if output.error.is_none() && output.exit_code == Some(0) {
            return Ok(output);
        }

        Err(classify_prf_setup_command_error(invocation, &output))
    }
}

#[derive(Debug)]
struct PrfRootStaging {
    layout: PrfRootLayout,
    tempdir: TempDir,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TpmPrfCommandKind {
    LoadKey,
    Hmac,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPrfCommandStep {
    pub kind: TpmPrfCommandKind,
    pub invocation: CommandInvocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPrfExecutionPlan {
    pub executor: TpmPrfExecutor,
    pub request: PrfRequest,
    pub workspace: TpmPrfWorkspace,
    pub steps: Vec<TpmPrfCommandStep>,
}

impl TpmPrfExecutionPlan {
    pub fn key_context_path(&self) -> &Path {
        match &self.executor.key_handle {
            TpmPrfKeyHandle::LoadedContext { context_path } => context_path.as_path(),
            TpmPrfKeyHandle::LoadableObject { .. } => {
                self.workspace.transient_context_path.as_path()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TpmPrfExecutionResult {
    pub raw: RawPrfOutput,
    pub response: PrfResponse,
}

pub fn plan_tpm_prf_in(
    request: PrfRequest,
    executor: TpmPrfExecutor,
    workspace_root: impl AsRef<Path>,
) -> Result<TpmPrfExecutionPlan> {
    request.validate()?;
    ensure_matching_execution_version(executor.version, request.protocol_version())?;

    let workspace = TpmPrfWorkspace::new(workspace_root.as_ref().to_path_buf());
    let mut steps = Vec::new();

    if let TpmPrfKeyHandle::LoadableObject {
        parent_context_path,
        public_path,
        private_path,
    } = &executor.key_handle
    {
        steps.push(TpmPrfCommandStep {
            kind: TpmPrfCommandKind::LoadKey,
            invocation: CommandInvocation::new(
                "tpm2_load",
                [
                    "-C".to_string(),
                    path_arg(parent_context_path),
                    "-u".to_string(),
                    path_arg(public_path),
                    "-r".to_string(),
                    path_arg(private_path),
                    "-c".to_string(),
                    path_arg(&workspace.transient_context_path),
                ],
            ),
        });
    }

    let key_context_path = match &executor.key_handle {
        TpmPrfKeyHandle::LoadedContext { context_path } => context_path.as_path(),
        TpmPrfKeyHandle::LoadableObject { .. } => workspace.transient_context_path.as_path(),
    };

    let mut hmac_args = vec![
        "-c".to_string(),
        path_arg(key_context_path),
        "-g".to_string(),
        executor.hash_algorithm.as_tpm2_tools_arg().to_string(),
        "-o".to_string(),
        path_arg(&workspace.raw_output_path),
        path_arg(&workspace.request_input_path),
    ];

    steps.push(TpmPrfCommandStep {
        kind: TpmPrfCommandKind::Hmac,
        invocation: CommandInvocation::new("tpm2_hmac", hmac_args.drain(..)),
    });

    Ok(TpmPrfExecutionPlan {
        executor,
        request,
        workspace,
        steps,
    })
}

pub fn execute_tpm_prf_plan_with_runner<R>(
    plan: &TpmPrfExecutionPlan,
    runner: &R,
) -> Result<TpmPrfExecutionResult>
where
    R: CommandRunner,
{
    plan.request.validate()?;
    ensure_matching_execution_version(plan.executor.version, plan.request.protocol_version())?;

    create_secure_prf_workspace(&plan.workspace.root_dir)?;

    let request_bytes = plan.request.tpm_input()?;
    write_secure_workspace_file(&plan.workspace.request_input_path, &request_bytes)?;

    for step in &plan.steps {
        let output = runner.run(&step.invocation);
        if !command_succeeded(&output) {
            return Err(command_failure(step, &output));
        }
    }

    let raw_bytes = fs::read(&plan.workspace.raw_output_path).map_err(|error| {
        Error::State(format!(
            "TPM PRF step completed but raw output '{}' could not be read: {error}",
            plan.workspace.raw_output_path.display()
        ))
    })?;

    let raw = RawPrfOutput::new(plan.request.protocol_version(), raw_bytes)?;
    let response = finalize(plan.request.clone(), raw.clone())?;

    Ok(TpmPrfExecutionResult { raw, response })
}

pub fn execute_tpm_prf(
    request: PrfRequest,
    executor: TpmPrfExecutor,
) -> Result<TpmPrfExecutionResult> {
    let workspace_root = temp_workspace_root(&request.identity)?;
    let plan = plan_tpm_prf_in(request, executor, &workspace_root)?;
    let runner = ProcessCommandRunner;
    let execution = execute_tpm_prf_plan_with_runner(&plan, &runner);
    let cleanup = fs::remove_dir_all(&workspace_root).map_err(|error| {
        Error::State(format!(
            "failed to remove TPM PRF workspace '{}': {error}",
            workspace_root.display()
        ))
    });

    match (execution, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

pub fn finalize(request: PrfRequest, raw: RawPrfOutput) -> Result<PrfResponse> {
    request.validate()?;
    ensure_matching_versions(request.protocol_version(), raw.version)?;

    let derived = request.derivation.derive_output(raw.expose_secret())?;
    Ok(PrfResponse {
        output: DerivedPrfOutput {
            version: raw.version,
            kind: request.derivation.output().kind,
            bytes: derived,
        },
        request,
    })
}

fn create_primary_invocation(parent_context_path: &Path) -> CommandInvocation {
    CommandInvocation::new(
        "tpm2_createprimary",
        [
            "-C".to_string(),
            "o".to_string(),
            "-g".to_string(),
            "sha256".to_string(),
            "-G".to_string(),
            "rsa".to_string(),
            "-c".to_string(),
            path_arg(parent_context_path),
        ],
    )
}

fn create_prf_root_invocation(
    parent_context_path: &Path,
    public_path: &Path,
    private_path: &Path,
) -> CommandInvocation {
    CommandInvocation::new(
        "tpm2_create",
        [
            "-C".to_string(),
            path_arg(parent_context_path),
            "-g".to_string(),
            "sha256".to_string(),
            "-G".to_string(),
            "keyedhash".to_string(),
            "-a".to_string(),
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign".to_string(),
            "-u".to_string(),
            path_arg(public_path),
            "-r".to_string(),
            path_arg(private_path),
        ],
    )
}

fn load_prf_root_invocation(
    parent_context_path: &Path,
    public_path: &Path,
    private_path: &Path,
    loaded_context_path: &Path,
) -> CommandInvocation {
    CommandInvocation::new(
        "tpm2_load",
        [
            "-C".to_string(),
            path_arg(parent_context_path),
            "-u".to_string(),
            path_arg(public_path),
            "-r".to_string(),
            path_arg(private_path),
            "-c".to_string(),
            path_arg(loaded_context_path),
        ],
    )
}

fn ensure_matching_versions(
    request_version: PrfProtocolVersion,
    response_version: PrfProtocolVersion,
) -> Result<()> {
    if request_version != response_version {
        return Err(Error::Validation(format!(
            "PRF version mismatch: request {:?}, response {:?}",
            request_version, response_version
        )));
    }

    Ok(())
}

fn ensure_matching_execution_version(
    execution_version: TpmPrfExecutionVersion,
    request_version: PrfProtocolVersion,
) -> Result<()> {
    if execution_version != TpmPrfExecutionVersion::from_protocol(request_version) {
        return Err(Error::Validation(format!(
            "TPM PRF execution version mismatch: executor {:?}, request {:?}",
            execution_version, request_version
        )));
    }

    Ok(())
}

fn create_secure_prf_workspace(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(path).map_err(|error| {
        Error::State(format!(
            "failed to create TPM PRF workspace '{}': {error}",
            path.display()
        ))
    })?;

    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        Error::State(format!(
            "failed to harden TPM PRF workspace permissions for '{}': {error}",
            path.display()
        ))
    })?;

    Ok(())
}

fn write_secure_workspace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path).map_err(|error| {
        Error::State(format!(
            "failed to open TPM PRF workspace file '{}': {error}",
            path.display()
        ))
    })?;

    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            Error::State(format!(
                "failed to harden TPM PRF workspace file permissions for '{}': {error}",
                path.display()
            ))
        })?;

    use std::io::Write as _;
    file.write_all(bytes).map_err(|error| {
        Error::State(format!(
            "failed to write TPM PRF request input '{}': {error}",
            path.display()
        ))
    })
}

fn temp_workspace_root(identity: &str) -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            Error::State(format!(
                "system clock error while creating TPM PRF workspace: {error}"
            ))
        })?;

    let sanitized_profile = identity
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();

    Ok(std::env::temp_dir().join(format!(
        "tpm2-derive-prf-{}-{}-{}",
        process::id(),
        sanitized_profile,
        now.as_nanos()
    )))
}

fn classify_prf_setup_command_error(
    invocation: &CommandInvocation,
    output: &CommandOutput,
) -> Error {
    let detail = render_command_detail(output);
    let message = format!(
        "PRF setup failed while running '{} {}'{}",
        invocation.program,
        invocation.args.join(" "),
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    );

    if output.error.is_some() {
        Error::TpmUnavailable(message)
    } else {
        Error::CapabilityMismatch(message)
    }
}

fn command_succeeded(output: &CommandOutput) -> bool {
    output.error.is_none() && output.exit_code == Some(0)
}

fn command_failure(step: &TpmPrfCommandStep, output: &CommandOutput) -> Error {
    let detail = render_command_detail(output);
    let summary = format!(
        "TPM PRF subprocess step '{:?}' failed while running '{} {}'{}",
        step.kind,
        step.invocation.program,
        step.invocation.args.join(" "),
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    );

    if output.error.is_some() {
        Error::TpmUnavailable(summary)
    } else {
        Error::CapabilityMismatch(summary)
    }
}

fn render_command_detail(output: &CommandOutput) -> String {
    if let Some(error) = output.error.as_deref() {
        return error.to_string();
    }

    let detail = if !output.stderr.trim().is_empty() {
        output.stderr.trim()
    } else {
        output.stdout.trim()
    };

    preview(detail)
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

fn path_arg(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use super::{
        PrfProtocolVersion, PrfRequest, RawPrfOutput, TpmPrfCommandKind, TpmPrfExecutor,
        TpmPrfHashAlgorithm, TpmPrfKeyHandle, execute_tpm_prf_plan_with_runner, finalize,
        plan_tpm_prf_in,
    };
    use crate::backend::{CommandInvocation, CommandOutput, CommandRunner};
    use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};

    #[test]
    fn request_tpm_input_is_canonical_and_non_empty() {
        let request = PrfRequest::new(
            "default",
            DerivationSpec::V1(
                DerivationSpecV1::passkey_provider(
                    "io.github.example",
                    "example.com",
                    "cred-123",
                    32,
                )
                .unwrap(),
            ),
        )
        .unwrap();

        let encoded = request.tpm_input().unwrap();
        assert!(!encoded.is_empty());
        assert!(encoded.starts_with(crate::crypto::PRF_REQUEST_V1_DOMAIN));
    }

    #[test]
    fn plan_for_loaded_context_uses_only_hmac_step() {
        let request = example_request();
        let workspace = temp_test_dir("loaded-context-plan");
        let executor = TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadedContext {
            context_path: workspace.join("existing.ctx"),
        });

        let plan = plan_tpm_prf_in(request, executor, &workspace).unwrap();

        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].kind, TpmPrfCommandKind::Hmac);
        assert_eq!(plan.steps[0].invocation.program, "tpm2_hmac");
        assert!(
            plan.steps[0]
                .invocation
                .args
                .contains(&"sha256".to_string())
        );
        cleanup_test_dir(&workspace);
    }

    #[test]
    fn plan_for_loadable_object_adds_load_step() {
        let request = example_request();
        let workspace = temp_test_dir("loadable-object-plan");
        let executor = TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadableObject {
            parent_context_path: workspace.join("parent.ctx"),
            public_path: workspace.join("key.pub"),
            private_path: workspace.join("key.priv"),
        })
        .with_hash_algorithm(TpmPrfHashAlgorithm::Sha384);

        let plan = plan_tpm_prf_in(request, executor, &workspace).unwrap();

        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].kind, TpmPrfCommandKind::LoadKey);
        assert_eq!(plan.steps[0].invocation.program, "tpm2_load");
        assert_eq!(plan.steps[1].kind, TpmPrfCommandKind::Hmac);
        assert!(
            plan.steps[1]
                .invocation
                .args
                .contains(&"sha384".to_string())
        );
        cleanup_test_dir(&workspace);
    }

    #[test]
    fn execute_plan_returns_raw_and_finalized_output() {
        let workspace = temp_test_dir("execute-plan");
        let request = example_request();
        let expected_raw = b"tpm-prf-material".to_vec();
        let plan = plan_tpm_prf_in(
            request,
            TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadedContext {
                context_path: workspace.join("loaded.ctx"),
            }),
            &workspace,
        )
        .unwrap();

        let runner = FakeRunner::new(expected_raw.clone());
        let result = execute_tpm_prf_plan_with_runner(&plan, &runner).unwrap();

        assert_eq!(result.raw.expose_secret(), expected_raw.as_slice());
        assert_eq!(result.response.output.expose_secret().len(), 32);
        assert_eq!(runner.invocations().len(), 1);
        cleanup_test_dir(&workspace);
    }

    #[test]
    fn finalize_derives_output_for_request() {
        let request = PrfRequest::new(
            "default",
            DerivationSpec::V1(
                DerivationSpecV1::software_child_key(
                    "io.github.example",
                    "ed25519",
                    "m/ssh/0",
                    crate::crypto::OutputKind::Ed25519Seed,
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let raw = RawPrfOutput::new(PrfProtocolVersion::V1, b"tpm-prf-material".to_vec()).unwrap();

        let response = finalize(request, raw).unwrap();
        assert_eq!(response.output.expose_secret().len(), 32);
    }

    fn example_request() -> PrfRequest {
        PrfRequest::new(
            "default",
            DerivationSpec::V1(
                DerivationSpecV1::software_child_key(
                    "io.github.example",
                    "ed25519",
                    "m/ssh/0",
                    OutputKind::Ed25519Seed,
                )
                .unwrap(),
            ),
        )
        .unwrap()
    }

    fn temp_test_dir(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tpm2-derive-prf-test-{}-{}",
            label,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn cleanup_test_dir(path: &std::path::Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    #[derive(Clone)]
    struct FakeRunner {
        raw_output: Vec<u8>,
        invocations: Arc<Mutex<Vec<CommandInvocation>>>,
    }

    impl FakeRunner {
        fn new(raw_output: Vec<u8>) -> Self {
            Self {
                raw_output,
                invocations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn invocations(&self) -> Vec<CommandInvocation> {
            self.invocations.lock().unwrap().clone()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.invocations.lock().unwrap().push(invocation.clone());

            match invocation.program.as_str() {
                "tpm2_hmac" => {
                    let plan = parse_hmac_invocation(invocation).unwrap();
                    let request_bytes = std::fs::read(&plan.request_path).unwrap();
                    assert!(request_bytes.starts_with(crate::crypto::PRF_REQUEST_V1_DOMAIN));
                    std::fs::write(&plan.output_path, &self.raw_output).unwrap();
                    CommandOutput {
                        exit_code: Some(0),
                        stdout: String::new(),
                        stderr: String::new(),
                        error: None,
                    }
                }
                other => CommandOutput {
                    exit_code: Some(1),
                    stdout: String::new(),
                    stderr: format!("unexpected fake command: {other}"),
                    error: None,
                },
            }
        }
    }

    struct ParsedHmacInvocation {
        request_path: PathBuf,
        output_path: PathBuf,
    }

    fn parse_hmac_invocation(
        invocation: &CommandInvocation,
    ) -> Result<ParsedHmacInvocation, String> {
        let mut output_path = None;
        let mut index = 0;
        while index < invocation.args.len() {
            match invocation.args[index].as_str() {
                "-o" => {
                    index += 1;
                    output_path = invocation.args.get(index).map(PathBuf::from);
                }
                _ => {}
            }
            index += 1;
        }

        let request_path = invocation
            .args
            .last()
            .map(PathBuf::from)
            .ok_or_else(|| "missing hmac request path".to_string())?;
        let output_path = output_path.ok_or_else(|| "missing hmac output path".to_string())?;

        Ok(ParsedHmacInvocation {
            request_path,
            output_path,
        })
    }
}
