pub mod derive;
pub mod native;
pub mod prf;
pub mod seed;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use tempfile::Builder as TempfileBuilder;

use crate::backend::{CapabilityProbe, CommandOutput, CommandRunner, ProcessCommandRunner};
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, CapabilityReport, ExportArtifact, ExportFormat, ExportKind, ExportRequest,
    ExportResult, InspectRequest, Mode, ModeResolution, Profile, SetupRequest, SetupResult,
    StateLayout, UseCase,
};
use crate::ops::native::subprocess::{
    plan_export_public_key, plan_setup, NativeCommandSpec, NativeKeyLocator,
    NativePersistentHandle, NativePublicKeyExportOptions, NativeSetupArtifacts,
};
use crate::ops::native::{
    NativeAlgorithm, NativeCurve, NativeHardwareBinding, NativeKeyRef, NativeKeyUse,
    NativePrivateKeyPolicy, NativePublicKeyEncoding, NativePublicKeyExportRequest,
    NativeSetupRequest,
};
use crate::ops::prf::{
    PRF_CONTEXT_PATH_METADATA_KEY, PRF_PARENT_CONTEXT_PATH_METADATA_KEY,
    PRF_PRIVATE_PATH_METADATA_KEY, PRF_PUBLIC_PATH_METADATA_KEY, PrfRootLayout,
    SubprocessPrfBackend,
};

pub fn inspect(probe: &dyn CapabilityProbe, request: &InspectRequest) -> CapabilityReport {
    probe.detect(request.algorithm, &normalize_uses(request.uses.clone()))
}

pub fn resolve_profile(probe: &dyn CapabilityProbe, request: &SetupRequest) -> Result<SetupResult> {
    resolve_profile_with_runner(probe, request, &ProcessCommandRunner)
}

fn resolve_profile_with_runner<R>(
    probe: &dyn CapabilityProbe,
    request: &SetupRequest,
    runner: &R,
) -> Result<SetupResult>
where
    R: CommandRunner,
{
    validate_profile_name(&request.profile)?;

    let uses = normalize_uses(request.uses.clone());
    if uses.is_empty() {
        return Err(Error::Validation(
            "at least one --use value is required for setup".to_string(),
        ));
    }

    let report = probe.detect(Some(request.algorithm), &uses);
    let resolved_mode = resolve_mode(
        probe,
        request.requested_mode,
        request.algorithm,
        &uses,
        &report,
    )?;
    let reasons = if let Some(explicit) = request.requested_mode.explicit() {
        vec![format!("mode explicitly requested as {explicit:?}")]
    } else {
        report.recommendation_reasons.clone()
    };

    let state_layout = StateLayout::from_optional_root(request.state_dir.clone());
    let mut profile = Profile::new(
        request.profile.clone(),
        request.algorithm,
        uses,
        ModeResolution {
            requested: request.requested_mode,
            resolved: resolved_mode,
            reasons,
        },
        state_layout,
    );

    let persisted = if request.dry_run {
        false
    } else {
        let provisioned_dir = match profile.mode.resolved {
            Mode::Native => {
                materialize_native_setup(&mut profile, runner)?;
                None
            }
            Mode::Prf => {
                let layout = materialize_prf_setup(&mut profile, runner)?;
                Some(layout.object_dir)
            }
            Mode::Seed => None,
        };

        if let Err(error) = profile.persist() {
            if let Some(path) = provisioned_dir {
                let _ = fs::remove_dir_all(path);
            }
            return Err(error);
        }

        true
    };

    Ok(SetupResult {
        profile,
        dry_run: request.dry_run,
        persisted,
    })
}

pub fn load_profile(profile: &str, state_dir: Option<PathBuf>) -> Result<Profile> {
    validate_profile_name(profile)?;
    Profile::load_named(profile, state_dir)
}

fn apply_prf_root_metadata(profile: &mut Profile, layout: &PrfRootLayout) -> Result<()> {
    profile.metadata.insert(
        PRF_PARENT_CONTEXT_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&profile.storage.state_layout, &layout.parent_context_path)?,
    );
    profile.metadata.insert(
        PRF_PUBLIC_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&profile.storage.state_layout, &layout.public_path)?,
    );
    profile.metadata.insert(
        PRF_PRIVATE_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&profile.storage.state_layout, &layout.private_path)?,
    );
    profile.metadata.insert(
        PRF_CONTEXT_PATH_METADATA_KEY.to_string(),
        persistable_state_path(&profile.storage.state_layout, &layout.loaded_context_path)?,
    );
    Ok(())
}

fn materialize_prf_setup<R>(profile: &mut Profile, runner: &R) -> Result<PrfRootLayout>
where
    R: CommandRunner,
{
    let backend = SubprocessPrfBackend::with_runner(
        profile.storage.state_layout.objects_dir.clone(),
        runner,
    );
    let layout = backend.provision_root(&profile.name)?;
    apply_prf_root_metadata(profile, &layout)?;
    Ok(layout)
}

fn persistable_state_path(state_layout: &StateLayout, path: &Path) -> Result<String> {
    if path.starts_with(&state_layout.root_dir) {
        let relative = path.strip_prefix(&state_layout.root_dir).map_err(|error| {
            Error::State(format!(
                "failed to persist state path '{}' relative to '{}': {error}",
                path.display(),
                state_layout.root_dir.display()
            ))
        })?;
        return Ok(relative.display().to_string());
    }

    Ok(path.display().to_string())
}

pub fn export(request: &ExportRequest) -> Result<ExportResult> {
    validate_profile_name(&request.profile)?;

    let profile = load_profile(&request.profile, request.state_dir.clone())?;
    match request.kind {
        ExportKind::PublicKey => export_public_key(&profile, request.output.as_deref()),
        ExportKind::RecoveryBundle => export_recovery_bundle(&profile),
    }
}

fn export_public_key(profile: &Profile, requested_output: Option<&Path>) -> Result<ExportResult> {
    match profile.mode.resolved {
        Mode::Prf => Err(Error::PolicyRefusal(format!(
            "profile '{}' resolved to PRF mode; PRF roots do not expose a standalone public key",
            profile.name
        ))),
        Mode::Native => {
            if !profile.export_policy.public_key_export {
                return Err(Error::PolicyRefusal(format!(
                    "profile '{}' resolved to {:?} mode, which does not allow public-key export",
                    profile.name, profile.mode.resolved
                )));
            }

            export_native_public_key_with_runner(profile, requested_output, &ProcessCommandRunner)
        }
        Mode::Seed => {
            if !profile.export_policy.public_key_export {
                return Err(Error::PolicyRefusal(format!(
                    "profile '{}' resolved to {:?} mode, which does not allow public-key export",
                    profile.name, profile.mode.resolved
                )));
            }

            Err(Error::Unsupported(format!(
                "profile '{}' resolved to seed mode; export public-key is not wired in this vertical slice",
                profile.name
            )))
        }
    }
}

fn export_recovery_bundle(profile: &Profile) -> Result<ExportResult> {
    if !profile.export_policy.recovery_export {
        return Err(Error::PolicyRefusal(format!(
            "profile '{}' resolved to {:?} mode, which does not allow recovery-bundle export",
            profile.name, profile.mode.resolved
        )));
    }

    Err(Error::Unsupported(format!(
        "profile '{}' resolved to {:?} mode; recovery-bundle export is not wired in this vertical slice",
        profile.name, profile.mode.resolved
    )))
}

fn materialize_native_setup<R>(profile: &mut Profile, runner: &R) -> Result<()>
where
    R: CommandRunner,
{
    if profile.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native setup is currently wired only for P-256 profiles, got {:?}",
            profile.algorithm
        )));
    }

    let allowed_uses = native_key_uses(profile)?;
    let key_id = native_key_id(profile);
    let native_dir = native_state_dir(profile);
    let scratch_dir = native_dir.join("setup-work");
    let handle_path = native_handle_path(profile);
    let persistent_handle = allocate_native_persistent_handle(runner)?;

    profile.storage.state_layout.ensure_dirs()?;
    fs::create_dir_all(&native_dir).map_err(|error| {
        Error::State(format!(
            "failed to create native setup directory '{}': {error}",
            native_dir.display()
        ))
    })?;

    if scratch_dir.exists() {
        remove_path_if_present(&scratch_dir);
    }
    fs::create_dir_all(&scratch_dir).map_err(|error| {
        Error::State(format!(
            "failed to create native scratch directory '{}': {error}",
            scratch_dir.display()
        ))
    })?;

    let setup_request = NativeSetupRequest {
        profile: profile.name.clone(),
        key_label: Some(profile.name.clone()),
        algorithm: NativeAlgorithm::P256,
        curve: NativeCurve::NistP256,
        allowed_uses,
        hardware_binding: NativeHardwareBinding::Required,
        private_key_policy: NativePrivateKeyPolicy::NonExportable,
    };
    let plan = plan_setup(
        &setup_request,
        &NativeSetupArtifacts {
            scratch_dir: scratch_dir.clone(),
            key_id: key_id.clone(),
            persistent: NativePersistentHandle {
                handle: persistent_handle.clone(),
                serialized_handle_path: handle_path.clone(),
            },
        },
    )?;

    let execution = plan
        .commands
        .iter()
        .try_for_each(|command| run_native_command_for_operation(command, runner, "native setup"));

    for path in &plan.cleanup_paths {
        remove_path_if_present(path);
    }
    remove_path_if_present(&scratch_dir);

    execution?;

    if !handle_path.is_file() {
        return Err(Error::State(format!(
            "native setup completed without creating serialized handle state '{}'; sign/export cannot locate the TPM object",
            handle_path.display()
        )));
    }

    persist_native_metadata(profile, &key_id, &persistent_handle, &handle_path);
    Ok(())
}

fn export_native_public_key_with_runner<R>(
    profile: &Profile,
    requested_output: Option<&Path>,
    runner: &R,
) -> Result<ExportResult>
where
    R: CommandRunner,
{
    if profile.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native public-key export is currently wired only for P-256 profiles, got {:?}",
            profile.algorithm
        )));
    }

    profile.storage.state_layout.ensure_dirs()?;

    let locator = resolve_native_key_locator(profile)?;
    let tempdir = TempfileBuilder::new()
        .prefix("native-public-key-export-")
        .tempdir_in(&profile.storage.state_layout.exports_dir)
        .map_err(|error| {
            Error::State(format!(
                "failed to create native export workspace in '{}': {error}",
                profile.storage.state_layout.exports_dir.display()
            ))
        })?;

    let plan = plan_export_public_key(
        &NativePublicKeyExportRequest {
            key: NativeKeyRef {
                profile: profile.name.clone(),
                key_id: native_key_id(profile),
            },
            encodings: vec![NativePublicKeyEncoding::SpkiDer],
        },
        &NativePublicKeyExportOptions {
            locator,
            output_dir: tempdir.path().to_path_buf(),
            file_stem: profile.name.clone(),
        },
    )?;

    for command in &plan.commands {
        run_native_command_for_operation(command, runner, "native public-key export")?;
    }

    let exported = plan
        .outputs
        .iter()
        .find(|output| output.encoding == NativePublicKeyEncoding::SpkiDer)
        .ok_or_else(|| {
            Error::Internal(
                "native public-key export plan did not produce the expected SPKI DER artifact"
                    .to_string(),
            )
        })?;

    let public_key = fs::read(&exported.path).map_err(|error| {
        Error::State(format!(
            "failed to read native public key from '{}': {error}",
            exported.path.display()
        ))
    })?;

    let destination = resolve_public_key_output_path(profile, requested_output)?;
    write_public_key_output(&destination, &public_key)?;

    Ok(ExportResult {
        profile: profile.name.clone(),
        mode: profile.mode.resolved,
        kind: ExportKind::PublicKey,
        artifact: ExportArtifact {
            format: ExportFormat::SpkiDer,
            path: destination,
            bytes_written: public_key.len(),
        },
    })
}

const TPM_PERSISTENT_HANDLE_MIN: u32 = 0x8100_0000;
const TPM_PERSISTENT_HANDLE_MAX: u32 = 0x81ff_ffff;
const TPM_PERSISTENT_HANDLE_START: u32 = 0x8101_0000;

pub(crate) fn resolve_native_key_locator(profile: &Profile) -> Result<NativeKeyLocator> {
    if let Some(path) = metadata_path(
        profile,
        &[
            "native.serialized_handle_path",
            "native.serialized-handle-path",
        ],
    ) {
        return Ok(NativeKeyLocator::SerializedHandle { path });
    }

    if let Some(handle) = metadata_value(
        profile,
        &["native.persistent_handle", "native.persistent-handle"],
    ) {
        return Ok(NativeKeyLocator::PersistentHandle { handle });
    }

    for path in native_handle_path_candidates(profile) {
        if path.is_file() {
            return Ok(NativeKeyLocator::SerializedHandle { path });
        }
    }

    Err(Error::State(format!(
        "profile '{}' resolved to native mode but no serialized handle state was found; checked {}",
        profile.name,
        native_handle_path_candidates(profile)
            .into_iter()
            .map(|path| format!("'{}'", path.display()))
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn native_key_uses(profile: &Profile) -> Result<Vec<NativeKeyUse>> {
    let uses: Vec<_> = profile
        .uses
        .iter()
        .map(|use_case| match use_case {
            UseCase::Sign => Ok(NativeKeyUse::Sign),
            UseCase::Verify => Ok(NativeKeyUse::Verify),
            unsupported => Err(Error::Unsupported(format!(
                "native setup is currently wired only for sign/verify uses, but profile '{}' requested {:?}",
                profile.name, unsupported
            ))),
        })
        .collect::<Result<_>>()?;

    if uses.is_empty() {
        return Err(Error::Validation(
            "native setup requires at least one sign/verify use".to_string(),
        ));
    }

    Ok(uses)
}

fn allocate_native_persistent_handle<R>(runner: &R) -> Result<String>
where
    R: CommandRunner,
{
    let output = runner.run(&crate::backend::CommandInvocation::new(
        "tpm2_getcap",
        ["handles-persistent"],
    ));

    if output.error.is_some() {
        return Err(Error::TpmUnavailable(format!(
            "failed to discover TPM persistent handles via 'tpm2_getcap handles-persistent': {}",
            render_command_detail(&output)
        )));
    }

    if output.exit_code != Some(0) {
        return Err(Error::CapabilityMismatch(format!(
            "failed to discover TPM persistent handles via 'tpm2_getcap handles-persistent': {}",
            render_command_detail(&output)
        )));
    }

    let taken = parse_persistent_handles(&output.stdout)?;
    for candidate in TPM_PERSISTENT_HANDLE_START..=TPM_PERSISTENT_HANDLE_MAX {
        let handle = format!("0x{candidate:08x}");
        if !taken.contains(&handle) {
            return Ok(handle);
        }
    }

    Err(Error::State(
        "no free TPM persistent handles remain in the persistent-object range".to_string(),
    ))
}

fn parse_persistent_handles(stdout: &str) -> Result<BTreeSet<String>> {
    let mut handles = BTreeSet::new();

    for line in stdout.lines() {
        for token in
            line.split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | '[' | ']' | ':' | '-'))
        {
            let token = token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | ','));
            if let Some(handle) = parse_persistent_handle_token(token)? {
                handles.insert(handle);
            }
        }
    }

    Ok(handles)
}

fn parse_persistent_handle_token(token: &str) -> Result<Option<String>> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let normalized = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if normalized.len() != 8 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(None);
    }

    let value = u32::from_str_radix(normalized, 16).map_err(|error| {
        Error::State(format!(
            "failed to parse persistent handle token '{trimmed}': {error}"
        ))
    })?;
    if !(TPM_PERSISTENT_HANDLE_MIN..=TPM_PERSISTENT_HANDLE_MAX).contains(&value) {
        return Ok(None);
    }

    Ok(Some(format!("0x{value:08x}")))
}

fn persist_native_metadata(
    profile: &mut Profile,
    key_id: &str,
    persistent_handle: &str,
    handle_path: &Path,
) {
    profile
        .metadata
        .insert("native.backend".to_string(), "subprocess".to_string());
    profile
        .metadata
        .insert("native.key_id".to_string(), key_id.to_string());
    profile.metadata.insert(
        "native.locator_kind".to_string(),
        "serialized-handle".to_string(),
    );
    profile.metadata.insert(
        "native.serialized_handle_path".to_string(),
        path_for_metadata(&profile.storage.state_layout.root_dir, handle_path),
    );
    profile.metadata.insert(
        "native.persistent_handle".to_string(),
        persistent_handle.to_string(),
    );
}

fn path_for_metadata(root_dir: &Path, path: &Path) -> String {
    path.strip_prefix(root_dir)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn native_state_dir(profile: &Profile) -> PathBuf {
    profile
        .storage
        .state_layout
        .objects_dir
        .join(&profile.name)
        .join("native")
}

fn native_handle_path(profile: &Profile) -> PathBuf {
    native_state_dir(profile).join(format!("{}.handle", native_key_id(profile)))
}

fn metadata_path(profile: &Profile, keys: &[&str]) -> Option<PathBuf> {
    let value = metadata_value(profile, keys)?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(profile.storage.state_layout.root_dir.join(path))
    }
}

fn metadata_value(profile: &Profile, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| profile.metadata.get(*key).cloned())
}

fn native_handle_path_candidates(profile: &Profile) -> Vec<PathBuf> {
    let objects_dir = &profile.storage.state_layout.objects_dir;
    vec![
        native_handle_path(profile),
        objects_dir.join(format!("{}.handle", profile.name)),
        objects_dir
            .join(&profile.name)
            .join(format!("{}.handle", profile.name)),
        objects_dir.join(&profile.name).join("key.handle"),
        objects_dir.join(&profile.name).join("persistent.handle"),
    ]
}

pub(crate) fn native_key_id(profile: &Profile) -> String {
    metadata_value(profile, &["native.key_id", "native.key-id"])
        .unwrap_or_else(|| format!("{}-signing-key", profile.name))
}

fn resolve_public_key_output_path(
    profile: &Profile,
    requested_output: Option<&Path>,
) -> Result<PathBuf> {
    match requested_output {
        Some(path) if path.is_dir() => Err(Error::Validation(format!(
            "export output '{}' must be a file path, not a directory",
            path.display()
        ))),
        Some(path) => Ok(path.to_path_buf()),
        None => Ok(profile
            .storage
            .state_layout
            .exports_dir
            .join(format!("{}.public-key.spki.der", profile.name))),
    }
}

fn write_public_key_output(path: &Path, public_key: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            Error::State(format!(
                "failed to create export directory '{}': {error}",
                parent.display()
            ))
        })?;
    }

    fs::write(path, public_key).map_err(|error| {
        Error::State(format!(
            "failed to write public key export to '{}': {error}",
            path.display()
        ))
    })
}

fn remove_path_if_present(path: &Path) {
    if path.is_dir() {
        let _ = fs::remove_dir_all(path);
    } else if path.exists() {
        let _ = fs::remove_file(path);
    }
}

fn run_native_command_for_operation<R>(
    command: &NativeCommandSpec,
    runner: &R,
    operation: &str,
) -> Result<()>
where
    R: CommandRunner,
{
    let output = runner.run(&crate::backend::CommandInvocation::new(
        &command.program,
        command.args.iter().cloned(),
    ));

    if output.error.is_some() {
        return Err(Error::TpmUnavailable(format!(
            "{operation} failed while running '{} {}': {}",
            command.program,
            command.args.join(" "),
            render_command_detail(&output)
        )));
    }

    if output.exit_code != Some(0) {
        return Err(Error::CapabilityMismatch(format!(
            "{operation} failed while running '{} {}': {}",
            command.program,
            command.args.join(" "),
            render_command_detail(&output)
        )));
    }

    Ok(())
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

    if detail.is_empty() {
        "command produced no diagnostic output".to_string()
    } else {
        preview(detail)
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

fn resolve_mode(
    probe: &dyn CapabilityProbe,
    requested_mode: crate::model::ModePreference,
    algorithm: Algorithm,
    uses: &[UseCase],
    report: &CapabilityReport,
) -> Result<Mode> {
    match requested_mode.explicit() {
        Some(mode) if probe.supports_mode(algorithm, uses, mode) => Ok(mode),
        Some(mode) => Err(Error::CapabilityMismatch(format!(
            "requested mode {mode:?} is not supported for {algorithm:?} with uses {uses:?}"
        ))),
        None => report
            .recommended_mode
            .ok_or_else(|| Error::CapabilityMismatch("unable to recommend a mode".to_string())),
    }
}

fn validate_profile_name(profile: &str) -> Result<()> {
    if profile.trim().is_empty() {
        return Err(Error::Validation(
            "profile name must not be empty".to_string(),
        ));
    }

    if !profile
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(Error::Validation(
            "profile name may contain only ASCII letters, numbers, '.', '-', and '_'".to_string(),
        ));
    }

    if profile.contains("..") {
        return Err(Error::Validation(
            "profile name must not contain '..'".to_string(),
        ));
    }

    Ok(())
}

fn normalize_uses(mut uses: Vec<UseCase>) -> Vec<UseCase> {
    uses.sort();
    uses.dedup();
    uses
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::env;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::backend::{
        CapabilityProbe, CommandInvocation, CommandOutput, CommandRunner, HeuristicProbe,
    };
    use crate::model::{Diagnostic, ModePreference, NativeCapabilitySummary, TpmStatus};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "tpm2-derive-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn setup_persists_materialized_native_profile_when_not_dry_run() {
        let root_dir = unique_temp_path("setup-persist");
        let runner = FakeNativeSetupRunner::new();
        let request = SetupRequest {
            profile: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Verify, UseCase::Sign],
            requested_mode: ModePreference::Native,
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };

        let result = resolve_profile_with_runner(&HeuristicProbe, &request, &runner)
            .expect("setup should succeed");
        let profile_path = root_dir.join("profiles").join("prod-signer.json");
        let handle_path = root_dir
            .join("objects")
            .join("prod-signer")
            .join("native")
            .join("prod-signer-signing-key.handle");

        assert!(result.persisted);
        assert_eq!(result.profile.storage.profile_path, profile_path);
        assert!(profile_path.is_file());
        assert!(handle_path.is_file());
        assert_eq!(
            result.profile.metadata.get("native.key_id"),
            Some(&"prod-signer-signing-key".to_string())
        );
        assert_eq!(
            result.profile.metadata.get("native.serialized_handle_path"),
            Some(&"objects/prod-signer/native/prod-signer-signing-key.handle".to_string())
        );
        assert_eq!(
            result.profile.metadata.get("native.persistent_handle"),
            Some(&"0x81010002".to_string())
        );
        assert!(!root_dir
            .join("objects")
            .join("prod-signer")
            .join("native")
            .join("setup-work")
            .exists());

        let loaded = load_profile("prod-signer", Some(root_dir.clone())).expect("profile loads");
        assert_eq!(loaded, result.profile);
        assert_eq!(runner.calls().len(), 5);

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn setup_dry_run_does_not_touch_state() {
        let root_dir = unique_temp_path("setup-dry-run");
        let runner = FakeNativeSetupRunner::new();
        let request = SetupRequest {
            profile: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign],
            requested_mode: ModePreference::Native,
            state_dir: Some(root_dir.clone()),
            dry_run: true,
        };

        let result = resolve_profile_with_runner(&HeuristicProbe, &request, &runner)
            .expect("setup should succeed");

        assert!(!result.persisted);
        assert!(!root_dir.exists());
        assert!(runner.calls().is_empty());

        if root_dir.exists() {
            fs::remove_dir_all(root_dir).expect("temporary dry-run state should be removed");
        }
    }

    #[test]
    fn setup_prf_provisions_root_material_and_persists_relative_metadata() {
        let root_dir = unique_temp_path("setup-prf-provision");
        let request = SetupRequest {
            profile: "prf-default".to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Derive],
            requested_mode: ModePreference::Prf,
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };
        let probe = StaticCapabilityProbe::prf();
        let runner = FakePrfSetupRunner::default();

        let result = resolve_profile_with_runner(&probe, &request, &runner)
            .expect("PRF setup should succeed");
        let object_dir = root_dir.join("objects").join("prf-default");

        assert!(result.persisted);
        assert!(object_dir.join("parent.ctx").is_file());
        assert!(object_dir.join("prf-root.pub").is_file());
        assert!(object_dir.join("prf-root.priv").is_file());
        assert!(object_dir.join("prf-root.ctx").is_file());
        assert_eq!(
            result
                .profile
                .metadata
                .get(PRF_PARENT_CONTEXT_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/parent.ctx")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(PRF_PUBLIC_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/prf-root.pub")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(PRF_PRIVATE_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/prf-root.priv")
        );
        assert_eq!(
            result
                .profile
                .metadata
                .get(PRF_CONTEXT_PATH_METADATA_KEY)
                .map(String::as_str),
            Some("objects/prf-default/prf-root.ctx")
        );

        let loaded = load_profile("prf-default", Some(root_dir.clone())).expect("profile loads");
        assert_eq!(loaded.metadata, result.profile.metadata);
        assert_eq!(
            runner.recorded_programs(),
            vec!["tpm2_createprimary", "tpm2_create", "tpm2_load"]
        );

        fs::remove_dir_all(root_dir).expect("temporary prf setup state should be removed");
    }

    #[test]
    fn export_loads_profile_and_writes_native_public_key() {
        let root_dir = unique_temp_path("export-native-public-key");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let mut profile = Profile {
            schema_version: crate::model::PROFILE_SCHEMA_VERSION,
            name: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign, UseCase::Verify],
            mode: ModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            storage: crate::model::ProfileStorage {
                state_layout: state_layout.clone(),
                profile_path: state_layout.profile_path("prod-signer"),
                root_material_kind: crate::model::RootMaterialKind::NativeObject,
            },
            export_policy: crate::model::ExportPolicy::for_mode(Mode::Native),
            metadata: BTreeMap::new(),
        };

        let handle_path = state_layout
            .objects_dir
            .join("prod-signer")
            .join("native")
            .join("prod-signer-signing-key.handle");
        fs::create_dir_all(handle_path.parent().expect("handle parent")).expect("handle dir");
        fs::write(&handle_path, b"serialized-handle").expect("handle file");
        persist_native_metadata(
            &mut profile,
            "prod-signer-signing-key",
            "0x81010002",
            &handle_path,
        );
        profile.persist().expect("persist profile");

        let output_path = root_dir.join("custom").join("prod-signer.der");
        let result = export_native_public_key_with_runner(
            &profile,
            Some(output_path.as_path()),
            &FakeNativeExportRunner::success(example_spki_der()),
        )
        .expect("native export should succeed");

        assert_eq!(result.profile, "prod-signer");
        assert_eq!(result.mode, Mode::Native);
        assert_eq!(result.kind, ExportKind::PublicKey);
        assert_eq!(result.artifact.format, ExportFormat::SpkiDer);
        assert_eq!(result.artifact.path, output_path);
        assert_eq!(
            fs::read(&result.artifact.path).expect("export output"),
            example_spki_der()
        );

        fs::remove_dir_all(root_dir).expect("temporary native export state should be removed");
    }

    #[test]
    fn export_refuses_prf_public_key_requests_after_loading_profile() {
        let root_dir = unique_temp_path("export-prf-refusal");
        let profile = Profile::new(
            "prf-default".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Derive],
            ModeResolution {
                requested: ModePreference::Prf,
                resolved: Mode::Prf,
                reasons: vec!["prf requested".to_string()],
            },
            StateLayout::new(root_dir.clone()),
        );
        profile.persist().expect("persist profile");

        let error = export(&ExportRequest {
            profile: "prf-default".to_string(),
            kind: ExportKind::PublicKey,
            output: None,
            state_dir: Some(root_dir.clone()),
        })
        .expect_err("prf export should refuse");

        assert!(matches!(error, Error::PolicyRefusal(message) if message.contains("PRF mode")));

        fs::remove_dir_all(root_dir).expect("temporary prf export state should be removed");
    }

    #[derive(Clone, Default)]
    struct FakeNativeSetupRunner {
        calls: Arc<Mutex<Vec<CommandInvocation>>>,
    }

    impl FakeNativeSetupRunner {
        fn new() -> Self {
            Self::default()
        }

        fn calls(&self) -> Vec<CommandInvocation> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl CommandRunner for FakeNativeSetupRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.calls
                .lock()
                .expect("calls lock")
                .push(invocation.clone());

            match invocation.program.as_str() {
                "tpm2_getcap" => CommandOutput {
                    exit_code: Some(0),
                    stdout: "- 0x81010000\n- 0x81010001\n".to_string(),
                    stderr: String::new(),
                    error: None,
                },
                "tpm2_createprimary" => {
                    write_output_flag(invocation, "-c", b"primary-context");
                    success_output()
                }
                "tpm2_create" => {
                    write_output_flag(invocation, "-u", b"public-blob");
                    write_output_flag(invocation, "-r", b"private-blob");
                    success_output()
                }
                "tpm2_load" => {
                    write_output_flag(invocation, "-c", b"loaded-context");
                    write_output_flag(invocation, "-n", b"object-name");
                    success_output()
                }
                "tpm2_evictcontrol" => {
                    write_output_flag(invocation, "-o", b"serialized-handle");
                    success_output()
                }
                other => panic!("unexpected command {other}"),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct StaticCapabilityProbe {
        report: CapabilityReport,
    }

    impl StaticCapabilityProbe {
        fn prf() -> Self {
            Self {
                report: CapabilityReport {
                    tpm: TpmStatus {
                        present: Some(true),
                        accessible: Some(true),
                    },
                    native: NativeCapabilitySummary {
                        supported_algorithms: Vec::new(),
                        supported_uses: Vec::new(),
                    },
                    prf_available: Some(true),
                    seed_available: Some(true),
                    recommended_mode: Some(Mode::Prf),
                    recommendation_reasons: vec!["fake PRF support".to_string()],
                    diagnostics: vec![Diagnostic::info("fake-probe", "PRF is supported")],
                },
            }
        }
    }

    impl CapabilityProbe for StaticCapabilityProbe {
        fn detect(&self, _algorithm: Option<Algorithm>, _uses: &[UseCase]) -> CapabilityReport {
            self.report.clone()
        }
    }

    #[derive(Clone, Default)]
    struct FakePrfSetupRunner {
        programs: Arc<Mutex<Vec<String>>>,
    }

    impl FakePrfSetupRunner {
        fn recorded_programs(&self) -> Vec<String> {
            self.programs.lock().expect("recorded programs").clone()
        }
    }

    impl CommandRunner for FakePrfSetupRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.programs
                .lock()
                .expect("recorded programs")
                .push(invocation.program.clone());

            match invocation.program.as_str() {
                "tpm2_createprimary" => {
                    fs::write(pathbuf_arg(invocation, "-c"), b"parent-context")
                        .expect("write parent context");
                }
                "tpm2_create" => {
                    fs::write(pathbuf_arg(invocation, "-u"), b"prf-public")
                        .expect("write public blob");
                    fs::write(pathbuf_arg(invocation, "-r"), b"prf-private")
                        .expect("write private blob");
                }
                "tpm2_load" => {
                    fs::write(pathbuf_arg(invocation, "-c"), b"prf-context")
                        .expect("write loaded context");
                }
                other => {
                    return CommandOutput {
                        exit_code: Some(1),
                        stdout: String::new(),
                        stderr: format!("unexpected command: {other}"),
                        error: None,
                    };
                }
            }

            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    fn pathbuf_arg(invocation: &CommandInvocation, flag: &str) -> PathBuf {
        invocation
            .args
            .windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| PathBuf::from(&pair[1]))
            .unwrap_or_else(|| panic!("missing {flag} argument"))
    }

    #[derive(Clone)]
    struct FakeNativeExportRunner {
        der: Vec<u8>,
    }

    impl FakeNativeExportRunner {
        fn success(der: Vec<u8>) -> Self {
            Self { der }
        }
    }

    impl CommandRunner for FakeNativeExportRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            assert_eq!(invocation.program, "tpm2_readpublic");

            let output_path = invocation
                .args
                .windows(2)
                .find(|pair| pair[0] == "-o")
                .map(|pair| PathBuf::from(&pair[1]))
                .expect("-o output path");
            fs::write(output_path, &self.der).expect("fake DER output");

            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    fn write_output_flag(invocation: &CommandInvocation, flag: &str, bytes: &[u8]) {
        let output_path = invocation
            .args
            .windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| PathBuf::from(&pair[1]))
            .unwrap_or_else(|| panic!("{flag} output path"));
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).expect("output parent dir");
        }
        fs::write(output_path, bytes).expect("fake TPM output");
    }

    fn success_output() -> CommandOutput {
        CommandOutput {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            error: None,
        }
    }

    fn example_spki_der() -> Vec<u8> {
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        der.extend_from_slice(&[0x11; 32]);
        der.extend_from_slice(&[0x22; 32]);
        der
    }
}
