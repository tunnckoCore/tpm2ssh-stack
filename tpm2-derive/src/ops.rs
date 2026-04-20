pub mod derive;
pub mod native;
pub mod prf;
pub mod seed;

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
    NativeCommandSpec, NativeKeyLocator, NativePublicKeyExportOptions, plan_export_public_key,
};
use crate::ops::native::{
    NativeKeyRef, NativePublicKeyEncoding, NativePublicKeyExportRequest,
};

pub fn inspect(probe: &dyn CapabilityProbe, request: &InspectRequest) -> CapabilityReport {
    probe.detect(request.algorithm, &normalize_uses(request.uses.clone()))
}

pub fn resolve_profile(probe: &dyn CapabilityProbe, request: &SetupRequest) -> Result<SetupResult> {
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
    let profile = Profile::new(
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
        profile.persist()?;
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
        run_native_command(command, runner)?;
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

fn resolve_native_key_locator(profile: &Profile) -> Result<NativeKeyLocator> {
    if let Some(path) = metadata_path(profile, &["native.serialized_handle_path", "native.serialized-handle-path"]) {
        return Ok(NativeKeyLocator::SerializedHandle { path });
    }

    if let Some(handle) = metadata_value(profile, &["native.persistent_handle", "native.persistent-handle"]) {
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
        objects_dir.join(format!("{}.handle", profile.name)),
        objects_dir.join(&profile.name).join(format!("{}.handle", profile.name)),
        objects_dir.join(&profile.name).join("key.handle"),
        objects_dir.join(&profile.name).join("persistent.handle"),
    ]
}

fn native_key_id(profile: &Profile) -> String {
    metadata_value(profile, &["native.key_id", "native.key-id"]).unwrap_or_else(|| profile.name.clone())
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
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
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

fn run_native_command<R>(command: &NativeCommandSpec, runner: &R) -> Result<()>
where
    R: CommandRunner,
{
    let output = runner.run(&crate::backend::CommandInvocation::new(
        &command.program,
        command.args.iter().cloned(),
    ));

    if output.error.is_some() {
        return Err(Error::TpmUnavailable(format!(
            "native public-key export failed while running '{} {}': {}",
            command.program,
            command.args.join(" "),
            render_command_detail(&output)
        )));
    }

    if output.exit_code != Some(0) {
        return Err(Error::CapabilityMismatch(format!(
            "native public-key export failed while running '{} {}': {}",
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

    use crate::backend::{CommandInvocation, CommandOutput, CommandRunner, HeuristicProbe};
    use crate::model::ModePreference;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "tpm2-derive-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn setup_persists_profile_when_not_dry_run() {
        let root_dir = unique_temp_path("setup-persist");
        let request = SetupRequest {
            profile: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Verify, UseCase::Sign],
            requested_mode: ModePreference::Auto,
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };

        let result = resolve_profile(&HeuristicProbe, &request).expect("setup should succeed");
        let profile_path = root_dir.join("profiles").join("prod-signer.json");

        assert!(result.persisted);
        assert_eq!(result.profile.storage.profile_path, profile_path);
        assert!(profile_path.is_file());

        let loaded = load_profile("prod-signer", Some(root_dir.clone())).expect("profile loads");
        assert_eq!(loaded, result.profile);

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn setup_dry_run_does_not_touch_state() {
        let root_dir = unique_temp_path("setup-dry-run");
        let request = SetupRequest {
            profile: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign],
            requested_mode: ModePreference::Auto,
            state_dir: Some(root_dir.clone()),
            dry_run: true,
        };

        let result = resolve_profile(&HeuristicProbe, &request).expect("setup should succeed");

        assert!(!result.persisted);
        assert!(!root_dir.exists());

        if root_dir.exists() {
            fs::remove_dir_all(root_dir).expect("temporary dry-run state should be removed");
        }
    }

    #[test]
    fn export_loads_profile_and_writes_native_public_key() {
        let root_dir = unique_temp_path("export-native-public-key");
        let state_layout = StateLayout::new(root_dir.clone());
        state_layout.ensure_dirs().expect("state dirs");

        let profile = Profile {
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
        profile.persist().expect("persist profile");

        let handle_path = state_layout.objects_dir.join("prod-signer.handle");
        fs::write(&handle_path, b"serialized-handle").expect("handle file");

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
        assert_eq!(fs::read(&result.artifact.path).expect("export output"), example_spki_der());

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

    fn example_spki_der() -> Vec<u8> {
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            0x04,
        ];
        der.extend_from_slice(&[0x11; 32]);
        der.extend_from_slice(&[0x22; 32]);
        der
    }
}
