use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::ExposeSecret;

use crate::backend::CommandRunner;
use crate::crypto::{
    DerivationContext as CryptoDerivationContext, DerivationDomain, DerivationSpec,
    DerivationSpecV1, OutputKind, OutputSpec,
};
use crate::error::{Error, Result};
use crate::model::{DeriveRequest, DeriveResult, Mode, Profile};

use super::prf::{
    PRF_CONTEXT_PATH_METADATA_KEY, PRF_PARENT_CONTEXT_PATH_METADATA_KEY,
    PRF_PRIVATE_PATH_METADATA_KEY, PRF_PUBLIC_PATH_METADATA_KEY, PrfRequest, TpmPrfExecutor,
    TpmPrfKeyHandle, execute_tpm_prf_plan_with_runner, plan_tpm_prf_in,
};
use super::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedProfile, SeedSoftwareDeriver, SoftwareSeedDerivationRequest, open_and_derive,
    seed_profile_from_profile,
};


pub fn execute_with_defaults<R>(
    profile: &Profile,
    request: &DeriveRequest,
    prf_runner: &R,
) -> Result<DeriveResult>
where
    R: CommandRunner,
{
    let seed_backend = super::seed::ScaffoldSeedBackend::default();
    let seed_deriver = HkdfSha256SeedDeriver;
    execute_with_runner(profile, request, prf_runner, &seed_backend, &seed_deriver)
}

pub fn execute_with_runner<R, B, D>(
    profile: &Profile,
    request: &DeriveRequest,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<DeriveResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let spec = derive_spec(request)?;

    match profile.mode.resolved {
        Mode::Native => Err(Error::Unsupported(format!(
            "profile '{}' resolved to native mode; derive is currently wired only for PRF and seed profiles",
            profile.name
        ))),
        Mode::Prf => execute_prf(profile, request.length, spec, prf_runner),
        Mode::Seed => execute_seed(profile, request.length, spec, seed_backend, seed_deriver),
    }
}

fn execute_prf<R>(
    profile: &Profile,
    length: u16,
    spec: DerivationSpec,
    runner: &R,
) -> Result<DeriveResult>
where
    R: CommandRunner,
{
    let executor = resolve_prf_executor(profile)?;
    let request = PrfRequest::new(profile.name.clone(), spec)?;
    let workspace_root = temporary_workspace_root("prf", &profile.name)?;
    let plan = plan_tpm_prf_in(request, executor, &workspace_root)?;
    let execution = execute_tpm_prf_plan_with_runner(&plan, runner);
    let cleanup = fs::remove_dir_all(&workspace_root).map_err(|error| {
        Error::State(format!(
            "failed to remove derive workspace '{}': {error}",
            workspace_root.display()
        ))
    });

    match (execution, cleanup) {
        (Ok(result), Ok(())) => Ok(DeriveResult {
            profile: profile.name.clone(),
            mode: Mode::Prf,
            length,
            encoding: "hex".to_string(),
            material: hex_encode(result.response.output.expose_secret()),
        }),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn execute_seed<B, D>(
    profile: &Profile,
    length: u16,
    spec: DerivationSpec,
    backend: &B,
    deriver: &D,
) -> Result<DeriveResult>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_profile = seed_profile_from_profile(profile)?;
    ensure_seed_material_exists(profile, &seed_profile)?;

    let request = SeedOpenRequest {
        profile: seed_profile,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
            spec,
            output_bytes: usize::from(length),
        }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    };

    let derived = open_and_derive(backend, deriver, &request)?;
    Ok(DeriveResult {
        profile: profile.name.clone(),
        mode: Mode::Seed,
        length,
        encoding: "hex".to_string(),
        material: hex_encode(derived.expose_secret()),
    })
}

fn derive_spec(request: &DeriveRequest) -> Result<DerivationSpec> {
    let mut context = CryptoDerivationContext::new(
        request.context.namespace.clone(),
        DerivationDomain::Application,
        request.context.purpose.clone(),
    );

    if let Some(label) = &request.context.label {
        context = context.with_label(label.clone());
    }

    for (key, value) in &request.context.context {
        context = context.with_field(key.clone(), value.clone());
    }

    Ok(DerivationSpec::V1(DerivationSpecV1::new(
        context,
        OutputSpec::new(OutputKind::SecretBytes, request.length)?,
    )?))
}

fn resolve_prf_executor(profile: &Profile) -> Result<TpmPrfExecutor> {
    let object_dir = profile.storage.state_layout.objects_dir.join(&profile.name);

    let metadata_parent = profile
        .metadata
        .get(PRF_PARENT_CONTEXT_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(profile, path));
    let metadata_public = profile
        .metadata
        .get(PRF_PUBLIC_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(profile, path));
    let metadata_private = profile
        .metadata
        .get(PRF_PRIVATE_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(profile, path));

    if let (Some(parent_context_path), Some(public_path), Some(private_path)) =
        (metadata_parent, metadata_public, metadata_private)
    {
        return Ok(TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadableObject {
            parent_context_path,
            public_path,
            private_path,
        }));
    }

    for (parent, public, private) in [
        ("parent.ctx", "prf-root.pub", "prf-root.priv"),
        ("parent.ctx", "root.pub", "root.priv"),
    ] {
        let parent_context_path = object_dir.join(parent);
        let public_path = object_dir.join(public);
        let private_path = object_dir.join(private);
        if parent_context_path.is_file() && public_path.is_file() && private_path.is_file() {
            return Ok(TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadableObject {
                parent_context_path,
                public_path,
                private_path,
            }));
        }
    }

    if let Some(context_path) = profile
        .metadata
        .get(PRF_CONTEXT_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(profile, path))
    {
        return Ok(TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadedContext {
            context_path,
        }));
    }

    for file_name in ["prf-root.ctx", "root.ctx", "key.ctx"] {
        let candidate = object_dir.join(file_name);
        if candidate.is_file() {
            return Ok(TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadedContext {
                context_path: candidate,
            }));
        }
    }

    Err(Error::Unsupported(format!(
        "profile '{}' resolved to PRF mode but no PRF root material was found; expected metadata '{}' or loadable blobs under '{}'",
        profile.name,
        PRF_CONTEXT_PATH_METADATA_KEY,
        object_dir.display()
    )))
}

fn resolve_state_path(profile: &Profile, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        profile.storage.state_layout.root_dir.join(path)
    }
}
fn ensure_seed_material_exists(profile: &Profile, seed_profile: &SeedProfile) -> Result<()> {
    let object_dir = profile
        .storage
        .state_layout
        .objects_dir
        .join(&seed_profile.storage.object_label);
    let public_blob = object_dir.join("sealed.pub");
    let private_blob = object_dir.join("sealed.priv");

    if public_blob.is_file() && private_blob.is_file() {
        return Ok(());
    }

    Err(Error::Unsupported(format!(
        "profile '{}' resolved to seed mode but no sealed seed object was found; expected '{}' and '{}'",
        profile.name,
        public_blob.display(),
        private_blob.display()
    )))
}

fn temporary_workspace_root(kind: &str, profile: &str) -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            Error::State(format!(
                "system clock error while creating derive workspace: {error}"
            ))
        })?;

    let sanitized_profile = profile
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();

    Ok(std::env::temp_dir().join(format!(
        "tpm2-derive-{kind}-{}-{sanitized_profile}-{}",
        std::process::id(),
        now.as_nanos()
    )))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::env;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use secrecy::SecretBox;

    use super::*;
    use crate::backend::{CommandInvocation, CommandOutput};
    use crate::model::{
        Algorithm, DerivationContext, ModePreference, ModeResolution, StateLayout, UseCase,
    };

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn executes_prf_derive_when_loaded_context_exists() {
        let root_dir = unique_temp_path("derive-prf");
        let object_dir = root_dir.join("objects").join("prf-profile");
        fs::create_dir_all(&object_dir).expect("create object dir");
        fs::write(object_dir.join("prf-root.ctx"), b"ctx").expect("write context");

        let profile = test_profile(root_dir.clone(), "prf-profile", Mode::Prf);
        let request = test_request("prf-profile", 16);
        let runner = FakePrfRunner::new(b"raw-prf-material".to_vec());
        let seed_backend = FakeSeedBackend::default();
        let seed_deriver = FakeSeedDeriver::default();

        let result = execute_with_runner(&profile, &request, &runner, &seed_backend, &seed_deriver)
            .expect("prf derive should succeed");

        assert_eq!(result.mode, Mode::Prf);
        assert_eq!(result.length, 16);
        assert_eq!(hex_to_len(&result.material), 16);

        fs::remove_dir_all(root_dir).expect("remove temp dir");
    }

    #[test]
    fn executes_prf_derive_from_relative_loadable_metadata() {
        let root_dir = unique_temp_path("derive-prf-relative-loadable");
        let object_dir = root_dir.join("objects").join("prf-profile");
        fs::create_dir_all(&object_dir).expect("create object dir");
        fs::write(object_dir.join("parent.ctx"), b"parent").expect("write parent context");
        fs::write(object_dir.join("prf-root.pub"), b"pub").expect("write public blob");
        fs::write(object_dir.join("prf-root.priv"), b"priv").expect("write private blob");
        fs::write(object_dir.join("prf-root.ctx"), b"loaded").expect("write loaded context");

        let mut profile = test_profile(root_dir.clone(), "prf-profile", Mode::Prf);
        profile.metadata.insert(
            PRF_PARENT_CONTEXT_PATH_METADATA_KEY.to_string(),
            "objects/prf-profile/parent.ctx".to_string(),
        );
        profile.metadata.insert(
            PRF_PUBLIC_PATH_METADATA_KEY.to_string(),
            "objects/prf-profile/prf-root.pub".to_string(),
        );
        profile.metadata.insert(
            PRF_PRIVATE_PATH_METADATA_KEY.to_string(),
            "objects/prf-profile/prf-root.priv".to_string(),
        );
        profile.metadata.insert(
            PRF_CONTEXT_PATH_METADATA_KEY.to_string(),
            "objects/prf-profile/prf-root.ctx".to_string(),
        );

        let request = test_request("prf-profile", 16);
        let runner = FakePrfRunner::new(b"raw-prf-material".to_vec());
        let seed_backend = FakeSeedBackend::default();
        let seed_deriver = FakeSeedDeriver::default();

        let result = execute_with_runner(&profile, &request, &runner, &seed_backend, &seed_deriver)
            .expect("prf derive should succeed");

        assert_eq!(result.mode, Mode::Prf);
        assert_eq!(runner.recorded_programs(), vec!["tpm2_load", "tpm2_hmac"]);

        fs::remove_dir_all(root_dir).expect("remove temp dir");
    }

    #[test]
    fn reports_unsupported_when_prf_material_is_missing() {
        let root_dir = unique_temp_path("derive-prf-missing");
        let profile = test_profile(root_dir.clone(), "prf-profile", Mode::Prf);
        let request = test_request("prf-profile", 16);
        let runner = FakePrfRunner::new(b"raw-prf-material".to_vec());
        let seed_backend = FakeSeedBackend::default();
        let seed_deriver = FakeSeedDeriver::default();

        let error = execute_with_runner(&profile, &request, &runner, &seed_backend, &seed_deriver)
            .expect_err("missing PRF material should be unsupported");

        assert_eq!(error.code(), crate::error::ErrorCode::Unsupported);
        assert!(error.to_string().contains("no PRF root material was found"));
    }

    #[test]
    fn executes_seed_derive_when_sealed_object_exists() {
        let root_dir = unique_temp_path("derive-seed");
        let object_dir = root_dir.join("objects").join("seed-profile");
        fs::create_dir_all(&object_dir).expect("create object dir");
        fs::write(object_dir.join("sealed.pub"), b"pub").expect("write public blob");
        fs::write(object_dir.join("sealed.priv"), b"priv").expect("write private blob");

        let profile = test_profile(root_dir.clone(), "seed-profile", Mode::Seed);
        let request = test_request("seed-profile", 24);
        let runner = FakePrfRunner::new(b"unused".to_vec());
        let seed_backend = FakeSeedBackend::new(vec![7_u8; 32]);
        let seed_deriver = FakeSeedDeriver::new(vec![9_u8; 24]);

        let result = execute_with_runner(&profile, &request, &runner, &seed_backend, &seed_deriver)
            .expect("seed derive should succeed");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.length, 24);
        assert_eq!(result.material, "09".repeat(24));

        fs::remove_dir_all(root_dir).expect("remove temp dir");
    }

    fn test_profile(root_dir: PathBuf, name: &str, mode: Mode) -> Profile {
        Profile {
            schema_version: crate::model::PROFILE_SCHEMA_VERSION,
            name: name.to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Derive],
            mode: ModeResolution {
                requested: ModePreference::Auto,
                resolved: mode,
                reasons: vec!["test profile".to_string()],
            },
            storage: crate::model::ProfileStorage {
                state_layout: StateLayout::new(root_dir),
                profile_path: PathBuf::new(),
                root_material_kind: crate::model::RootMaterialKind::for_mode(mode),
            },
            export_policy: crate::model::ExportPolicy::for_mode(mode),
            metadata: BTreeMap::new(),
        }
    }

    fn test_request(profile: &str, length: u16) -> DeriveRequest {
        DeriveRequest {
            profile: profile.to_string(),
            context: DerivationContext {
                version: 1,
                purpose: "session-secret".to_string(),
                namespace: "io.github.example".to_string(),
                label: Some("primary".to_string()),
                context: BTreeMap::from([("tenant".to_string(), "alpha".to_string())]),
            },
            length,
        }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "tpm2-derive-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn hex_to_len(hex: &str) -> usize {
        hex.len() / 2
    }

    #[derive(Clone)]
    struct FakePrfRunner {
        raw_output: Vec<u8>,
        invocations: Arc<Mutex<Vec<CommandInvocation>>>,
    }

    impl FakePrfRunner {
        fn new(raw_output: Vec<u8>) -> Self {
            Self {
                raw_output,
                invocations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn recorded_programs(&self) -> Vec<String> {
            self.invocations
                .lock()
                .expect("lock invocations")
                .iter()
                .map(|invocation| invocation.program.clone())
                .collect()
        }
    }

    impl CommandRunner for FakePrfRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.invocations
                .lock()
                .expect("lock invocations")
                .push(invocation.clone());

            if invocation.program != "tpm2_hmac" {
                return CommandOutput {
                    exit_code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                    error: None,
                };
            }

            let mut output_path = None;
            let mut index = 0;
            while index < invocation.args.len() {
                if invocation.args[index] == "-o" {
                    output_path = invocation.args.get(index + 1).map(PathBuf::from);
                    break;
                }
                index += 1;
            }

            fs::write(
                output_path.expect("output path configured"),
                &self.raw_output,
            )
            .expect("write raw output");

            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    #[derive(Default)]
    struct FakeSeedBackend {
        seed: Vec<u8>,
    }

    impl FakeSeedBackend {
        fn new(seed: Vec<u8>) -> Self {
            Self { seed }
        }
    }

    impl SeedBackend for FakeSeedBackend {
        fn seal_seed(&self, _request: &super::super::seed::SeedCreateRequest) -> Result<()> {
            unreachable!("seed sealing is not used in derive tests")
        }

        fn unseal_seed(
            &self,
            _profile: &SeedProfile,
            _auth_source: &SeedOpenAuthSource,
        ) -> Result<super::super::seed::SeedMaterial> {
            Ok(SecretBox::new(Box::new(self.seed.clone())))
        }
    }

    #[derive(Default)]
    struct FakeSeedDeriver {
        derived: Vec<u8>,
    }

    impl FakeSeedDeriver {
        fn new(derived: Vec<u8>) -> Self {
            Self { derived }
        }
    }

    impl SeedSoftwareDeriver for FakeSeedDeriver {
        fn derive(
            &self,
            _seed: &super::super::seed::SeedMaterial,
            _request: &SoftwareSeedDerivationRequest,
        ) -> Result<super::super::seed::SeedMaterial> {
            Ok(SecretBox::new(Box::new(self.derived.clone())))
        }
    }
}
