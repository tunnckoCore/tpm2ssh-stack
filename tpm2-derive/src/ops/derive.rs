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
use crate::model::{DeriveRequest, DeriveResult, Identity, Mode};

use super::prf::{
    PRF_CONTEXT_PATH_METADATA_KEY, PRF_PARENT_CONTEXT_PATH_METADATA_KEY,
    PRF_PRIVATE_PATH_METADATA_KEY, PRF_PUBLIC_PATH_METADATA_KEY, PrfRequest, TpmPrfExecutor,
    TpmPrfKeyHandle, execute_tpm_prf_plan_with_runner, plan_tpm_prf_in,
};
use super::seed::{
    HkdfSha256SeedDeriver, SEED_PRIVATE_BLOB_PATH_METADATA_KEY, SEED_PUBLIC_BLOB_PATH_METADATA_KEY,
    SeedBackend, SeedIdentity, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive,
    seed_profile_from_profile,
};

pub fn execute_with_defaults<R>(
    identity: &Identity,
    request: &DeriveRequest,
    prf_runner: &R,
) -> Result<DeriveResult>
where
    R: CommandRunner,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    execute_with_runner(identity, request, prf_runner, &seed_backend, &seed_deriver)
}

pub fn execute_with_runner<R, B, D>(
    identity: &Identity,
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
    // Enforce use=derive at operation dispatch time.
    if !identity.uses.contains(&crate::model::UseCase::Derive) {
        return Err(Error::PolicyRefusal(format!(
            "identity '{}' is not configured with use=derive",
            identity.name
        )));
    }

    // Enforce mode/use compatibility at operation dispatch time.
    crate::model::UseCase::validate_for_mode(&identity.uses, identity.mode.resolved)?;

    let spec = derive_spec(request)?;

    match identity.mode.resolved {
        Mode::Native => Err(Error::Unsupported(format!(
            "identity '{}' resolved to native mode; derive is currently wired only for PRF and seed identities",
            identity.name
        ))),
        Mode::Prf => execute_prf(identity, request.length, spec, prf_runner),
        Mode::Seed => execute_seed(identity, request.length, spec, seed_backend, seed_deriver),
    }
}

fn execute_prf<R>(
    identity: &Identity,
    length: u16,
    spec: DerivationSpec,
    runner: &R,
) -> Result<DeriveResult>
where
    R: CommandRunner,
{
    let executor = resolve_prf_executor(identity)?;
    let request = PrfRequest::new(identity.name.clone(), spec)?;
    let workspace_root = temporary_workspace_root("prf", &identity.name)?;
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
            identity: identity.name.clone(),
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
    identity: &Identity,
    length: u16,
    spec: DerivationSpec,
    backend: &B,
    deriver: &D,
) -> Result<DeriveResult>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_profile = seed_profile_from_profile(identity)?;
    ensure_seed_material_exists(identity, &seed_profile)?;

    let request = SeedOpenRequest {
        identity: seed_profile,
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
        identity: identity.name.clone(),
        mode: Mode::Seed,
        length,
        encoding: "hex".to_string(),
        material: hex_encode(derived.expose_secret()),
    })
}

fn derive_spec(request: &DeriveRequest) -> Result<DerivationSpec> {
    let org = request.derivation.org.clone().ok_or_else(|| {
        Error::Validation("derive currently requires --org or an identity default".to_string())
    })?;
    let purpose = request.derivation.purpose.clone().ok_or_else(|| {
        Error::Validation("derive currently requires --purpose or an identity default".to_string())
    })?;

    let mut context = CryptoDerivationContext::new(org, DerivationDomain::Application, purpose);

    for (key, value) in &request.derivation.context {
        context = context.with_field(key.clone(), value.clone());
    }

    Ok(DerivationSpec::V1(DerivationSpecV1::new(
        context,
        OutputSpec::new(OutputKind::SecretBytes, request.length)?,
    )?))
}

fn resolve_prf_executor(identity: &Identity) -> Result<TpmPrfExecutor> {
    let object_dir = identity
        .storage
        .state_layout
        .objects_dir
        .join(&identity.name);

    let metadata_parent = identity
        .metadata
        .get(PRF_PARENT_CONTEXT_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(identity, path));
    let metadata_public = identity
        .metadata
        .get(PRF_PUBLIC_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(identity, path));
    let metadata_private = identity
        .metadata
        .get(PRF_PRIVATE_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(identity, path));

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

    if let Some(context_path) = identity
        .metadata
        .get(PRF_CONTEXT_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(identity, path))
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
        "identity '{}' resolved to PRF mode but no PRF root material was found; expected metadata '{}' or loadable blobs under '{}'",
        identity.name,
        PRF_CONTEXT_PATH_METADATA_KEY,
        object_dir.display()
    )))
}

fn resolve_state_path(identity: &Identity, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        identity.storage.state_layout.root_dir.join(path)
    }
}
fn ensure_seed_material_exists(identity: &Identity, seed_profile: &SeedIdentity) -> Result<()> {
    let object_dir = identity
        .storage
        .state_layout
        .objects_dir
        .join(&seed_profile.storage.object_label);
    let public_blob = metadata_path(identity, SEED_PUBLIC_BLOB_PATH_METADATA_KEY)
        .unwrap_or_else(|| object_dir.join("sealed.pub"));
    let private_blob = metadata_path(identity, SEED_PRIVATE_BLOB_PATH_METADATA_KEY)
        .unwrap_or_else(|| object_dir.join("sealed.priv"));

    if public_blob.is_file() && private_blob.is_file() {
        return Ok(());
    }

    Err(Error::Unsupported(format!(
        "identity '{}' resolved to seed mode but no sealed seed object was found; expected '{}' and '{}'",
        identity.name,
        public_blob.display(),
        private_blob.display()
    )))
}

fn metadata_path(identity: &Identity, key: &str) -> Option<PathBuf> {
    let value = identity.metadata.get(key)?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(identity.storage.state_layout.root_dir.join(path))
    }
}

fn temporary_workspace_root(kind: &str, identity: &str) -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            Error::State(format!(
                "system clock error while creating derive workspace: {error}"
            ))
        })?;

    let sanitized_profile = identity
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
        Algorithm, DerivationOverrides, IdentityDerivationDefaults, IdentityModeResolution,
        ModePreference, StateLayout, UseCase,
    };

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn executes_prf_derive_when_loaded_context_exists() {
        let root_dir = unique_temp_path("derive-prf");
        let object_dir = root_dir.join("objects").join("prf-identity");
        fs::create_dir_all(&object_dir).expect("create object dir");
        fs::write(object_dir.join("prf-root.ctx"), b"ctx").expect("write context");

        let identity = test_profile(root_dir.clone(), "prf-identity", Mode::Prf);
        let request = test_request("prf-identity", 16);
        let runner = FakePrfRunner::new(b"raw-prf-material".to_vec());
        let seed_backend = FakeSeedBackend::default();
        let seed_deriver = FakeSeedDeriver::default();

        let result =
            execute_with_runner(&identity, &request, &runner, &seed_backend, &seed_deriver)
                .expect("prf derive should succeed");

        assert_eq!(result.mode, Mode::Prf);
        assert_eq!(result.length, 16);
        assert_eq!(hex_to_len(&result.material), 16);

        fs::remove_dir_all(root_dir).expect("remove temp dir");
    }

    #[test]
    fn executes_prf_derive_from_relative_loadable_metadata() {
        let root_dir = unique_temp_path("derive-prf-relative-loadable");
        let object_dir = root_dir.join("objects").join("prf-identity");
        fs::create_dir_all(&object_dir).expect("create object dir");
        fs::write(object_dir.join("parent.ctx"), b"parent").expect("write parent context");
        fs::write(object_dir.join("prf-root.pub"), b"pub").expect("write public blob");
        fs::write(object_dir.join("prf-root.priv"), b"priv").expect("write private blob");
        fs::write(object_dir.join("prf-root.ctx"), b"loaded").expect("write loaded context");

        let mut identity = test_profile(root_dir.clone(), "prf-identity", Mode::Prf);
        identity.metadata.insert(
            PRF_PARENT_CONTEXT_PATH_METADATA_KEY.to_string(),
            "objects/prf-identity/parent.ctx".to_string(),
        );
        identity.metadata.insert(
            PRF_PUBLIC_PATH_METADATA_KEY.to_string(),
            "objects/prf-identity/prf-root.pub".to_string(),
        );
        identity.metadata.insert(
            PRF_PRIVATE_PATH_METADATA_KEY.to_string(),
            "objects/prf-identity/prf-root.priv".to_string(),
        );
        identity.metadata.insert(
            PRF_CONTEXT_PATH_METADATA_KEY.to_string(),
            "objects/prf-identity/prf-root.ctx".to_string(),
        );

        let request = test_request("prf-identity", 16);
        let runner = FakePrfRunner::new(b"raw-prf-material".to_vec());
        let seed_backend = FakeSeedBackend::default();
        let seed_deriver = FakeSeedDeriver::default();

        let result =
            execute_with_runner(&identity, &request, &runner, &seed_backend, &seed_deriver)
                .expect("prf derive should succeed");

        assert_eq!(result.mode, Mode::Prf);
        assert_eq!(runner.recorded_programs(), vec!["tpm2_load", "tpm2_hmac"]);

        fs::remove_dir_all(root_dir).expect("remove temp dir");
    }

    #[test]
    fn reports_unsupported_when_prf_material_is_missing() {
        let root_dir = unique_temp_path("derive-prf-missing");
        let identity = test_profile(root_dir.clone(), "prf-identity", Mode::Prf);
        let request = test_request("prf-identity", 16);
        let runner = FakePrfRunner::new(b"raw-prf-material".to_vec());
        let seed_backend = FakeSeedBackend::default();
        let seed_deriver = FakeSeedDeriver::default();

        let error = execute_with_runner(&identity, &request, &runner, &seed_backend, &seed_deriver)
            .expect_err("missing PRF material should be unsupported");

        assert_eq!(error.code(), crate::error::ErrorCode::Unsupported);
        assert!(error.to_string().contains("no PRF root material was found"));
    }

    #[test]
    fn executes_seed_derive_when_sealed_object_exists() {
        let root_dir = unique_temp_path("derive-seed");
        let object_dir = root_dir.join("objects").join("seed-identity");
        fs::create_dir_all(&object_dir).expect("create object dir");
        fs::write(object_dir.join("sealed.pub"), b"pub").expect("write public blob");
        fs::write(object_dir.join("sealed.priv"), b"priv").expect("write private blob");

        let identity = test_profile(root_dir.clone(), "seed-identity", Mode::Seed);
        let request = test_request("seed-identity", 24);
        let runner = FakePrfRunner::new(b"unused".to_vec());
        let seed_backend = FakeSeedBackend::new(vec![7_u8; 32]);
        let seed_deriver = FakeSeedDeriver::new(vec![9_u8; 24]);

        let result =
            execute_with_runner(&identity, &request, &runner, &seed_backend, &seed_deriver)
                .expect("seed derive should succeed");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.length, 24);
        assert_eq!(result.material, "09".repeat(24));

        fs::remove_dir_all(root_dir).expect("remove temp dir");
    }

    fn test_profile(root_dir: PathBuf, name: &str, mode: Mode) -> Identity {
        Identity {
            schema_version: crate::model::IDENTITY_SCHEMA_VERSION,
            name: name.to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Derive],
            mode: IdentityModeResolution {
                requested: ModePreference::Auto,
                resolved: mode,
                reasons: vec!["test identity".to_string()],
            },
            defaults: IdentityDerivationDefaults::default(),
            storage: crate::model::IdentityStorage {
                state_layout: StateLayout::new(root_dir),
                identity_path: PathBuf::new(),
                root_material_kind: crate::model::RootMaterialKind::for_mode(mode),
            },
            export_policy: crate::model::ExportPolicy::for_mode(mode),
            metadata: BTreeMap::new(),
        }
    }

    fn test_request(identity: &str, length: u16) -> DeriveRequest {
        DeriveRequest {
            identity: identity.to_string(),
            derivation: DerivationOverrides {
                org: Some("io.github.example".to_string()),
                purpose: Some("session-secret".to_string()),
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
            _profile: &SeedIdentity,
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

    // ── enforcement tests ──────────────────────────────────────────────

    #[test]
    fn derive_fails_when_profile_lacks_derive_use() {
        let root_dir = unique_temp_path("derive-no-use");
        let object_dir = root_dir.join("objects").join("no-derive");
        fs::create_dir_all(&object_dir).expect("create object dir");
        fs::write(object_dir.join("sealed.pub"), b"pub").expect("pub");
        fs::write(object_dir.join("sealed.priv"), b"priv").expect("priv");

        // Identity with only SshAgent, not Derive
        let mut identity = test_profile(root_dir.clone(), "no-derive", Mode::Seed);
        identity.uses = vec![UseCase::Ssh];

        let request = test_request("no-derive", 16);
        let runner = FakePrfRunner::new(b"unused".to_vec());
        let seed_backend = FakeSeedBackend::new(vec![7_u8; 32]);
        let seed_deriver = FakeSeedDeriver::new(vec![9_u8; 16]);

        let error = execute_with_runner(&identity, &request, &runner, &seed_backend, &seed_deriver)
            .expect_err("derive should fail without use=derive");

        assert_eq!(error.code(), crate::error::ErrorCode::PolicyRefusal);
        assert!(error.to_string().contains("not configured with use=derive"));

        let _ = fs::remove_dir_all(root_dir);
    }

    #[test]
    fn derive_fails_for_native_mode_profile() {
        let root_dir = unique_temp_path("derive-native-enforcement");
        // Identity with derive + native mode should fail mode/use enforcement
        let mut identity = test_profile(root_dir.clone(), "native-derive", Mode::Native);
        identity.uses = vec![UseCase::Derive];

        let request = test_request("native-derive", 16);
        let runner = FakePrfRunner::new(b"unused".to_vec());
        let seed_backend = FakeSeedBackend::default();
        let seed_deriver = FakeSeedDeriver::default();

        let error = execute_with_runner(&identity, &request, &runner, &seed_backend, &seed_deriver)
            .expect_err("native mode should refuse derive");

        assert_eq!(error.code(), crate::error::ErrorCode::PolicyRefusal);
        assert!(error.to_string().contains("not allowed in Native mode"));

        let _ = fs::remove_dir_all(root_dir);
    }

    #[test]
    fn derive_succeeds_for_prf_mode_with_derive_use() {
        let root_dir = unique_temp_path("derive-prf-ok");
        let object_dir = root_dir.join("objects").join("prf-ok");
        fs::create_dir_all(&object_dir).expect("create object dir");
        fs::write(object_dir.join("prf-root.ctx"), b"ctx").expect("write context");

        let identity = test_profile(root_dir.clone(), "prf-ok", Mode::Prf);
        let request = test_request("prf-ok", 16);
        let runner = FakePrfRunner::new(b"raw-prf-material".to_vec());
        let seed_backend = FakeSeedBackend::default();
        let seed_deriver = FakeSeedDeriver::default();

        let result =
            execute_with_runner(&identity, &request, &runner, &seed_backend, &seed_deriver)
                .expect("prf + derive should succeed");

        assert_eq!(result.mode, Mode::Prf);

        let _ = fs::remove_dir_all(root_dir);
    }

    #[test]
    fn derive_fails_for_prf_mode_with_sign_use() {
        let root_dir = unique_temp_path("derive-prf-sign");
        let mut identity = test_profile(root_dir.clone(), "prf-sign", Mode::Prf);
        identity.uses = vec![UseCase::Sign];

        let request = test_request("prf-sign", 16);
        let runner = FakePrfRunner::new(b"unused".to_vec());
        let seed_backend = FakeSeedBackend::default();
        let seed_deriver = FakeSeedDeriver::default();

        let error = execute_with_runner(&identity, &request, &runner, &seed_backend, &seed_deriver)
            .expect_err("prf + sign should fail derive");

        // First error: missing use=derive
        assert_eq!(error.code(), crate::error::ErrorCode::PolicyRefusal);
        assert!(error.to_string().contains("not configured with use=derive"));

        let _ = fs::remove_dir_all(root_dir);
    }
}
