//! Keygen: derive a keypair (secret key + public key) from a persisted identity.
//!
//! This is architecture-specific keygen tied to our tpm2-derive system, NOT a
//! general-purpose keygen. The command derives key material internally from the
//! identity, then produces an algorithm-appropriate keypair.
//!
//! - **seed** mode: unseal seed, HKDF-derive a child key, produce keypair.
//! - **prf** mode: invoke TPM PRF, HKDF-expand output, produce keypair.
//! - **native** mode: unsupported (native keys live inside the TPM).

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use secrecy::ExposeSecret;
use sha2::{Digest as _, Sha256};

use crate::backend::CommandRunner;
use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};
use crate::error::{Error, Result};
use crate::model::{Algorithm, Identity, KeygenResult, Mode};

use super::prf::{
    PRF_CONTEXT_PATH_METADATA_KEY, PRF_PARENT_CONTEXT_PATH_METADATA_KEY,
    PRF_PRIVATE_PATH_METADATA_KEY, PRF_PUBLIC_PATH_METADATA_KEY, PrfRequest, TpmPrfExecutor,
    TpmPrfKeyHandle, execute_tpm_prf_plan_with_runner, plan_tpm_prf_in,
};
use super::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive,
    seed_profile_from_profile,
};

const KEYGEN_CHILD_KEY_NAMESPACE: &str = "tpm2-derive.keygen";
const KEYGEN_CHILD_KEY_PATH: &str = "m/keypair/default";
const KEYGEN_SCALAR_RETRY_DOMAIN: &[u8] = b"tpm2-derive\0keygen-scalar-retry\0v1";
const KEYGEN_SCALAR_RETRY_LIMIT: u32 = 16;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn execute_with_defaults<R>(identity: &Identity, prf_runner: &R) -> Result<KeygenResult>
where
    R: CommandRunner,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    execute(identity, prf_runner, &seed_backend, &seed_deriver)
}

pub fn execute<R, B, D>(
    identity: &Identity,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<KeygenResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let derived_bytes = derive_keygen_material(identity, prf_runner, seed_backend, seed_deriver)?;
    let (secret_key_hex, public_key_hex) = keypair_from_material(identity, &derived_bytes)?;

    Ok(KeygenResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        secret_key_hex,
        public_key_hex,
        output_path: None,
    })
}

// ---------------------------------------------------------------------------
// Key material derivation – mode dispatch
// ---------------------------------------------------------------------------

fn derive_keygen_material<R, B, D>(
    identity: &Identity,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<Vec<u8>>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    match identity.mode.resolved {
        Mode::Native => Err(Error::Unsupported(
            "keygen is not supported for native-mode identities; native keys live inside the TPM \
             and cannot be exported – use a seed or prf identity instead"
                .to_string(),
        )),
        Mode::Seed => derive_seed_keygen_material(identity, seed_backend, seed_deriver),
        Mode::Prf => derive_prf_keygen_material(identity, prf_runner),
    }
}

fn derive_seed_keygen_material<B, D>(
    identity: &Identity,
    backend: &B,
    deriver: &D,
) -> Result<Vec<u8>>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_profile = seed_profile_from_profile(identity)?;
    let spec = keygen_derivation_spec(identity.algorithm)?;
    let request = SeedOpenRequest {
        identity: seed_profile,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
            spec,
            output_bytes: 32,
        }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    };

    let derived = open_and_derive(backend, deriver, &request)?;
    Ok(derived.expose_secret().to_vec())
}

fn derive_prf_keygen_material<R>(identity: &Identity, runner: &R) -> Result<Vec<u8>>
where
    R: CommandRunner,
{
    let executor = resolve_prf_executor(identity)?;
    let spec = keygen_derivation_spec(identity.algorithm)?;
    let request = PrfRequest::new(identity.name.clone(), spec.clone())?;
    let workspace_root = temporary_workspace_root("keygen", &identity.name)?;
    let plan = plan_tpm_prf_in(request, executor, &workspace_root)?;
    let execution = execute_tpm_prf_plan_with_runner(&plan, runner);
    let _ = std::fs::remove_dir_all(&workspace_root);

    let result = execution?;
    let derived = spec.derive_output(result.response.output.expose_secret())?;
    Ok(derived.expose_secret().to_vec())
}

// ---------------------------------------------------------------------------
// Keypair construction from derived material
// ---------------------------------------------------------------------------

fn keypair_from_material(identity: &Identity, derived: &[u8]) -> Result<(String, String)> {
    match identity.algorithm {
        Algorithm::Ed25519 => ed25519_keypair(derived),
        Algorithm::P256 => p256_keypair(identity, derived),
        Algorithm::Secp256k1 => secp256k1_keypair(identity, derived),
    }
}

fn ed25519_keypair(derived: &[u8]) -> Result<(String, String)> {
    let seed: [u8; 32] = derived.try_into().map_err(|_| {
        Error::Internal(format!(
            "keygen ed25519 derivation produced {} bytes instead of 32",
            derived.len()
        ))
    })?;
    let signing_key = Ed25519SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key();

    Ok((hex_encode(&seed), hex_encode(public_key.as_bytes())))
}

fn p256_keypair(identity: &Identity, derived: &[u8]) -> Result<(String, String)> {
    let scalar = valid_ec_scalar(identity, derived, |c| {
        p256::SecretKey::from_slice(c).is_ok()
    })?;
    let sk = p256::SecretKey::from_slice(&scalar)
        .map_err(|e| Error::Internal(format!("keygen p256 scalar materialization failed: {e}")))?;
    let pk = sk.public_key();
    let pk_bytes = p256::pkcs8::EncodePublicKey::to_public_key_der(&pk)
        .map_err(|e| Error::Internal(format!("keygen p256 public key encoding failed: {e}")))?;

    Ok((hex_encode(&scalar), hex_encode(pk_bytes.as_bytes())))
}

fn secp256k1_keypair(identity: &Identity, derived: &[u8]) -> Result<(String, String)> {
    let scalar = valid_ec_scalar(identity, derived, |c| {
        k256::SecretKey::from_slice(c).is_ok()
    })?;
    let sk = k256::SecretKey::from_slice(&scalar).map_err(|e| {
        Error::Internal(format!(
            "keygen secp256k1 scalar materialization failed: {e}"
        ))
    })?;
    let pk = sk.public_key();
    let pk_bytes = k256::pkcs8::EncodePublicKey::to_public_key_der(&pk).map_err(|e| {
        Error::Internal(format!("keygen secp256k1 public key encoding failed: {e}"))
    })?;

    Ok((hex_encode(&scalar), hex_encode(pk_bytes.as_bytes())))
}

fn valid_ec_scalar<F>(identity: &Identity, derived: &[u8], is_valid: F) -> Result<[u8; 32]>
where
    F: Fn(&[u8]) -> bool,
{
    let seed: [u8; 32] = derived.try_into().map_err(|_| {
        Error::Internal(format!(
            "keygen EC derivation produced {} bytes instead of 32",
            derived.len()
        ))
    })?;
    if is_valid(&seed) {
        return Ok(seed);
    }

    for counter in 1..=KEYGEN_SCALAR_RETRY_LIMIT {
        let candidate = scalar_retry_bytes(&seed, identity.algorithm, counter);
        if is_valid(&candidate) {
            return Ok(candidate);
        }
    }

    Err(Error::Internal(format!(
        "keygen could not produce a valid {:?} scalar for identity '{}' after {} retries",
        identity.algorithm, identity.name, KEYGEN_SCALAR_RETRY_LIMIT
    )))
}

fn scalar_retry_bytes(seed: &[u8; 32], algorithm: Algorithm, counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEYGEN_SCALAR_RETRY_DOMAIN);
    hasher.update(match algorithm {
        Algorithm::Ed25519 => b"ed25519".as_slice(),
        Algorithm::Secp256k1 => b"secp256k1".as_slice(),
        Algorithm::P256 => b"p256".as_slice(),
    });
    hasher.update(counter.to_be_bytes());
    hasher.update(seed);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn keygen_derivation_spec(algorithm: Algorithm) -> Result<DerivationSpec> {
    let (algo_name, output_kind) = match algorithm {
        Algorithm::Ed25519 => ("ed25519", OutputKind::Ed25519Seed),
        Algorithm::P256 => ("p256", OutputKind::P256Scalar),
        Algorithm::Secp256k1 => ("secp256k1", OutputKind::Secp256k1Scalar),
    };

    Ok(DerivationSpec::V1(DerivationSpecV1::software_child_key(
        KEYGEN_CHILD_KEY_NAMESPACE,
        algo_name,
        KEYGEN_CHILD_KEY_PATH,
        output_kind,
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
        "identity '{}' resolved to PRF mode but no PRF root material was found for keygen",
        identity.name
    )))
}

fn resolve_state_path(identity: &Identity, value: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        identity.storage.state_layout.root_dir.join(path)
    }
}

fn temporary_workspace_root(kind: &str, identity: &str) -> Result<std::path::PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::State(format!("system clock error: {e}")))?;
    let sanitized = identity
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();
    Ok(std::env::temp_dir().join(format!(
        "tpm2-derive-{kind}-{}-{sanitized}-{}",
        std::process::id(),
        now.as_nanos()
    )))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use secrecy::SecretBox;

    use super::*;
    use crate::backend::{CommandInvocation, CommandOutput, CommandRunner};
    use crate::model::{IdentityModeResolution, ModePreference, StateLayout, UseCase};
    use crate::ops::seed::{SeedCreateRequest, SeedIdentity, SeedMaterial, SeedOpenAuthSource};

    struct FakeSeedBackend {
        seed: Vec<u8>,
    }

    impl FakeSeedBackend {
        fn new(seed: &[u8]) -> Self {
            Self {
                seed: seed.to_vec(),
            }
        }
    }

    impl SeedBackend for FakeSeedBackend {
        fn seal_seed(&self, _request: &SeedCreateRequest) -> Result<()> {
            Ok(())
        }
        fn unseal_seed(
            &self,
            _profile: &SeedIdentity,
            _auth_source: &SeedOpenAuthSource,
        ) -> Result<SeedMaterial> {
            Ok(SecretBox::new(Box::new(self.seed.clone())))
        }
    }

    struct NullRunner;
    impl CommandRunner for NullRunner {
        fn run(&self, _inv: &CommandInvocation) -> CommandOutput {
            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    fn seed_profile_fixture(root: &std::path::Path, algorithm: Algorithm) -> Identity {
        Identity {
            schema_version: crate::model::IDENTITY_SCHEMA_VERSION,
            name: "keygen-seed".to_string(),
            algorithm,
            uses: vec![UseCase::Derive],
            mode: IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed".to_string()],
            },
            defaults: crate::model::IdentityDerivationDefaults::default(),
            storage: crate::model::IdentityStorage {
                state_layout: StateLayout::new(root.to_path_buf()),
                identity_path: PathBuf::new(),
                root_material_kind: crate::model::RootMaterialKind::SealedSeed,
            },
            export_policy: crate::model::ExportPolicy::for_mode(Mode::Seed),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn keygen_ed25519_from_seed() {
        let root = tempfile::tempdir().unwrap();
        let identity = seed_profile_fixture(root.path(), Algorithm::Ed25519);
        let backend = FakeSeedBackend::new(&[0x42; 32]);
        let deriver = HkdfSha256SeedDeriver;
        let runner = NullRunner;

        let result =
            execute(&identity, &runner, &backend, &deriver).expect("ed25519 keygen should succeed");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.algorithm, Algorithm::Ed25519);
        // ed25519 secret key = 32 bytes hex = 64 chars
        assert_eq!(result.secret_key_hex.len(), 64);
        // ed25519 public key = 32 bytes hex = 64 chars
        assert_eq!(result.public_key_hex.len(), 64);
    }

    #[test]
    fn keygen_p256_from_seed() {
        let root = tempfile::tempdir().unwrap();
        let identity = seed_profile_fixture(root.path(), Algorithm::P256);
        let backend = FakeSeedBackend::new(&[0x55; 32]);
        let deriver = HkdfSha256SeedDeriver;
        let runner = NullRunner;

        let result =
            execute(&identity, &runner, &backend, &deriver).expect("p256 keygen should succeed");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.algorithm, Algorithm::P256);
        assert_eq!(result.secret_key_hex.len(), 64);
        // p256 SPKI DER public key is typically 91 bytes = 182 hex chars
        assert!(result.public_key_hex.len() > 64);
    }

    #[test]
    fn keygen_secp256k1_from_seed() {
        let root = tempfile::tempdir().unwrap();
        let identity = seed_profile_fixture(root.path(), Algorithm::Secp256k1);
        let backend = FakeSeedBackend::new(&[0x77; 32]);
        let deriver = HkdfSha256SeedDeriver;
        let runner = NullRunner;

        let result = execute(&identity, &runner, &backend, &deriver)
            .expect("secp256k1 keygen should succeed");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.algorithm, Algorithm::Secp256k1);
        assert_eq!(result.secret_key_hex.len(), 64);
        assert!(result.public_key_hex.len() > 64);
    }

    #[test]
    fn keygen_native_returns_unsupported() {
        let root = tempfile::tempdir().unwrap();
        let mut identity = seed_profile_fixture(root.path(), Algorithm::P256);
        identity.mode.resolved = Mode::Native;

        let backend = FakeSeedBackend::new(&[0xDD; 32]);
        let deriver = HkdfSha256SeedDeriver;
        let runner = NullRunner;

        let err = execute(&identity, &runner, &backend, &deriver)
            .expect_err("native should be unsupported");
        assert!(err.to_string().contains("not supported for native"));
    }

    #[test]
    fn keygen_deterministic_same_seed_same_result() {
        let root = tempfile::tempdir().unwrap();
        let identity = seed_profile_fixture(root.path(), Algorithm::Ed25519);
        let backend = FakeSeedBackend::new(&[0x99; 32]);
        let deriver = HkdfSha256SeedDeriver;
        let runner = NullRunner;

        let r1 = execute(&identity, &runner, &backend, &deriver).unwrap();
        let r2 = execute(&identity, &runner, &backend, &deriver).unwrap();

        assert_eq!(r1.secret_key_hex, r2.secret_key_hex);
        assert_eq!(r1.public_key_hex, r2.public_key_hex);
    }
}
