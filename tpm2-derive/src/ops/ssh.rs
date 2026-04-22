use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use p256::SecretKey;
use secrecy::ExposeSecret;
use sha2::{Digest as _, Sha256};
use ssh_key::{
    LineEnding, PrivateKey,
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData},
};

use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};
use crate::error::{Error, Result};
use crate::model::{Algorithm, Identity, Mode, SshAddRequest, SshAddResult, UseCase};

use super::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive,
    seed_profile_from_profile,
};

const SSH_CHILD_KEY_NAMESPACE: &str = "tpm2-derive.ssh";
const SSH_CHILD_KEY_PATH: &str = "m/openssh/agent/default";
const SSH_P256_SCALAR_FALLBACK_DOMAIN: &[u8] = b"tpm2-derive\0ssh\0p256-scalar-fallback\0v1";

pub trait SshAddClient {
    fn add_private_key(&self, socket: &Path, private_key_openssh: &str) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessSshAddClient;

impl SshAddClient for ProcessSshAddClient {
    fn add_private_key(&self, socket: &Path, private_key_openssh: &str) -> Result<()> {
        let mut child = Command::new("ssh-add")
            .args(["-q", "-"])
            .env("SSH_AUTH_SOCK", socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                Error::State(format!(
                    "failed to spawn ssh-add for socket '{}': {error}",
                    socket.display()
                ))
            })?;

        let mut stdin = child.stdin.take().ok_or_else(|| {
            Error::State("ssh-add stdin was not available for private-key injection".to_string())
        })?;
        stdin
            .write_all(private_key_openssh.as_bytes())
            .map_err(|error| {
                Error::State(format!(
                    "failed to pipe OpenSSH private key into ssh-add: {error}"
                ))
            })?;
        drop(stdin);

        let output = child.wait_with_output().map_err(|error| {
            Error::State(format!(
                "failed while waiting for ssh-add to finish: {error}"
            ))
        })?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        Err(Error::State(if detail.is_empty() {
            format!(
                "ssh-add failed for socket '{}' with status {:?}",
                socket.display(),
                output.status.code()
            )
        } else {
            format!(
                "ssh-add failed for socket '{}': {}",
                socket.display(),
                detail
            )
        }))
    }
}

pub fn add_with_defaults(identity: &Identity, request: &SshAddRequest) -> Result<SshAddResult> {
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    let client = ProcessSshAddClient;

    add_with_backend(identity, request, &seed_backend, &seed_deriver, &client)
}

pub fn add_with_backend<B, D, C>(
    identity: &Identity,
    request: &SshAddRequest,
    seed_backend: &B,
    seed_deriver: &D,
    client: &C,
) -> Result<SshAddResult>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
    C: SshAddClient,
{
    match identity.mode.resolved {
        Mode::Native => Err(Error::Unsupported(format!(
            "identity '{}' resolved to native mode; ssh-add cannot export a TPM-native private key into a software agent",
            identity.name
        ))),
        Mode::Prf => Err(Error::Unsupported(format!(
            "identity '{}' resolved to PRF mode; ssh-add is not wired for PRF-mode identities yet",
            identity.name
        ))),
        Mode::Seed => add_seed_profile(identity, request, seed_backend, seed_deriver, client),
    }
}

fn add_seed_profile<B, D, C>(
    identity: &Identity,
    request: &SshAddRequest,
    seed_backend: &B,
    seed_deriver: &D,
    client: &C,
) -> Result<SshAddResult>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
    C: SshAddClient,
{
    ensure_ssh_use(identity)?;

    // Enforce mode/use compatibility at operation dispatch time.
    UseCase::validate_for_mode(&identity.uses, identity.mode.resolved)?;

    if !matches!(identity.algorithm, Algorithm::Ed25519 | Algorithm::P256) {
        return Err(Error::Unsupported(format!(
            "identity '{}' resolved to seed mode, but ssh-add currently supports only ed25519 and p256 seed identities; found {:?}",
            identity.name, identity.algorithm
        )));
    }

    let comment = request
        .comment
        .clone()
        .unwrap_or_else(|| default_comment(identity));
    let socket = resolve_socket(request.socket.as_deref())?;
    let private_key = derive_seed_private_key(identity, seed_backend, seed_deriver, &comment)?;
    let public_key_openssh = private_key.public_key().to_openssh().map_err(|error| {
        Error::Internal(format!(
            "failed to render OpenSSH public key for identity '{}': {error}",
            identity.name
        ))
    })?;
    let private_key_openssh = private_key.to_openssh(LineEnding::LF).map_err(|error| {
        Error::Internal(format!(
            "failed to render OpenSSH private key for identity '{}': {error}",
            identity.name
        ))
    })?;

    client.add_private_key(&socket, private_key_openssh.as_ref())?;

    Ok(SshAddResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        socket,
        comment,
        public_key_openssh,
    })
}

fn derive_seed_private_key<B, D>(
    identity: &Identity,
    seed_backend: &B,
    seed_deriver: &D,
    comment: &str,
) -> Result<PrivateKey>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    match identity.algorithm {
        Algorithm::Ed25519 => {
            derive_ed25519_private_key(identity, seed_backend, seed_deriver, comment)
        }
        Algorithm::P256 => derive_p256_private_key(identity, seed_backend, seed_deriver, comment),
        other => Err(Error::Unsupported(format!(
            "identity '{}' resolved to seed mode, but ssh-add does not derive {:?} private keys yet",
            identity.name, other
        ))),
    }
}

fn derive_ed25519_private_key<B, D>(
    identity: &Identity,
    seed_backend: &B,
    seed_deriver: &D,
    comment: &str,
) -> Result<PrivateKey>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let derived_seed = derive_seed_bytes(
        identity,
        seed_backend,
        seed_deriver,
        ssh_ed25519_derivation_spec()?,
        "ed25519 seed",
    )?;
    let seed_bytes: [u8; 32] = derived_seed.try_into().map_err(|_| {
        Error::Internal(
            "ssh-agent ed25519 derivation produced a non-32-byte seed unexpectedly".to_string(),
        )
    })?;
    let keypair = Ed25519Keypair::from_seed(&seed_bytes);

    PrivateKey::new(KeypairData::from(keypair), comment).map_err(|error| {
        Error::Internal(format!(
            "failed to construct an OpenSSH ed25519 private key for identity '{}': {error}",
            identity.name
        ))
    })
}

fn derive_p256_private_key<B, D>(
    identity: &Identity,
    seed_backend: &B,
    seed_deriver: &D,
    comment: &str,
) -> Result<PrivateKey>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let scalar_bytes = derive_seed_bytes(
        identity,
        seed_backend,
        seed_deriver,
        ssh_p256_derivation_spec()?,
        "p256 scalar",
    )?;
    let secret_key = p256_secret_key_from_material(identity, &scalar_bytes)?;
    let public_key = secret_key.public_key();

    PrivateKey::new(
        KeypairData::from(EcdsaKeypair::NistP256 {
            private: secret_key.into(),
            public: public_key.into(),
        }),
        comment,
    )
    .map_err(|error| {
        Error::Internal(format!(
            "failed to construct an OpenSSH p256 private key for identity '{}': {error}",
            identity.name
        ))
    })
}

fn derive_seed_bytes<B, D>(
    identity: &Identity,
    seed_backend: &B,
    seed_deriver: &D,
    spec: DerivationSpec,
    output_name: &str,
) -> Result<Vec<u8>>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let output_bytes = usize::from(spec.output().length);
    let seed_profile = seed_profile_from_profile(identity)?;
    let request = SeedOpenRequest {
        identity: seed_profile,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest { spec, output_bytes }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    };

    open_and_derive(seed_backend, seed_deriver, &request)
        .map(|derived| derived.expose_secret().to_vec())
        .map_err(|error| {
            Error::State(format!(
                "failed to derive ssh-agent {output_name} for identity '{}': {error}",
                identity.name
            ))
        })
}

pub(crate) fn ssh_ed25519_derivation_spec() -> Result<DerivationSpec> {
    Ok(DerivationSpec::V1(DerivationSpecV1::software_child_key(
        SSH_CHILD_KEY_NAMESPACE,
        "ed25519",
        SSH_CHILD_KEY_PATH,
        OutputKind::Ed25519Seed,
    )?))
}

fn ssh_p256_derivation_spec() -> Result<DerivationSpec> {
    Ok(DerivationSpec::V1(DerivationSpecV1::software_child_key(
        SSH_CHILD_KEY_NAMESPACE,
        "p256",
        SSH_CHILD_KEY_PATH,
        OutputKind::P256Scalar,
    )?))
}

fn p256_secret_key_from_material(identity: &Identity, material: &[u8]) -> Result<SecretKey> {
    if let Ok(secret_key) = SecretKey::from_slice(material) {
        return Ok(secret_key);
    }

    for counter in 1u32..=1024 {
        let mut hasher = Sha256::new();
        hasher.update(SSH_P256_SCALAR_FALLBACK_DOMAIN);
        hasher.update(material);
        hasher.update(counter.to_be_bytes());
        let candidate = hasher.finalize();
        if let Ok(secret_key) = SecretKey::from_slice(candidate.as_slice()) {
            return Ok(secret_key);
        }
    }

    Err(Error::Internal(format!(
        "failed to normalize p256 ssh-agent scalar material for identity '{}'",
        identity.name
    )))
}

fn ensure_ssh_use(identity: &Identity) -> Result<()> {
    if identity
        .uses
        .iter()
        .any(|use_case| matches!(use_case, UseCase::Ssh))
    {
        return Ok(());
    }

    Err(Error::PolicyRefusal(format!(
        "identity '{}' is not configured with use=ssh",
        identity.name
    )))
}

fn default_comment(identity: &Identity) -> String {
    format!("{}@tpm2-derive", identity.name)
}

fn resolve_socket(explicit_socket: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit_socket {
        return Ok(path.to_path_buf());
    }

    match env::var_os("SSH_AUTH_SOCK") {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => Err(Error::State(
            "ssh-add requires --socket or SSH_AUTH_SOCK to point at a running agent".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use secrecy::SecretBox;
    use tempfile::tempdir;

    use super::*;
    use crate::model::{IdentityModeResolution, ModePreference, StateLayout};
    use crate::ops::seed::{SeedCreateRequest, SeedIdentity, SeedMaterial};

    #[derive(Debug, Clone)]
    struct RecordingSshAddClient {
        state: Arc<Mutex<Vec<(PathBuf, String)>>>,
    }

    impl RecordingSshAddClient {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn records(&self) -> Vec<(PathBuf, String)> {
            self.state.lock().expect("records lock").clone()
        }
    }

    impl SshAddClient for RecordingSshAddClient {
        fn add_private_key(&self, socket: &Path, private_key_openssh: &str) -> Result<()> {
            self.state
                .lock()
                .expect("records lock")
                .push((socket.to_path_buf(), private_key_openssh.to_string()));
            Ok(())
        }
    }

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

    fn seed_profile(root: &Path, mode: Mode, algorithm: Algorithm, uses: Vec<UseCase>) -> Identity {
        Identity::new(
            "seed-ssh".to_string(),
            algorithm,
            uses,
            IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: mode,
                reasons: vec![format!("{mode:?} requested")],
            },
            StateLayout::new(root.to_path_buf()),
        )
    }

    #[test]
    fn adds_ed25519_seed_profile_to_requested_agent_socket() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Mode::Seed,
            Algorithm::Ed25519,
            vec![UseCase::Ssh],
        );
        let backend = FakeSeedBackend::new(&[0x42; 32]);
        let client = RecordingSshAddClient::new();

        let result = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: Some("seed-ssh@example".to_string()),
                socket: Some(state_root.path().join("agent.sock")),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &backend,
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect("ssh-add should succeed");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.algorithm, Algorithm::Ed25519);
        assert_eq!(result.comment, "seed-ssh@example");
        assert!(result.public_key_openssh.starts_with("ssh-ed25519 "));

        let records = client.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, state_root.path().join("agent.sock"));
        assert!(
            records[0]
                .1
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
    }

    #[test]
    fn rejects_non_seed_modes_explicitly() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Mode::Prf,
            Algorithm::Ed25519,
            vec![UseCase::Ssh],
        );
        let backend = FakeSeedBackend::new(&[0x24; 32]);
        let client = RecordingSshAddClient::new();
        let error = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: None,
                socket: Some(state_root.path().join("agent.sock")),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &backend,
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect_err("prf mode should stay unsupported");

        assert_eq!(error.code(), crate::ErrorCode::Unsupported);
        assert!(error.to_string().contains("PRF-mode identities yet"));
    }

    #[test]
    fn rejects_seed_profiles_without_ssh_use() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Mode::Seed,
            Algorithm::Ed25519,
            vec![UseCase::Derive],
        );
        let backend = FakeSeedBackend::new(&[0x11; 32]);
        let client = RecordingSshAddClient::new();
        let error = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: None,
                socket: Some(state_root.path().join("agent.sock")),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &backend,
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect_err("ssh use should be required");

        assert_eq!(error.code(), crate::ErrorCode::PolicyRefusal);
        assert!(error.to_string().contains("not configured with use=ssh"));
    }

    #[test]
    fn adds_p256_seed_profile_to_requested_agent_socket() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Mode::Seed,
            Algorithm::P256,
            vec![UseCase::Ssh],
        );
        let backend = FakeSeedBackend::new(&[0x33; 32]);
        let client = RecordingSshAddClient::new();

        let result = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: Some("seed-p256@example".to_string()),
                socket: Some(state_root.path().join("agent.sock")),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &backend,
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect("p256 seed ssh-add should succeed");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.algorithm, Algorithm::P256);
        assert_eq!(result.comment, "seed-p256@example");
        assert!(
            result
                .public_key_openssh
                .starts_with("ecdsa-sha2-nistp256 ")
        );

        let records = client.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, state_root.path().join("agent.sock"));
        assert!(
            records[0]
                .1
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
    }

    #[test]
    fn p256_seed_profile_normalizes_zero_scalar_material() {
        let state_root = tempdir().expect("state root");
        let identity = seed_profile(
            state_root.path(),
            Mode::Seed,
            Algorithm::P256,
            vec![UseCase::Ssh],
        );
        let backend = FakeSeedBackend::new(&[0u8; 32]);
        let client = RecordingSshAddClient::new();

        let result = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: None,
                socket: Some(state_root.path().join("agent.sock")),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &backend,
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect("zero scalar material should be normalized into a valid p256 key");

        assert!(
            result
                .public_key_openssh
                .starts_with("ecdsa-sha2-nistp256 ")
        );
    }
}
