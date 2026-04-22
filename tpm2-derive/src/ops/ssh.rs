use std::env;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::SecretKey;
use ssh_key::{
    LineEnding, PrivateKey, PublicKey as SshPublicKey,
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData},
    public::{
        EcdsaPublicKey as SshEcdsaPublicKey, Ed25519PublicKey as SshEd25519PublicKey,
        KeyData as SshKeyData,
    },
};

use crate::backend::{CommandRunner, ProcessCommandRunner, resolve_trusted_program_path};
use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};
use crate::error::{Error, Result};
use crate::model::{Algorithm, Identity, SshAddRequest, SshAddResult, UseCase};

use super::keygen::{derive_identity_key_material, normalized_secret_key_bytes};
use super::seed::{HkdfSha256SeedDeriver, SeedBackend, SeedSoftwareDeriver, SubprocessSeedBackend};

pub trait SshAddClient {
    fn add_private_key(&self, socket: &Path, private_key_openssh: &str) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessSshAddClient;

impl SshAddClient for ProcessSshAddClient {
    fn add_private_key(&self, socket: &Path, private_key_openssh: &str) -> Result<()> {
        let program = resolve_trusted_program_path("ssh-add").map_err(|error| {
            Error::State(format!("failed to resolve trusted ssh-add binary: {error}"))
        })?;

        let mut child = Command::new(program)
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
    let client = ProcessSshAddClient;
    let prf_runner = ProcessCommandRunner;
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    add_with_backend(
        identity,
        request,
        &prf_runner,
        &seed_backend,
        &seed_deriver,
        &client,
    )
}

pub fn add_with_backend<R, B, D, C>(
    identity: &Identity,
    request: &SshAddRequest,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
    client: &C,
) -> Result<SshAddResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
    C: SshAddClient,
{
    if identity.mode.resolved == crate::model::Mode::Native {
        return Err(Error::Unsupported(format!(
            "identity '{}' resolved to native mode; ssh-add cannot export a TPM-native private key into a software agent",
            identity.name
        )));
    }

    ensure_ssh_use(identity)?;
    UseCase::validate_for_mode(&identity.uses, identity.mode.resolved)?;
    add_derived_identity(
        identity,
        request,
        prf_runner,
        seed_backend,
        seed_deriver,
        client,
    )
}

fn add_derived_identity<R, B, D, C>(
    identity: &Identity,
    request: &SshAddRequest,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
    client: &C,
) -> Result<SshAddResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
    C: SshAddClient,
{
    if !matches!(identity.algorithm, Algorithm::Ed25519 | Algorithm::P256) {
        return Err(Error::Unsupported(format!(
            "identity '{}' resolved to {:?} mode, but ssh-add currently supports only ed25519 and p256 identities; found {:?}",
            identity.name, identity.mode.resolved, identity.algorithm
        )));
    }

    let comment = request
        .comment
        .clone()
        .unwrap_or_else(|| default_comment(identity));
    let socket = resolve_socket(request.socket.as_deref())?;
    let private_key = derive_private_key(
        identity,
        request,
        prf_runner,
        seed_backend,
        seed_deriver,
        &comment,
    )?;
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

fn derive_private_key<R, B, D>(
    identity: &Identity,
    request: &SshAddRequest,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
    comment: &str,
) -> Result<PrivateKey>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let material = derive_identity_key_material(
        identity,
        &request.derivation,
        prf_runner,
        seed_backend,
        seed_deriver,
    )?;

    match identity.algorithm {
        Algorithm::Ed25519 => derive_ed25519_private_key(identity, &material, comment),
        Algorithm::P256 => derive_p256_private_key(identity, &material, comment),
        Algorithm::Secp256k1 => Err(Error::Unsupported(format!(
            "identity '{}' resolved to {:?} mode, but ssh-add does not derive {:?} private keys yet",
            identity.name, identity.mode.resolved, identity.algorithm
        ))),
    }
}

fn derive_ed25519_private_key(
    identity: &Identity,
    material: &[u8],
    comment: &str,
) -> Result<PrivateKey> {
    let seed_bytes = normalized_secret_key_bytes(identity, material)?;
    let keypair = Ed25519Keypair::from_seed(&seed_bytes);

    PrivateKey::new(KeypairData::from(keypair), comment).map_err(|error| {
        Error::Internal(format!(
            "failed to construct an OpenSSH ed25519 private key for identity '{}': {error}",
            identity.name
        ))
    })
}

fn derive_p256_private_key(
    identity: &Identity,
    material: &[u8],
    comment: &str,
) -> Result<PrivateKey> {
    let scalar = normalized_secret_key_bytes(identity, material)?;
    let secret_key = SecretKey::from_slice(&scalar).map_err(|error| {
        Error::Internal(format!(
            "failed to construct a p256 private key for identity '{}': {error}",
            identity.name
        ))
    })?;
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

pub(crate) fn openssh_public_key_from_material(
    identity: &Identity,
    material: &[u8],
) -> Result<String> {
    match identity.algorithm {
        Algorithm::Ed25519 => {
            let seed = normalized_secret_key_bytes(identity, material)?;
            let signing_key = Ed25519SigningKey::from_bytes(&seed);
            let public_key = SshPublicKey::new(
                SshKeyData::from(SshEd25519PublicKey::from(signing_key.verifying_key())),
                identity.name.clone(),
            );
            public_key.to_openssh().map_err(|error| {
                Error::Internal(format!(
                    "failed to render OpenSSH public key for identity '{}': {error}",
                    identity.name
                ))
            })
        }
        Algorithm::P256 => {
            let scalar = normalized_secret_key_bytes(identity, material)?;
            let secret_key = SecretKey::from_slice(&scalar).map_err(|error| {
                Error::Internal(format!(
                    "failed to construct a p256 private key for identity '{}': {error}",
                    identity.name
                ))
            })?;
            let sec1 = secret_key.public_key().to_sec1_bytes();
            let public_key = SshPublicKey::new(
                SshKeyData::Ecdsa(SshEcdsaPublicKey::from_sec1_bytes(sec1.as_ref()).map_err(
                    |error| {
                        Error::Internal(format!(
                            "failed to convert p256 key to OpenSSH public form for identity '{}': {error}",
                            identity.name
                        ))
                    },
                )?),
                identity.name.clone(),
            );
            public_key.to_openssh().map_err(|error| {
                Error::Internal(format!(
                    "failed to render OpenSSH public key for identity '{}': {error}",
                    identity.name
                ))
            })
        }
        Algorithm::Secp256k1 => Err(Error::Unsupported(
            "OpenSSH public-key rendering is not supported for secp256k1 identities".to_string(),
        )),
    }
}

pub(crate) fn ssh_ed25519_derivation_spec() -> Result<DerivationSpec> {
    Ok(DerivationSpec::V1(DerivationSpecV1::software_child_key(
        "tpm2-derive.ssh",
        "ed25519",
        "m/openssh/agent/default",
        OutputKind::Ed25519Seed,
    )?))
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
    let path = if let Some(path) = explicit_socket {
        path.to_path_buf()
    } else {
        match env::var_os("SSH_AUTH_SOCK") {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => {
                return Err(Error::State(
                    "ssh-add requires --socket or SSH_AUTH_SOCK to point at a running agent"
                        .to_string(),
                ))
            }
        }
    };

    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        Error::State(format!(
            "ssh-add requires a valid agent socket path '{}': {error}",
            path.display()
        ))
    })?;

    #[cfg(unix)]
    {
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(Error::Validation(format!(
                "ssh-add requires '{}' to be a direct Unix-domain socket path, not a symlink",
                path.display()
            )));
        }
        if !file_type.is_socket() {
            return Err(Error::Validation(format!(
                "ssh-add requires '{}' to be a Unix-domain socket",
                path.display()
            )));
        }

        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid {
            return Err(Error::Validation(format!(
                "ssh-add requires socket '{}' to be owned by the current user",
                path.display()
            )));
        }

        if let Some(parent) = path.parent() {
            let parent_metadata = fs::metadata(parent).map_err(|error| {
                Error::State(format!(
                    "failed to inspect ssh-agent socket parent directory '{}': {error}",
                    parent.display()
                ))
            })?;
            if parent_metadata.uid() != current_uid {
                return Err(Error::Validation(format!(
                    "ssh-add requires socket parent directory '{}' to be owned by the current user",
                    parent.display()
                )));
            }
            if parent_metadata.permissions().mode() & 0o002 != 0 {
                return Err(Error::Validation(format!(
                    "ssh-add requires socket parent directory '{}' to not be world-writable",
                    parent.display()
                )));
            }
        }
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;

    use secrecy::SecretBox;
    use tempfile::tempdir;

    use crate::backend::{CommandInvocation, CommandOutput};
    use crate::model::{
        Algorithm, DerivationOverrides, Identity, IdentityModeResolution, Mode, ModePreference,
        StateLayout, UseCase,
    };
    use crate::ops::prf::PRF_CONTEXT_PATH_METADATA_KEY;
    use crate::ops::seed::{SeedCreateRequest, SeedMaterial};

    use super::*;

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
            _profile: &crate::ops::seed::SeedIdentity,
            _auth_source: &crate::ops::seed::SeedOpenAuthSource,
        ) -> Result<SeedMaterial> {
            Ok(SecretBox::new(Box::new(self.seed.clone())))
        }
    }

    struct RecordingPrfRunner {
        raw_output: Vec<u8>,
    }

    impl RecordingPrfRunner {
        fn new(raw_output: &[u8]) -> Self {
            Self {
                raw_output: raw_output.to_vec(),
            }
        }
    }

    impl CommandRunner for RecordingPrfRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            let output_path = invocation
                .args
                .windows(2)
                .find(|pair| pair[0] == "-o")
                .map(|pair| PathBuf::from(&pair[1]))
                .expect("prf output path");
            std::fs::write(output_path, &self.raw_output).expect("write prf output");
            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    #[derive(Default)]
    struct RecordingSshAddClient {
        private_keys: RefCell<Vec<String>>,
    }

    impl RecordingSshAddClient {
        fn keys(&self) -> Vec<String> {
            self.private_keys.borrow().clone()
        }
    }

    impl SshAddClient for RecordingSshAddClient {
        fn add_private_key(&self, _socket: &Path, private_key_openssh: &str) -> Result<()> {
            self.private_keys
                .borrow_mut()
                .push(private_key_openssh.to_string());
            Ok(())
        }
    }

    fn seed_identity(root: &Path) -> Identity {
        Identity::new(
            "seed-ssh".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::Ssh],
            IdentityModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed requested".to_string()],
            },
            StateLayout::new(root.to_path_buf()),
        )
    }

    fn prf_identity(root: &Path) -> Identity {
        let mut identity = Identity::new(
            "prf-ssh".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Ssh],
            IdentityModeResolution {
                requested: ModePreference::Prf,
                resolved: Mode::Prf,
                reasons: vec!["prf requested".to_string()],
            },
            StateLayout::new(root.to_path_buf()),
        );
        identity.metadata.insert(
            PRF_CONTEXT_PATH_METADATA_KEY.to_string(),
            format!("objects/{}/prf-root.ctx", identity.name),
        );
        identity
    }

    #[cfg(unix)]
    #[test]
    fn resolve_socket_rejects_symlink_paths() {
        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("agent.sock");
        let symlink_path = temp.path().join("agent-link.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        std::os::unix::fs::symlink(&socket_path, &symlink_path).expect("symlink");

        let error = resolve_socket(Some(&symlink_path)).expect_err("symlink should be rejected");
        assert!(matches!(error, Error::Validation(message) if message.contains("direct Unix-domain socket path")));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_socket_rejects_non_socket_paths() {
        let temp = tempdir().expect("tempdir");
        let file_path = temp.path().join("not-a-socket");
        std::fs::write(&file_path, b"nope").expect("file");

        let error = resolve_socket(Some(&file_path)).expect_err("non-socket should be rejected");
        assert!(matches!(error, Error::Validation(message) if message.contains("Unix-domain socket")));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_socket_accepts_current_user_socket() {
        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");

        let resolved = resolve_socket(Some(&socket_path)).expect("socket should validate");
        assert_eq!(resolved, socket_path);
    }

    #[cfg(unix)]
    #[test]
    fn ssh_add_seed_adds_private_key_to_agent_client() {
        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        let identity = seed_identity(temp.path());
        let client = RecordingSshAddClient::default();
        let result = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: Some("seed@test".to_string()),
                socket: Some(socket_path),
                state_dir: Some(temp.path().to_path_buf()),
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &FakeSeedBackend::new(&[0x44; 32]),
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect("seed ssh-add");

        assert_eq!(result.mode, Mode::Seed);
        assert_eq!(result.comment, "seed@test");
        assert!(result.public_key_openssh.starts_with("ssh-ed25519 "));
        assert_eq!(client.keys().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn ssh_add_prf_adds_private_key_to_agent_client() {
        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        let identity = prf_identity(temp.path());
        let client = RecordingSshAddClient::default();
        let result = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: Some("prf@test".to_string()),
                socket: Some(socket_path),
                state_dir: Some(temp.path().to_path_buf()),
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"tpm-prf-material"),
            &FakeSeedBackend::new(&[0x00; 32]),
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect("prf ssh-add");

        assert_eq!(result.mode, Mode::Prf);
        assert!(result.public_key_openssh.starts_with("ecdsa-sha2-nistp256 "));
        assert_eq!(client.keys().len(), 1);
    }

    #[test]
    fn ssh_add_native_rejection_is_explicit() {
        let temp = tempdir().expect("tempdir");
        let identity = Identity::new(
            "native-ssh".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Ssh],
            IdentityModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            StateLayout::new(temp.path().to_path_buf()),
        );
        let error = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: None,
                socket: Some(temp.path().join("agent.sock")),
                state_dir: Some(temp.path().to_path_buf()),
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &FakeSeedBackend::new(&[0x00; 32]),
            &HkdfSha256SeedDeriver,
            &RecordingSshAddClient::default(),
        )
        .expect_err("native ssh-add should fail");

        assert!(matches!(error, Error::Unsupported(message) if message.contains("native mode")));
    }
}
