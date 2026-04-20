use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use secrecy::ExposeSecret;
use ssh_key::{LineEnding, PrivateKey, private::Ed25519Keypair, private::KeypairData};

use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};
use crate::error::{Error, Result};
use crate::model::{Algorithm, Mode, Profile, SshAgentAddRequest, SshAgentAddResult, UseCase};

use super::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive,
    seed_profile_from_profile,
};

const SSH_CHILD_KEY_NAMESPACE: &str = "tpm2-derive.ssh";
const SSH_CHILD_KEY_PATH: &str = "m/openssh/agent/default";

pub trait SshAgentClient {
    fn add_private_key(&self, socket: &Path, private_key_openssh: &str) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessSshAgentClient;

impl SshAgentClient for ProcessSshAgentClient {
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

pub fn add_with_defaults(
    profile: &Profile,
    request: &SshAgentAddRequest,
) -> Result<SshAgentAddResult> {
    let seed_backend = SubprocessSeedBackend::new(profile.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    let client = ProcessSshAgentClient;

    add_with_backend(profile, request, &seed_backend, &seed_deriver, &client)
}

pub fn add_with_backend<B, D, C>(
    profile: &Profile,
    request: &SshAgentAddRequest,
    seed_backend: &B,
    seed_deriver: &D,
    client: &C,
) -> Result<SshAgentAddResult>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
    C: SshAgentClient,
{
    match profile.mode.resolved {
        Mode::Native => Err(Error::Unsupported(format!(
            "profile '{}' resolved to native mode; ssh-agent add cannot export a TPM-native private key into a software agent",
            profile.name
        ))),
        Mode::Prf => Err(Error::Unsupported(format!(
            "profile '{}' resolved to PRF mode; ssh-agent add is not wired for PRF-mode profiles yet",
            profile.name
        ))),
        Mode::Seed => add_seed_profile(profile, request, seed_backend, seed_deriver, client),
    }
}

fn add_seed_profile<B, D, C>(
    profile: &Profile,
    request: &SshAgentAddRequest,
    seed_backend: &B,
    seed_deriver: &D,
    client: &C,
) -> Result<SshAgentAddResult>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
    C: SshAgentClient,
{
    ensure_ssh_use(profile)?;

    if profile.algorithm != Algorithm::Ed25519 {
        return Err(Error::Unsupported(format!(
            "profile '{}' resolved to seed mode, but ssh-agent add currently supports only ed25519 seed profiles; found {:?}",
            profile.name, profile.algorithm
        )));
    }

    let comment = request
        .comment
        .clone()
        .unwrap_or_else(|| default_comment(profile));
    let socket = resolve_socket(request.socket.as_deref())?;
    let private_key = derive_ed25519_private_key(profile, seed_backend, seed_deriver, &comment)?;
    let public_key_openssh = private_key.public_key().to_openssh().map_err(|error| {
        Error::Internal(format!(
            "failed to render OpenSSH public key for profile '{}': {error}",
            profile.name
        ))
    })?;
    let private_key_openssh = private_key.to_openssh(LineEnding::LF).map_err(|error| {
        Error::Internal(format!(
            "failed to render OpenSSH private key for profile '{}': {error}",
            profile.name
        ))
    })?;

    client.add_private_key(&socket, private_key_openssh.as_ref())?;

    Ok(SshAgentAddResult {
        profile: profile.name.clone(),
        mode: profile.mode.resolved,
        algorithm: profile.algorithm,
        socket,
        comment,
        public_key_openssh,
    })
}

fn derive_ed25519_private_key<B, D>(
    profile: &Profile,
    seed_backend: &B,
    seed_deriver: &D,
    comment: &str,
) -> Result<PrivateKey>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_profile = seed_profile_from_profile(profile)?;
    let request = SeedOpenRequest {
        profile: seed_profile,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
            spec: ssh_ed25519_derivation_spec()?,
            output_bytes: 32,
        }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    };

    let derived_seed = open_and_derive(seed_backend, seed_deriver, &request)?;
    let seed_bytes: [u8; 32] =
        derived_seed
            .expose_secret()
            .as_slice()
            .try_into()
            .map_err(|_| {
                Error::Internal(
                    "ssh-agent ed25519 derivation produced a non-32-byte seed unexpectedly"
                        .to_string(),
                )
            })?;
    let keypair = Ed25519Keypair::from_seed(&seed_bytes);

    PrivateKey::new(KeypairData::from(keypair), comment).map_err(|error| {
        Error::Internal(format!(
            "failed to construct an OpenSSH ed25519 private key for profile '{}': {error}",
            profile.name
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

fn ensure_ssh_use(profile: &Profile) -> Result<()> {
    if profile
        .uses
        .iter()
        .any(|use_case| matches!(use_case, UseCase::Ssh | UseCase::SshAgent))
    {
        return Ok(());
    }

    Err(Error::Unsupported(format!(
        "profile '{}' is not configured with ssh or ssh-agent use",
        profile.name
    )))
}

fn default_comment(profile: &Profile) -> String {
    format!("{}@tpm2-derive", profile.name)
}

fn resolve_socket(explicit_socket: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit_socket {
        return Ok(path.to_path_buf());
    }

    match env::var_os("SSH_AUTH_SOCK") {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => Err(Error::State(
            "ssh-agent add requires --socket or SSH_AUTH_SOCK to point at a running agent"
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use secrecy::SecretBox;
    use tempfile::tempdir;

    use super::*;
    use crate::model::{ModePreference, ModeResolution, StateLayout};
    use crate::ops::seed::{SeedCreateRequest, SeedMaterial, SeedProfile};

    #[derive(Debug, Clone)]
    struct RecordingSshAgentClient {
        state: Arc<Mutex<Vec<(PathBuf, String)>>>,
    }

    impl RecordingSshAgentClient {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn records(&self) -> Vec<(PathBuf, String)> {
            self.state.lock().expect("records lock").clone()
        }
    }

    impl SshAgentClient for RecordingSshAgentClient {
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
            _profile: &SeedProfile,
            _auth_source: &SeedOpenAuthSource,
        ) -> Result<SeedMaterial> {
            Ok(SecretBox::new(Box::new(self.seed.clone())))
        }
    }

    fn seed_profile(root: &Path, mode: Mode, algorithm: Algorithm, uses: Vec<UseCase>) -> Profile {
        Profile::new(
            "seed-ssh".to_string(),
            algorithm,
            uses,
            ModeResolution {
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
        let profile = seed_profile(
            state_root.path(),
            Mode::Seed,
            Algorithm::Ed25519,
            vec![UseCase::SshAgent],
        );
        let backend = FakeSeedBackend::new(&[0x42; 32]);
        let client = RecordingSshAgentClient::new();

        let result = add_with_backend(
            &profile,
            &SshAgentAddRequest {
                profile: profile.name.clone(),
                comment: Some("seed-ssh@example".to_string()),
                socket: Some(state_root.path().join("agent.sock")),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &backend,
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect("ssh-agent add should succeed");

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
        let profile = seed_profile(
            state_root.path(),
            Mode::Prf,
            Algorithm::Ed25519,
            vec![UseCase::SshAgent],
        );
        let backend = FakeSeedBackend::new(&[0x24; 32]);
        let client = RecordingSshAgentClient::new();
        let error = add_with_backend(
            &profile,
            &SshAgentAddRequest {
                profile: profile.name.clone(),
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
        assert!(error.to_string().contains("PRF-mode profiles yet"));
    }

    #[test]
    fn rejects_seed_profiles_without_ssh_use() {
        let state_root = tempdir().expect("state root");
        let profile = seed_profile(
            state_root.path(),
            Mode::Seed,
            Algorithm::Ed25519,
            vec![UseCase::Derive],
        );
        let backend = FakeSeedBackend::new(&[0x11; 32]);
        let client = RecordingSshAgentClient::new();
        let error = add_with_backend(
            &profile,
            &SshAgentAddRequest {
                profile: profile.name.clone(),
                comment: None,
                socket: Some(state_root.path().join("agent.sock")),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &backend,
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect_err("ssh use should be required");

        assert_eq!(error.code(), crate::ErrorCode::Unsupported);
        assert!(
            error
                .to_string()
                .contains("not configured with ssh or ssh-agent use")
        );
    }

    #[test]
    fn rejects_seed_profiles_with_non_ed25519_algorithm() {
        let state_root = tempdir().expect("state root");
        let profile = seed_profile(
            state_root.path(),
            Mode::Seed,
            Algorithm::P256,
            vec![UseCase::SshAgent],
        );
        let backend = FakeSeedBackend::new(&[0x33; 32]);
        let client = RecordingSshAgentClient::new();
        let error = add_with_backend(
            &profile,
            &SshAgentAddRequest {
                profile: profile.name.clone(),
                comment: None,
                socket: Some(state_root.path().join("agent.sock")),
                state_dir: Some(state_root.path().to_path_buf()),
            },
            &backend,
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect_err("p256 seed ssh-agent add should stay explicit unsupported");

        assert_eq!(error.code(), crate::ErrorCode::Unsupported);
        assert!(
            error
                .to_string()
                .contains("supports only ed25519 seed profiles")
        );
    }
}
