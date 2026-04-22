use std::env;
use std::io::Write;
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

use crate::backend::{CommandRunner, ProcessCommandRunner};
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
