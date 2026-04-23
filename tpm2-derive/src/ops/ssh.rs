use std::env;
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::thread;

use tempfile::Builder as TempfileBuilder;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::SecretKey;
use secrecy::ExposeSecret;
use ssh_key::{
    LineEnding, PrivateKey, PublicKey as SshPublicKey,
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData},
    public::{
        EcdsaPublicKey as SshEcdsaPublicKey, Ed25519PublicKey as SshEd25519PublicKey,
        KeyData as SshKeyData,
    },
};
use zeroize::Zeroizing;

use crate::backend::{CommandRunner, ProcessCommandRunner, resolve_trusted_program_path};
use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};
use crate::error::{Error, Result};
use crate::model::{Algorithm, Identity, SshAddRequest, SshAddResult, UseCase};

use super::keygen::{derive_identity_key_material, normalized_secret_key_bytes};
use super::seed::{HkdfSha256SeedDeriver, SeedBackend, SeedSoftwareDeriver, SubprocessSeedBackend};

trait SshAddClient {
    fn add_private_key(
        &self,
        socket: &VerifiedSocketPath,
        private_key_openssh: &Zeroizing<String>,
    ) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ProcessSshAddClient;

impl SshAddClient for ProcessSshAddClient {
    fn add_private_key(
        &self,
        socket: &VerifiedSocketPath,
        private_key_openssh: &Zeroizing<String>,
    ) -> Result<()> {
        let program = resolve_trusted_program_path("ssh-add").map_err(|error| {
            Error::State(format!("failed to resolve trusted ssh-add binary: {error}"))
        })?;

        #[cfg(unix)]
        let proxy = socket.spawn_proxy()?;
        #[cfg(unix)]
        let ssh_auth_sock = proxy.socket_path();
        #[cfg(not(unix))]
        let ssh_auth_sock = socket.path();

        let mut child = Command::new(program)
            .env_clear()
            .args(["-q", "-"])
            .env("SSH_AUTH_SOCK", ssh_auth_sock)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                Error::State(format!(
                    "failed to spawn ssh-add for socket '{}': {error}",
                    socket.path().display()
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

        #[cfg(unix)]
        proxy.wait()?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        Err(Error::State(if detail.is_empty() {
            format!(
                "ssh-add failed for socket '{}' with status {:?}",
                socket.path().display(),
                output.status.code()
            )
        } else {
            format!(
                "ssh-add failed for socket '{}': {}",
                socket.path().display(),
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

fn add_with_backend<R, B, D, C>(
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
    super::enforce_secret_egress_policy(
        identity,
        "ssh-add",
        "private key material",
        request.confirm,
        request.reason.as_deref(),
    )?;
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
    let private_key_openssh =
        Zeroizing::new(private_key.to_openssh(LineEnding::LF).map_err(|error| {
            Error::Internal(format!(
                "failed to render OpenSSH private key for identity '{}': {error}",
                identity.name
            ))
        })?);

    client.add_private_key(&socket, &private_key_openssh)?;

    Ok(SshAddResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        socket: socket.path().to_path_buf(),
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
        Algorithm::Ed25519 => {
            derive_ed25519_private_key(identity, material.expose_secret(), comment)
        }
        Algorithm::P256 => derive_p256_private_key(identity, material.expose_secret(), comment),
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
    let secret_key = SecretKey::from_slice(scalar.as_ref()).map_err(|error| {
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

pub(crate) fn openssh_private_key_from_material(
    identity: &Identity,
    material: &[u8],
    comment: &str,
) -> Result<Zeroizing<String>> {
    let private_key = match identity.algorithm {
        Algorithm::Ed25519 => derive_ed25519_private_key(identity, material, comment)?,
        Algorithm::P256 => derive_p256_private_key(identity, material, comment)?,
        Algorithm::Secp256k1 => {
            return Err(Error::Unsupported(
                "OpenSSH private-key rendering is not supported for secp256k1 identities"
                    .to_string(),
            ));
        }
    };

    private_key.to_openssh(LineEnding::LF).map_err(|error| {
        Error::Internal(format!(
            "failed to render OpenSSH private key for identity '{}': {error}",
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
            let secret_key = SecretKey::from_slice(scalar.as_ref()).map_err(|error| {
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

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketFingerprint {
    device_id: u64,
    inode: u64,
    status_change_time_secs: i64,
    status_change_time_nanos: i64,
    modified_time_secs: i64,
    modified_time_nanos: i64,
}

#[cfg(unix)]
impl SocketFingerprint {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device_id: metadata.dev(),
            inode: metadata.ino(),
            status_change_time_secs: metadata.ctime(),
            status_change_time_nanos: metadata.ctime_nsec(),
            modified_time_secs: metadata.mtime(),
            modified_time_nanos: metadata.mtime_nsec(),
        }
    }
}

#[derive(Debug)]
struct VerifiedSocketPath {
    path: PathBuf,
    #[cfg(unix)]
    connected_stream: Mutex<Option<UnixStream>>,
}

impl VerifiedSocketPath {
    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    fn spawn_proxy(&self) -> Result<SshAddProxy> {
        let upstream = self
            .connected_stream
            .lock()
            .map_err(|_| {
                Error::State("failed to acquire validated ssh-agent socket lock".to_string())
            })?
            .take()
            .ok_or_else(|| {
                Error::State(format!(
                    "validated ssh-agent socket '{}' was already consumed",
                    self.path.display()
                ))
            })?;
        SshAddProxy::new(&self.path, upstream)
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct SshAddProxy {
    socket_path: PathBuf,
    _temp_dir: tempfile::TempDir,
    forwarder: thread::JoinHandle<Result<()>>,
}

#[cfg(unix)]
impl SshAddProxy {
    fn new(target_path: &Path, upstream: UnixStream) -> Result<Self> {
        let temp_dir = TempfileBuilder::new()
            .prefix("tpm2-derive-ssh-add-proxy-")
            .tempdir()
            .map_err(|error| {
                Error::State(format!(
                    "failed to create ssh-add proxy workspace for '{}': {error}",
                    target_path.display()
                ))
            })?;
        let socket_path = temp_dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).map_err(|error| {
            Error::State(format!(
                "failed to bind ssh-add proxy socket for '{}': {error}",
                target_path.display()
            ))
        })?;
        let target = target_path.to_path_buf();
        let forwarder = thread::spawn(move || proxy_ssh_add_connection(listener, upstream, target));

        Ok(Self {
            socket_path,
            _temp_dir: temp_dir,
            forwarder,
        })
    }

    fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    fn wait(self) -> Result<()> {
        self.forwarder.join().map_err(|_| {
            Error::State("ssh-add proxy thread panicked while forwarding agent traffic".to_string())
        })?
    }
}

#[cfg(unix)]
fn proxy_ssh_add_connection(
    listener: UnixListener,
    upstream: UnixStream,
    target_path: PathBuf,
) -> Result<()> {
    let (downstream, _) = listener.accept().map_err(|error| {
        Error::State(format!(
            "ssh-add proxy failed to accept a client for '{}': {error}",
            target_path.display()
        ))
    })?;
    bridge_unix_streams(upstream, downstream, &target_path)
}

#[cfg(unix)]
fn bridge_unix_streams(
    upstream: UnixStream,
    downstream: UnixStream,
    target_path: &Path,
) -> Result<()> {
    let mut upstream_for_downstream = upstream.try_clone().map_err(|error| {
        Error::State(format!(
            "failed to clone validated ssh-agent stream for '{}': {error}",
            target_path.display()
        ))
    })?;
    let mut downstream_writer = downstream.try_clone().map_err(|error| {
        Error::State(format!(
            "failed to clone ssh-add proxy client stream for '{}': {error}",
            target_path.display()
        ))
    })?;
    let target = target_path.to_path_buf();
    let upstream_to_downstream = thread::spawn(move || -> Result<()> {
        io::copy(&mut upstream_for_downstream, &mut downstream_writer).map_err(|error| {
            Error::State(format!(
                "failed while forwarding agent response bytes for '{}': {error}",
                target.display()
            ))
        })?;
        let _ = downstream_writer.shutdown(std::net::Shutdown::Write);
        Ok(())
    });

    let mut downstream_for_upstream = downstream;
    let mut upstream_writer = upstream;
    io::copy(&mut downstream_for_upstream, &mut upstream_writer).map_err(|error| {
        Error::State(format!(
            "failed while forwarding agent request bytes for '{}': {error}",
            target_path.display()
        ))
    })?;
    let _ = upstream_writer.shutdown(std::net::Shutdown::Write);

    upstream_to_downstream.join().map_err(|_| {
        Error::State(format!(
            "ssh-add proxy forwarding thread panicked for '{}'",
            target_path.display()
        ))
    })?
}

#[cfg(unix)]
fn connect_validated_socket(path: &Path, fingerprint: SocketFingerprint) -> Result<UnixStream> {
    let stream = UnixStream::connect(path).map_err(|error| {
        Error::State(format!(
            "failed to connect to validated ssh-agent socket '{}': {error}",
            path.display()
        ))
    })?;

    let metadata = load_socket_metadata(path)?;
    validate_socket_metadata(path, &metadata)?;
    validate_socket_parent_directory(path)?;
    let current = SocketFingerprint::from_metadata(&metadata);
    if current != fingerprint {
        return Err(Error::Validation(format!(
            "ssh-add socket '{}' changed during validation; refusing to export private key",
            path.display()
        )));
    }

    Ok(stream)
}

fn requested_socket_path(explicit_socket: Option<&Path>) -> Result<PathBuf> {
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

fn load_socket_metadata(path: &Path) -> Result<fs::Metadata> {
    fs::symlink_metadata(path).map_err(|error| {
        Error::State(format!(
            "ssh-add requires a valid agent socket path '{}': {error}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn absolute_socket_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(env::current_dir()
        .map_err(|error| {
            Error::State(format!(
                "failed to resolve current directory while validating ssh-agent socket '{}': {error}",
                path.display()
            ))
        })?
        .join(path))
}

#[cfg(unix)]
fn reject_symlinked_ancestor_components(path: &Path) -> Result<()> {
    let absolute_path = absolute_socket_path(path)?;
    let components: Vec<_> = absolute_path.components().collect();
    let mut current = PathBuf::new();

    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        if index + 1 == components.len() {
            break;
        }

        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            Error::State(format!(
                "failed to inspect ssh-agent socket ancestor '{}': {error}",
                current.display()
            ))
        })?;

        if metadata.file_type().is_symlink() {
            return Err(Error::Validation(format!(
                "ssh-add requires socket ancestor '{}' to not be a symlink",
                current.display()
            )));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn validate_socket_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
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
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(Error::Validation(format!(
            "ssh-add requires socket '{}' to not be writable by group or other users",
            path.display()
        )));
    }

    Ok(())
}

#[cfg(unix)]
fn validate_socket_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
            Error::State(format!(
                "failed to inspect ssh-agent socket parent directory '{}': {error}",
                parent.display()
            ))
        })?;
        if parent_metadata.file_type().is_symlink() {
            return Err(Error::Validation(format!(
                "ssh-add requires socket parent directory '{}' to not be a symlink",
                parent.display()
            )));
        }
        let current_uid = unsafe { libc::geteuid() };
        if parent_metadata.uid() != current_uid {
            return Err(Error::Validation(format!(
                "ssh-add requires socket parent directory '{}' to be owned by the current user",
                parent.display()
            )));
        }
        if parent_metadata.permissions().mode() & 0o022 != 0 {
            return Err(Error::Validation(format!(
                "ssh-add requires socket parent directory '{}' to not be writable by group or other users",
                parent.display()
            )));
        }
    }

    Ok(())
}

fn resolve_socket(explicit_socket: Option<&Path>) -> Result<VerifiedSocketPath> {
    let requested_path = requested_socket_path(explicit_socket)?;

    #[cfg(unix)]
    reject_symlinked_ancestor_components(&requested_path)?;

    let requested_metadata = load_socket_metadata(&requested_path)?;

    #[cfg(unix)]
    if requested_metadata.file_type().is_symlink() {
        return Err(Error::Validation(format!(
            "ssh-add requires '{}' to be a direct Unix-domain socket path, not a symlink",
            requested_path.display()
        )));
    }

    let path = fs::canonicalize(&requested_path).map_err(|error| {
        Error::State(format!(
            "ssh-add requires a valid agent socket path '{}': {error}",
            requested_path.display()
        ))
    })?;

    let metadata = load_socket_metadata(&path)?;
    let _ = requested_metadata;

    #[cfg(unix)]
    {
        validate_socket_metadata(&path, &metadata)?;
        validate_socket_parent_directory(&path)?;
        let connected_stream =
            connect_validated_socket(&path, SocketFingerprint::from_metadata(&metadata))?;
        return Ok(VerifiedSocketPath {
            path,
            connected_stream: Mutex::new(Some(connected_stream)),
        });
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(VerifiedSocketPath { path })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};

    use secrecy::SecretBox;
    use tempfile::tempdir;

    use crate::backend::{CommandInvocation, CommandOutput};
    use crate::model::{
        Algorithm, DerivationOverrides, Identity, IdentityModeResolution, Mode, ModePreference,
        StateLayout, UseCase,
    };
    use crate::ops::prf::PRF_CONTEXT_PATH_METADATA_KEY;
    use crate::ops::seed::{SeedCreateRequest, SeedMaterial, SoftwareSeedDerivationRequest};

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
        sockets: RefCell<Vec<PathBuf>>,
        private_keys: RefCell<Vec<String>>,
    }

    impl RecordingSshAddClient {
        fn keys(&self) -> Vec<String> {
            self.private_keys.borrow().clone()
        }

        fn sockets(&self) -> Vec<PathBuf> {
            self.sockets.borrow().clone()
        }
    }

    impl SshAddClient for RecordingSshAddClient {
        fn add_private_key(
            &self,
            socket: &VerifiedSocketPath,
            private_key_openssh: &Zeroizing<String>,
        ) -> Result<()> {
            self.sockets.borrow_mut().push(socket.path().to_path_buf());
            self.private_keys
                .borrow_mut()
                .push(private_key_openssh.to_string());
            Ok(())
        }
    }

    #[cfg(unix)]
    struct SwappingSeedDeriver {
        socket_path: PathBuf,
        original_listener: RefCell<Option<UnixListener>>,
        replacement_listener: RefCell<Option<UnixListener>>,
    }

    #[cfg(unix)]
    impl SwappingSeedDeriver {
        fn new(socket_path: PathBuf, listener: UnixListener) -> Self {
            Self {
                socket_path,
                original_listener: RefCell::new(Some(listener)),
                replacement_listener: RefCell::new(None),
            }
        }
    }

    #[cfg(unix)]
    impl SeedSoftwareDeriver for SwappingSeedDeriver {
        fn derive(
            &self,
            _seed: &SeedMaterial,
            _request: &SoftwareSeedDerivationRequest,
        ) -> Result<SeedMaterial> {
            self.original_listener.borrow_mut().take();
            std::fs::remove_file(&self.socket_path).expect("remove original socket");
            let replacement =
                UnixListener::bind(&self.socket_path).expect("bind replacement socket");
            self.replacement_listener.borrow_mut().replace(replacement);
            Ok(SecretBox::new(Box::new(vec![0x44; 32])))
        }
    }

    fn seed_identity(root: &Path) -> Identity {
        Identity::new(
            "seed-ssh".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Sign, UseCase::Ssh, UseCase::ExportSecret],
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
            vec![UseCase::Sign, UseCase::Ssh, UseCase::ExportSecret],
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
        assert!(
            matches!(error, Error::Validation(message) if message.contains("direct Unix-domain socket path"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_socket_rejects_symlinked_ancestor_paths() {
        let temp = tempdir().expect("tempdir");
        let safe_dir = temp.path().join("safe");
        let link_dir = temp.path().join("link");
        std::fs::create_dir(&safe_dir).expect("safe dir");
        let socket_path = safe_dir.join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        std::os::unix::fs::symlink(&safe_dir, &link_dir).expect("symlink ancestor");

        let error = resolve_socket(Some(&link_dir.join("agent.sock")))
            .expect_err("symlinked ancestor should be rejected");
        assert!(matches!(error, Error::Validation(message) if message.contains("socket ancestor")));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_socket_pins_canonical_path() {
        let temp = tempdir().expect("tempdir");
        let nested = temp.path().join("nested");
        std::fs::create_dir(&nested).expect("nested dir");
        let socket_path = temp.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        let aliased_path = nested.join("..").join("agent.sock");

        let resolved = resolve_socket(Some(&aliased_path)).expect("socket should validate");
        assert_eq!(resolved.path(), socket_path.as_path());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_socket_rejects_non_socket_paths() {
        let temp = tempdir().expect("tempdir");
        let file_path = temp.path().join("not-a-socket");
        std::fs::write(&file_path, b"nope").expect("file");

        let error = resolve_socket(Some(&file_path)).expect_err("non-socket should be rejected");
        assert!(
            matches!(error, Error::Validation(message) if message.contains("Unix-domain socket"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_socket_accepts_current_user_socket() {
        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");

        let resolved = resolve_socket(Some(&socket_path)).expect("socket should validate");
        assert_eq!(resolved.path(), socket_path.as_path());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_socket_rejects_group_accessible_socket_permissions() {
        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))
            .expect("chmod socket");

        let error =
            resolve_socket(Some(&socket_path)).expect_err("group-accessible socket should fail");
        assert!(
            matches!(error, Error::Validation(message) if message.contains("writable by group or other users"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_socket_rejects_group_writable_parent_directory() {
        let temp = tempdir().expect("tempdir");
        let parent = temp.path().join("agent-dir");
        std::fs::create_dir(&parent).expect("parent dir");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o770))
            .expect("chmod parent");
        let socket_path = parent.join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");

        let error =
            resolve_socket(Some(&socket_path)).expect_err("group-writable parent should fail");
        assert!(
            matches!(error, Error::Validation(message) if message.contains("writable by group or other users"))
        );
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
                socket: Some(socket_path.clone()),
                state_dir: Some(temp.path().to_path_buf()),
                reason: Some("seed ssh-agent use".to_string()),
                confirm: true,
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
        assert_eq!(result.socket, socket_path);
        assert_eq!(client.sockets(), vec![result.socket.clone()]);
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
                socket: Some(socket_path.clone()),
                state_dir: Some(temp.path().to_path_buf()),
                reason: Some("prf ssh-agent use".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"tpm-prf-material"),
            &FakeSeedBackend::new(&[0x00; 32]),
            &HkdfSha256SeedDeriver,
            &client,
        )
        .expect("prf ssh-add");

        assert_eq!(result.mode, Mode::Prf);
        assert!(
            result
                .public_key_openssh
                .starts_with("ecdsa-sha2-nistp256 ")
        );
        assert_eq!(result.socket, socket_path);
        assert_eq!(client.sockets(), vec![result.socket.clone()]);
        assert_eq!(client.keys().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn ssh_add_keeps_preconnected_socket_when_path_is_swapped() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::{Duration, Instant};

        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind socket");
        let accept_listener = listener.try_clone().expect("clone listener");
        accept_listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let accepted_original = Arc::new(AtomicBool::new(false));
        let accepted_original_flag = accepted_original.clone();
        let accepter = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match accept_listener.accept() {
                    Ok((_stream, _addr)) => {
                        accepted_original_flag.store(true, Ordering::SeqCst);
                        return;
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                    Err(_) => return,
                }
            }
        });
        let identity = seed_identity(temp.path());
        let client = RecordingSshAddClient::default();

        let result = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: Some("seed@test".to_string()),
                socket: Some(socket_path.clone()),
                state_dir: Some(temp.path().to_path_buf()),
                reason: Some("seed ssh-agent use".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &FakeSeedBackend::new(&[0x44; 32]),
            &SwappingSeedDeriver::new(socket_path.clone(), listener),
            &client,
        )
        .expect("preconnected validated socket should survive later path swaps");

        accepter.join().expect("accept thread should join");
        assert!(
            accepted_original.load(Ordering::SeqCst),
            "original validated agent socket should receive the pinned connection"
        );
        assert_eq!(result.socket, socket_path);
        assert_eq!(client.sockets(), vec![result.socket.clone()]);
        assert_eq!(client.keys().len(), 1);
    }

    fn assert_zeroizing_string(_: &Zeroizing<String>) {}

    #[test]
    fn openssh_private_key_from_material_returns_zeroizing_secret_text() {
        let temp = tempdir().expect("tempdir");
        let identity = seed_identity(temp.path());
        let private_key = openssh_private_key_from_material(&identity, &[0x22; 32], "seed@test")
            .expect("openssh private key");

        assert_zeroizing_string(&private_key);
        assert!(private_key.contains("BEGIN OPENSSH PRIVATE KEY"));
    }

    #[cfg(unix)]
    #[test]
    fn ssh_add_requires_export_secret_use() {
        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        let mut identity = seed_identity(temp.path());
        identity
            .uses
            .retain(|use_case| !matches!(use_case, UseCase::ExportSecret));

        let error = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: Some("seed@test".to_string()),
                socket: Some(socket_path),
                state_dir: Some(temp.path().to_path_buf()),
                reason: Some("seed ssh-agent use".to_string()),
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &FakeSeedBackend::new(&[0x44; 32]),
            &HkdfSha256SeedDeriver,
            &RecordingSshAddClient::default(),
        )
        .expect_err("ssh-add should require export-secret");

        assert!(
            matches!(error, Error::PolicyRefusal(message) if message.contains("use=export-secret"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_add_requires_confirm_and_reason() {
        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        let identity = seed_identity(temp.path());

        let missing_confirm = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: Some("seed@test".to_string()),
                socket: Some(socket_path.clone()),
                state_dir: Some(temp.path().to_path_buf()),
                reason: Some("seed ssh-agent use".to_string()),
                confirm: false,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &FakeSeedBackend::new(&[0x44; 32]),
            &HkdfSha256SeedDeriver,
            &RecordingSshAddClient::default(),
        )
        .expect_err("ssh-add should require confirm");
        assert!(
            matches!(missing_confirm, Error::Validation(message) if message.contains("--confirm"))
        );

        let missing_reason = add_with_backend(
            &identity,
            &SshAddRequest {
                identity: identity.name.clone(),
                comment: Some("seed@test".to_string()),
                socket: Some(socket_path),
                state_dir: Some(temp.path().to_path_buf()),
                reason: None,
                confirm: true,
                derivation: DerivationOverrides::default(),
            },
            &RecordingPrfRunner::new(b"unused"),
            &FakeSeedBackend::new(&[0x44; 32]),
            &HkdfSha256SeedDeriver,
            &RecordingSshAddClient::default(),
        )
        .expect_err("ssh-add should require reason");
        assert!(
            matches!(missing_reason, Error::Validation(message) if message.contains("--reason"))
        );
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
                reason: Some("native ssh-agent use".to_string()),
                confirm: true,
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
