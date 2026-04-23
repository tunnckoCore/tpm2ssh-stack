//! Encrypt/decrypt operations using symmetric keys derived from identity material.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use secrecy::ExposeSecret;

use crate::backend::CommandRunner;
use crate::error::{Error, Result};
use crate::model::{DecryptResult, DerivationOverrides, EncryptResult, Identity, Mode, UseCase};

use super::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive,
    seed_profile_from_profile,
};
use super::shared::{
    encrypt_command_spec, ensure_derivation_overrides_allowed, execute_prf_derivation_with_runner,
    resolve_effective_derivation_inputs,
};

const NONCE_LEN: usize = 12;

pub fn encrypt_with_defaults<R>(
    identity: &Identity,
    plaintext: &[u8],
    derivation: &DerivationOverrides,
    prf_runner: &R,
) -> Result<EncryptResult>
where
    R: CommandRunner,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    encrypt(
        identity,
        plaintext,
        derivation,
        prf_runner,
        &seed_backend,
        &seed_deriver,
    )
}

pub fn encrypt<R, B, D>(
    identity: &Identity,
    plaintext: &[u8],
    derivation: &DerivationOverrides,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<EncryptResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    ensure_derivation_overrides_allowed(identity, derivation)?;
    if !identity.uses.contains(&UseCase::Encrypt) {
        return Err(Error::PolicyRefusal(format!(
            "identity '{}' is not configured with use=encrypt",
            identity.name
        )));
    }

    let key_material =
        derive_symmetric_key(identity, derivation, prf_runner, seed_backend, seed_deriver)?;
    let ciphertext = aead_encrypt(&key_material, plaintext)?;

    Ok(EncryptResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        input_bytes: plaintext.len(),
        ciphertext_bytes: ciphertext.len(),
        nonce_bytes: NONCE_LEN,
        output_path: None,
        encoding: "hex".to_string(),
        ciphertext: Some(hex_encode(&ciphertext)),
    })
}

pub fn decrypt_with_defaults<R>(
    identity: &Identity,
    ciphertext: &[u8],
    derivation: &DerivationOverrides,
    prf_runner: &R,
) -> Result<DecryptResult>
where
    R: CommandRunner,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    decrypt(
        identity,
        ciphertext,
        derivation,
        prf_runner,
        &seed_backend,
        &seed_deriver,
    )
}

pub fn decrypt<R, B, D>(
    identity: &Identity,
    ciphertext: &[u8],
    derivation: &DerivationOverrides,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<DecryptResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    ensure_derivation_overrides_allowed(identity, derivation)?;
    if !identity.uses.contains(&UseCase::Decrypt) {
        return Err(Error::PolicyRefusal(format!(
            "identity '{}' is not configured with use=decrypt",
            identity.name
        )));
    }

    let key_material =
        derive_symmetric_key(identity, derivation, prf_runner, seed_backend, seed_deriver)?;
    let plaintext = aead_decrypt(&key_material, ciphertext)?;

    Ok(DecryptResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        ciphertext_bytes: ciphertext.len(),
        plaintext_bytes: plaintext.len(),
        output_path: None,
        encoding: "hex".to_string(),
        plaintext: Some(hex_encode(&plaintext)),
    })
}

fn derive_symmetric_key<R, B, D>(
    identity: &Identity,
    derivation: &DerivationOverrides,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<[u8; 32]>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    match identity.mode.resolved {
        Mode::Native => Err(Error::Unsupported(
            "encrypt/decrypt with native-mode identities is not implemented yet; native TPM symmetric encrypt would require RSA-OAEP wrapping or TPM2_EncryptDecrypt2 which is not universally available – use a seed or prf identity instead"
                .to_string(),
        )),
        Mode::Seed => derive_seed_symmetric_key(identity, derivation, seed_backend, seed_deriver),
        Mode::Prf => derive_prf_symmetric_key(identity, derivation, prf_runner),
    }
}

fn derive_seed_symmetric_key<B, D>(
    identity: &Identity,
    derivation: &DerivationOverrides,
    backend: &B,
    deriver: &D,
) -> Result<[u8; 32]>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_identity = seed_profile_from_profile(identity)?;
    let effective = resolve_effective_derivation_inputs(identity, derivation)?;
    let spec = encrypt_command_spec(&effective)?;
    let request = SeedOpenRequest {
        identity: seed_identity,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
            spec,
            output_bytes: 32,
        }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    };

    let derived = open_and_derive(backend, deriver, &request)?;
    to_key_bytes(derived.expose_secret())
}

fn derive_prf_symmetric_key<R>(
    identity: &Identity,
    derivation: &DerivationOverrides,
    runner: &R,
) -> Result<[u8; 32]>
where
    R: CommandRunner,
{
    let effective = resolve_effective_derivation_inputs(identity, derivation)?;
    let spec = encrypt_command_spec(&effective)?;
    let material = execute_prf_derivation_with_runner(identity, spec, runner, "encrypt")?;
    to_key_bytes(&material)
}

fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|error| Error::Internal(format!("AEAD encrypt failed: {error}")))?;

    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn aead_decrypt(key: &[u8; 32], envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < NONCE_LEN + 16 {
        return Err(Error::Validation(
            "ciphertext is too short to contain a valid AEAD envelope (nonce + tag)".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = envelope.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key.into());

    cipher.decrypt(nonce, ciphertext).map_err(|_| {
        Error::Validation("AEAD decryption failed: invalid ciphertext or key".to_string())
    })
}

fn to_key_bytes(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        Error::Internal(format!(
            "symmetric key derivation produced {} bytes instead of 32",
            bytes.len()
        ))
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

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
        invocations: RefCell<Vec<CommandInvocation>>,
    }

    impl RecordingPrfRunner {
        fn new(raw_output: &[u8]) -> Self {
            Self {
                raw_output: raw_output.to_vec(),
                invocations: RefCell::new(Vec::new()),
            }
        }

        fn invocations(&self) -> Vec<CommandInvocation> {
            self.invocations.borrow().clone()
        }
    }

    impl CommandRunner for RecordingPrfRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.invocations.borrow_mut().push(invocation.clone());
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

    fn seed_identity(root: &Path) -> Identity {
        Identity::new(
            "seed-box".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Encrypt, UseCase::Decrypt],
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
            "prf-box".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Encrypt, UseCase::Decrypt],
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
        identity.defaults.org = Some("com.example".to_string());
        identity.defaults.purpose = Some("encrypt".to_string());
        identity.defaults.context = BTreeMap::from([("tenant".to_string(), "alpha".to_string())]);
        identity
    }

    #[test]
    fn seed_encrypt_decrypt_round_trip() {
        let state_root = tempdir().expect("state root");
        let identity = seed_identity(state_root.path());
        let backend = FakeSeedBackend::new(&[0x42; 32]);
        let runner = RecordingPrfRunner::new(b"unused");
        let plaintext = b"hello seed encryption";

        let encrypted = encrypt(
            &identity,
            plaintext,
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed encrypt");
        let ciphertext = encrypted
            .ciphertext
            .clone()
            .expect("ciphertext should be inline");
        let decrypted = decrypt(
            &identity,
            &hex_decode(&ciphertext),
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed decrypt");

        assert_eq!(decrypted.mode, Mode::Seed);
        assert_eq!(
            hex_decode(decrypted.plaintext.as_deref().expect("plaintext")),
            plaintext
        );
    }

    #[test]
    fn prf_encrypt_decrypt_round_trip() {
        let state_root = tempdir().expect("state root");
        let identity = prf_identity(state_root.path());
        let backend = FakeSeedBackend::new(&[0x11; 32]);
        let runner = RecordingPrfRunner::new(b"tpm-prf-material");
        let plaintext = b"hello prf encryption";

        let encrypted = encrypt(
            &identity,
            plaintext,
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("prf encrypt");
        let ciphertext = encrypted
            .ciphertext
            .clone()
            .expect("ciphertext should be inline");
        let decrypted = decrypt(
            &identity,
            &hex_decode(&ciphertext),
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("prf decrypt");

        assert_eq!(decrypted.mode, Mode::Prf);
        assert_eq!(
            hex_decode(decrypted.plaintext.as_deref().expect("plaintext")),
            plaintext
        );
        assert_eq!(runner.invocations().len(), 2);
    }

    #[test]
    fn encrypt_requires_encrypt_use() {
        let state_root = tempdir().expect("state root");
        let mut identity = seed_identity(state_root.path());
        identity.uses = vec![UseCase::Decrypt];

        let error = encrypt(
            &identity,
            b"nope",
            &DerivationOverrides::default(),
            &RecordingPrfRunner::new(b"unused"),
            &FakeSeedBackend::new(&[0x01; 32]),
            &HkdfSha256SeedDeriver,
        )
        .expect_err("encrypt should enforce use=encrypt");

        assert!(matches!(error, Error::PolicyRefusal(message) if message.contains("use=encrypt")));
    }

    #[test]
    fn decrypt_requires_decrypt_use() {
        let state_root = tempdir().expect("state root");
        let mut identity = seed_identity(state_root.path());
        identity.uses = vec![UseCase::Encrypt];

        let error = decrypt(
            &identity,
            b"nope",
            &DerivationOverrides::default(),
            &RecordingPrfRunner::new(b"unused"),
            &FakeSeedBackend::new(&[0x01; 32]),
            &HkdfSha256SeedDeriver,
        )
        .expect_err("decrypt should enforce use=decrypt");

        assert!(matches!(error, Error::PolicyRefusal(message) if message.contains("use=decrypt")));
    }

    #[test]
    fn native_encrypt_rejects_truthfully() {
        let state_root = tempdir().expect("state root");
        let identity = Identity::new(
            "native-box".to_string(),
            Algorithm::P256,
            vec![UseCase::Encrypt, UseCase::Decrypt],
            IdentityModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            StateLayout::new(state_root.path().to_path_buf()),
        );
        let error = encrypt(
            &identity,
            b"nope",
            &DerivationOverrides::default(),
            &RecordingPrfRunner::new(b"unused"),
            &FakeSeedBackend::new(&[0x01; 32]),
            &HkdfSha256SeedDeriver,
        )
        .expect_err("native encrypt should fail");

        assert!(
            matches!(error, Error::Unsupported(message) if message.contains("not implemented yet"))
        );
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("utf8"), 16).expect("hex")
            })
            .collect()
    }
}
