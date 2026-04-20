//! Encrypt/decrypt operations using symmetric keys derived from profile material.
//!
//! - **seed** mode: unseal seed, derive a 256-bit symmetric key via HKDF, then
//!   encrypt/decrypt with ChaCha20-Poly1305 AEAD.
//! - **prf** mode: derive key material from the TPM PRF root internally, then
//!   encrypt/decrypt with the same AEAD.
//! - **native** mode: scaffolded – returns an explicit unsupported error with a plan.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use secrecy::ExposeSecret;

use crate::backend::CommandRunner;
use crate::crypto::{DerivationSpec, DerivationSpecV1, OutputKind};
use crate::error::{Error, Result};
use crate::model::{EncryptResult, DecryptResult, Mode, Profile};

use super::prf::{
    PrfRequest, TpmPrfExecutor, TpmPrfKeyHandle, execute_tpm_prf_plan_with_runner,
    plan_tpm_prf_in, PRF_CONTEXT_PATH_METADATA_KEY, PRF_PARENT_CONTEXT_PATH_METADATA_KEY,
    PRF_PRIVATE_PATH_METADATA_KEY, PRF_PUBLIC_PATH_METADATA_KEY,
};
use super::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive,
    seed_profile_from_profile,
};

const ENCRYPT_CHILD_KEY_NAMESPACE: &str = "tpm2-derive.encrypt";
const ENCRYPT_CHILD_KEY_PATH: &str = "m/symmetric/default";

/// AEAD envelope: 12-byte nonce ‖ ciphertext (includes 16-byte Poly1305 tag).
const NONCE_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn encrypt_with_defaults<R>(
    profile: &Profile,
    plaintext: &[u8],
    prf_runner: &R,
) -> Result<EncryptResult>
where
    R: CommandRunner,
{
    let seed_backend = SubprocessSeedBackend::new(profile.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    encrypt(profile, plaintext, prf_runner, &seed_backend, &seed_deriver)
}

pub fn encrypt<R, B, D>(
    profile: &Profile,
    plaintext: &[u8],
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<EncryptResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let key_material = derive_symmetric_key(profile, prf_runner, seed_backend, seed_deriver)?;
    let ciphertext = aead_encrypt(&key_material, plaintext)?;

    Ok(EncryptResult {
        profile: profile.name.clone(),
        mode: profile.mode.resolved,
        algorithm: profile.algorithm,
        input_bytes: plaintext.len(),
        ciphertext_bytes: ciphertext.len(),
        nonce_bytes: NONCE_LEN,
        output_path: None,
        encoding: "hex".to_string(),
        ciphertext: Some(hex_encode(&ciphertext)),
    })
}

pub fn decrypt_with_defaults<R>(
    profile: &Profile,
    ciphertext: &[u8],
    prf_runner: &R,
) -> Result<DecryptResult>
where
    R: CommandRunner,
{
    let seed_backend = SubprocessSeedBackend::new(profile.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    decrypt(profile, ciphertext, prf_runner, &seed_backend, &seed_deriver)
}

pub fn decrypt<R, B, D>(
    profile: &Profile,
    ciphertext: &[u8],
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<DecryptResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let key_material = derive_symmetric_key(profile, prf_runner, seed_backend, seed_deriver)?;
    let plaintext = aead_decrypt(&key_material, ciphertext)?;

    Ok(DecryptResult {
        profile: profile.name.clone(),
        mode: profile.mode.resolved,
        algorithm: profile.algorithm,
        ciphertext_bytes: ciphertext.len(),
        plaintext_bytes: plaintext.len(),
        output_path: None,
        encoding: "hex".to_string(),
        plaintext: Some(hex_encode(&plaintext)),
    })
}

// ---------------------------------------------------------------------------
// Key derivation – mode dispatch
// ---------------------------------------------------------------------------

fn derive_symmetric_key<R, B, D>(
    profile: &Profile,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<[u8; 32]>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    match profile.mode.resolved {
        Mode::Native => Err(Error::Unsupported(
            "encrypt/decrypt with native-mode profiles is not implemented yet; native TPM \
             symmetric encrypt would require RSA-OAEP wrapping or TPM2_EncryptDecrypt2 which \
             is not universally available – use a seed or prf profile instead"
                .to_string(),
        )),
        Mode::Seed => derive_seed_symmetric_key(profile, seed_backend, seed_deriver),
        Mode::Prf => derive_prf_symmetric_key(profile, prf_runner),
    }
}

fn derive_seed_symmetric_key<B, D>(
    profile: &Profile,
    backend: &B,
    deriver: &D,
) -> Result<[u8; 32]>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_profile = seed_profile_from_profile(profile)?;
    let spec = encrypt_derivation_spec()?;
    let request = SeedOpenRequest {
        profile: seed_profile,
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

fn derive_prf_symmetric_key<R>(profile: &Profile, runner: &R) -> Result<[u8; 32]>
where
    R: CommandRunner,
{
    let executor = resolve_prf_executor(profile)?;
    let spec = encrypt_derivation_spec()?;
    let request = PrfRequest::new(profile.name.clone(), spec)?;
    let workspace_root = temporary_workspace_root("encrypt", &profile.name)?;
    let plan = plan_tpm_prf_in(request, executor, &workspace_root)?;
    let execution = execute_tpm_prf_plan_with_runner(&plan, runner);
    let _ = std::fs::remove_dir_all(&workspace_root);

    let result = execution?;
    // The PRF gives us raw material; derive a proper 256-bit symmetric key via
    // the spec's derive_output (HKDF expand).
    let spec2 = encrypt_derivation_spec()?;
    let derived = spec2.derive_output(result.response.output.expose_secret())?;
    to_key_bytes(derived.expose_secret())
}

// ---------------------------------------------------------------------------
// AEAD helpers
// ---------------------------------------------------------------------------

fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Internal(format!("AEAD encrypt failed: {e}")))?;

    // envelope: nonce ‖ ciphertext+tag
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

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::Validation("AEAD decryption failed: invalid ciphertext or key".to_string()))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn encrypt_derivation_spec() -> Result<DerivationSpec> {
    Ok(DerivationSpec::V1(DerivationSpecV1::software_child_key(
        ENCRYPT_CHILD_KEY_NAMESPACE,
        "chacha20poly1305",
        ENCRYPT_CHILD_KEY_PATH,
        OutputKind::SecretBytes,
    )?))
}

fn to_key_bytes(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        Error::Internal(format!(
            "symmetric key derivation produced {} bytes instead of 32",
            bytes.len()
        ))
    })
}

fn resolve_prf_executor(profile: &Profile) -> Result<TpmPrfExecutor> {
    // Reuse the same resolution logic from derive.rs.
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
        "profile '{}' resolved to PRF mode but no PRF root material was found for encrypt/decrypt",
        profile.name
    )))
}

fn resolve_state_path(profile: &Profile, value: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        profile.storage.state_layout.root_dir.join(path)
    }
}

fn temporary_workspace_root(kind: &str, profile: &str) -> Result<std::path::PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::State(format!("system clock error: {e}")))?;
    let sanitized = profile
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
    use crate::model::{
        Algorithm, ModePreference, ModeResolution, StateLayout, UseCase,
    };
    use crate::ops::seed::{SeedCreateRequest, SeedMaterial, SeedProfile, SeedOpenAuthSource};

    // -----------------------------------------------------------------------
    // Fakes
    // -----------------------------------------------------------------------
    struct FakeSeedBackend {
        seed: Vec<u8>,
    }

    impl FakeSeedBackend {
        fn new(seed: &[u8]) -> Self {
            Self { seed: seed.to_vec() }
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

    fn seed_profile_fixture(root: &std::path::Path) -> Profile {
        Profile {
            schema_version: crate::model::PROFILE_SCHEMA_VERSION,
            name: "enc-seed".to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Encrypt, UseCase::Decrypt],
            mode: ModeResolution {
                requested: ModePreference::Seed,
                resolved: Mode::Seed,
                reasons: vec!["seed".to_string()],
            },
            storage: crate::model::ProfileStorage {
                state_layout: StateLayout::new(root.to_path_buf()),
                profile_path: PathBuf::new(),
                root_material_kind: crate::model::RootMaterialKind::SealedSeed,
            },
            export_policy: crate::model::ExportPolicy::for_mode(Mode::Seed),
            metadata: BTreeMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn seed_encrypt_decrypt_round_trip() {
        let root = tempfile::tempdir().unwrap();
        let profile = seed_profile_fixture(root.path());
        let backend = FakeSeedBackend::new(&[0xAA; 32]);
        let deriver = HkdfSha256SeedDeriver;
        let runner = NullRunner;

        let plaintext = b"hello, tpm2-derive encrypt!";
        let enc_result = encrypt(&profile, plaintext, &runner, &backend, &deriver)
            .expect("encrypt should succeed");

        assert_eq!(enc_result.mode, Mode::Seed);
        assert_eq!(enc_result.input_bytes, plaintext.len());

        // Decode hex ciphertext
        let ct_hex = enc_result.ciphertext.as_ref().unwrap();
        let ciphertext = hex_decode(ct_hex);

        let dec_result = decrypt(&profile, &ciphertext, &runner, &backend, &deriver)
            .expect("decrypt should succeed");

        let pt_hex = dec_result.plaintext.as_ref().unwrap();
        let recovered = hex_decode(pt_hex);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_rejects_truncated_ciphertext() {
        let root = tempfile::tempdir().unwrap();
        let profile = seed_profile_fixture(root.path());
        let backend = FakeSeedBackend::new(&[0xBB; 32]);
        let deriver = HkdfSha256SeedDeriver;
        let runner = NullRunner;

        let err = decrypt(&profile, &[0u8; 10], &runner, &backend, &deriver)
            .expect_err("truncated ciphertext should fail");
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let root = tempfile::tempdir().unwrap();
        let profile = seed_profile_fixture(root.path());
        let backend = FakeSeedBackend::new(&[0xCC; 32]);
        let deriver = HkdfSha256SeedDeriver;
        let runner = NullRunner;

        let enc = encrypt(&profile, b"secret", &runner, &backend, &deriver).unwrap();
        let mut ct = hex_decode(enc.ciphertext.as_ref().unwrap());
        // Tamper with last byte (inside tag)
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;

        let err = decrypt(&profile, &ct, &runner, &backend, &deriver)
            .expect_err("tampered ciphertext should fail");
        assert!(err.to_string().contains("AEAD decryption failed"));
    }

    #[test]
    fn native_mode_returns_unsupported() {
        let root = tempfile::tempdir().unwrap();
        let mut profile = seed_profile_fixture(root.path());
        profile.mode.resolved = Mode::Native;

        let backend = FakeSeedBackend::new(&[0xDD; 32]);
        let deriver = HkdfSha256SeedDeriver;
        let runner = NullRunner;

        let err = encrypt(&profile, b"data", &runner, &backend, &deriver)
            .expect_err("native should be unsupported");
        assert!(err.to_string().contains("not implemented yet"));
    }

    // Hex decode helper for tests
    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
