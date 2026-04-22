//! Encrypt/decrypt operations using symmetric keys derived from identity material.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use secrecy::ExposeSecret;

use crate::backend::CommandRunner;
use crate::error::{Error, Result};
use crate::model::{DecryptResult, DerivationOverrides, EncryptResult, Identity, Mode};

use super::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive,
    seed_profile_from_profile,
};
use super::shared::{
    encrypt_command_spec, execute_prf_derivation_with_runner, resolve_effective_derivation_inputs,
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
