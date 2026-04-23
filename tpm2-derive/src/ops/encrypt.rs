//! Encrypt/decrypt operations using symmetric keys derived from identity material.

use std::io::{BufRead, BufReader, Cursor, Read, Write, sink};

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

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
const STORED_NONCE_PREFIX_LEN: usize = 8;
const FRAME_LENGTH_BYTES: usize = 4;
const AEAD_TAG_BYTES: usize = 16;
const STREAM_FRAME_PLAINTEXT_BYTES: usize = 64 * 1024;
const STREAM_ENVELOPE_MAGIC: [u8; 8] = *b"TPM2ENC1";

pub(crate) const INLINE_OUTPUT_LIMIT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PlaintextOutputPolicy {
    SuppressInline,
    AllowInline,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct StreamIoStats {
    plaintext_bytes: usize,
    ciphertext_bytes: usize,
}

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
    let mut ciphertext = Vec::new();
    let stats =
        encrypt_reader_to_writer(&key_material, &mut Cursor::new(plaintext), &mut ciphertext)?;

    Ok(EncryptResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        input_bytes: stats.plaintext_bytes,
        ciphertext_bytes: stats.ciphertext_bytes,
        nonce_bytes: NONCE_LEN,
        output_path: None,
        encoding: "hex".to_string(),
        ciphertext: Some(hex_encode(&ciphertext)),
    })
}

pub fn encrypt_stream_with_defaults<R, I, O>(
    identity: &Identity,
    plaintext: &mut I,
    output: &mut O,
    derivation: &DerivationOverrides,
    prf_runner: &R,
) -> Result<EncryptResult>
where
    R: CommandRunner,
    I: Read + ?Sized,
    O: Write + ?Sized,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    encrypt_stream(
        identity,
        plaintext,
        output,
        derivation,
        prf_runner,
        &seed_backend,
        &seed_deriver,
    )
}

pub fn encrypt_stream<R, B, D, I, O>(
    identity: &Identity,
    plaintext: &mut I,
    output: &mut O,
    derivation: &DerivationOverrides,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<EncryptResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
    I: Read + ?Sized,
    O: Write + ?Sized,
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
    let stats = encrypt_reader_to_writer(&key_material, plaintext, output)?;

    Ok(EncryptResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        input_bytes: stats.plaintext_bytes,
        ciphertext_bytes: stats.ciphertext_bytes,
        nonce_bytes: NONCE_LEN,
        output_path: None,
        encoding: "binary".to_string(),
        ciphertext: None,
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
    decrypt_with_defaults_policy(
        identity,
        ciphertext,
        derivation,
        prf_runner,
        PlaintextOutputPolicy::SuppressInline,
    )
}

pub fn decrypt_with_defaults_policy<R>(
    identity: &Identity,
    ciphertext: &[u8],
    derivation: &DerivationOverrides,
    prf_runner: &R,
    plaintext_output: PlaintextOutputPolicy,
) -> Result<DecryptResult>
where
    R: CommandRunner,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    decrypt_with_policy(
        identity,
        ciphertext,
        derivation,
        prf_runner,
        &seed_backend,
        &seed_deriver,
        plaintext_output,
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
    decrypt_with_policy(
        identity,
        ciphertext,
        derivation,
        prf_runner,
        seed_backend,
        seed_deriver,
        PlaintextOutputPolicy::SuppressInline,
    )
}

pub fn decrypt_with_policy<R, B, D>(
    identity: &Identity,
    ciphertext: &[u8],
    derivation: &DerivationOverrides,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
    plaintext_output: PlaintextOutputPolicy,
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
    let (encoding, plaintext, stats) = match plaintext_output {
        PlaintextOutputPolicy::SuppressInline => {
            let mut suppressed_plaintext = sink();
            let stats = decrypt_reader_to_writer(
                &key_material,
                &mut Cursor::new(ciphertext),
                &mut suppressed_plaintext,
            )?;
            ("suppressed".to_string(), None, stats)
        }
        PlaintextOutputPolicy::AllowInline => {
            let mut plaintext = Vec::new();
            let stats = decrypt_reader_to_writer(
                &key_material,
                &mut Cursor::new(ciphertext),
                &mut plaintext,
            )?;
            ("hex".to_string(), Some(hex_encode(&plaintext)), stats)
        }
    };

    Ok(DecryptResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        ciphertext_bytes: stats.ciphertext_bytes,
        plaintext_bytes: stats.plaintext_bytes,
        output_path: None,
        encoding,
        plaintext,
    })
}

pub fn decrypt_stream_with_defaults<R, I, O>(
    identity: &Identity,
    ciphertext: &mut I,
    output: &mut O,
    derivation: &DerivationOverrides,
    prf_runner: &R,
) -> Result<DecryptResult>
where
    R: CommandRunner,
    I: Read + ?Sized,
    O: Write + ?Sized,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    decrypt_stream(
        identity,
        ciphertext,
        output,
        derivation,
        prf_runner,
        &seed_backend,
        &seed_deriver,
    )
}

pub fn decrypt_stream<R, B, D, I, O>(
    identity: &Identity,
    ciphertext: &mut I,
    output: &mut O,
    derivation: &DerivationOverrides,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<DecryptResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
    I: Read + ?Sized,
    O: Write + ?Sized,
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
    let stats = decrypt_reader_to_writer(&key_material, ciphertext, output)?;

    Ok(DecryptResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        ciphertext_bytes: stats.ciphertext_bytes,
        plaintext_bytes: stats.plaintext_bytes,
        output_path: None,
        encoding: "binary".to_string(),
        plaintext: None,
    })
}

pub fn decrypt_ciphertext_to_writer_with_defaults<R, O>(
    identity: &Identity,
    ciphertext: &[u8],
    output: &mut O,
    derivation: &DerivationOverrides,
    prf_runner: &R,
) -> Result<DecryptResult>
where
    R: CommandRunner,
    O: Write + ?Sized,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    decrypt_ciphertext_to_writer(
        identity,
        ciphertext,
        output,
        derivation,
        prf_runner,
        &seed_backend,
        &seed_deriver,
    )
}

pub fn decrypt_ciphertext_to_writer<R, B, D, O>(
    identity: &Identity,
    ciphertext: &[u8],
    output: &mut O,
    derivation: &DerivationOverrides,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<DecryptResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
    O: Write + ?Sized,
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
    let stats = decrypt_reader_to_writer(&key_material, &mut Cursor::new(ciphertext), output)?;

    Ok(DecryptResult {
        identity: identity.name.clone(),
        mode: identity.mode.resolved,
        algorithm: identity.algorithm,
        ciphertext_bytes: stats.ciphertext_bytes,
        plaintext_bytes: stats.plaintext_bytes,
        output_path: None,
        encoding: "binary".to_string(),
        plaintext: None,
    })
}

fn derive_symmetric_key<R, B, D>(
    identity: &Identity,
    derivation: &DerivationOverrides,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<Zeroizing<[u8; 32]>>
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
) -> Result<Zeroizing<[u8; 32]>>
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
) -> Result<Zeroizing<[u8; 32]>>
where
    R: CommandRunner,
{
    let effective = resolve_effective_derivation_inputs(identity, derivation)?;
    let spec = encrypt_command_spec(&effective)?;
    let material = execute_prf_derivation_with_runner(identity, spec, runner, "encrypt")?;
    to_key_bytes(material.expose_secret())
}

fn encrypt_reader_to_writer<I, O>(
    key: &[u8; 32],
    plaintext: &mut I,
    output: &mut O,
) -> Result<StreamIoStats>
where
    I: Read + ?Sized,
    O: Write + ?Sized,
{
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_prefix = [0u8; STORED_NONCE_PREFIX_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_prefix);

    write_all(output, &STREAM_ENVELOPE_MAGIC, "stream ciphertext header")?;
    write_all(output, &nonce_prefix, "stream ciphertext nonce prefix")?;

    let mut plaintext_bytes = 0usize;
    let mut ciphertext_bytes = STREAM_ENVELOPE_MAGIC.len() + STORED_NONCE_PREFIX_LEN;
    let mut chunk_index = 0u32;
    let mut buffer = [0u8; STREAM_FRAME_PLAINTEXT_BYTES];

    loop {
        let read = plaintext
            .read(&mut buffer)
            .map_err(|error| Error::State(format!("failed to read plaintext stream: {error}")))?;
        if read == 0 {
            break;
        }

        plaintext_bytes = checked_add(plaintext_bytes, read, "plaintext")?;
        let nonce = frame_nonce(&nonce_prefix, chunk_index);
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), &buffer[..read])
            .map_err(|error| Error::Internal(format!("AEAD encrypt failed: {error}")))?;
        let frame_length = u32::try_from(read).map_err(|_| {
            Error::Validation("plaintext chunk exceeded the supported frame size".to_string())
        })?;
        write_all(
            output,
            &frame_length.to_le_bytes(),
            "stream ciphertext frame length",
        )?;
        write_all(output, &sealed, "stream ciphertext frame")?;
        ciphertext_bytes = checked_add(
            ciphertext_bytes,
            FRAME_LENGTH_BYTES + sealed.len(),
            "ciphertext",
        )?;
        chunk_index = chunk_index.checked_add(1).ok_or_else(|| {
            Error::Validation("ciphertext exceeded the maximum supported chunk count".to_string())
        })?;
    }

    Ok(StreamIoStats {
        plaintext_bytes,
        ciphertext_bytes,
    })
}

fn decrypt_reader_to_writer<I, O>(
    key: &[u8; 32],
    ciphertext: &mut I,
    output: &mut O,
) -> Result<StreamIoStats>
where
    I: Read + ?Sized,
    O: Write + ?Sized,
{
    let mut reader = BufReader::new(ciphertext);
    let is_stream_envelope = reader
        .fill_buf()
        .map_err(|error| Error::State(format!("failed to inspect ciphertext stream: {error}")))?
        .starts_with(&STREAM_ENVELOPE_MAGIC);

    if is_stream_envelope {
        reader.consume(STREAM_ENVELOPE_MAGIC.len());
        decrypt_stream_envelope_to_writer(key, &mut reader, output)
    } else {
        let mut legacy = Vec::new();
        reader
            .read_to_end(&mut legacy)
            .map_err(|error| Error::State(format!("failed to read ciphertext stream: {error}")))?;
        let plaintext = aead_decrypt_legacy(key, &legacy)?;
        write_all(output, &plaintext, "legacy plaintext output")?;
        Ok(StreamIoStats {
            plaintext_bytes: plaintext.len(),
            ciphertext_bytes: legacy.len(),
        })
    }
}

fn decrypt_stream_envelope_to_writer<O>(
    key: &[u8; 32],
    reader: &mut impl Read,
    output: &mut O,
) -> Result<StreamIoStats>
where
    O: Write + ?Sized,
{
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_prefix = [0u8; STORED_NONCE_PREFIX_LEN];
    reader.read_exact(&mut nonce_prefix).map_err(|error| {
        Error::Validation(format!(
            "ciphertext stream header is truncated before the nonce prefix: {error}"
        ))
    })?;

    let mut plaintext_bytes = 0usize;
    let mut ciphertext_bytes = STREAM_ENVELOPE_MAGIC.len() + STORED_NONCE_PREFIX_LEN;
    let mut chunk_index = 0u32;

    while let Some(frame_length) = read_frame_length(reader)? {
        let frame_plaintext_bytes = usize::try_from(frame_length).map_err(|_| {
            Error::Validation("ciphertext frame length exceeded implementation limits".to_string())
        })?;
        if frame_plaintext_bytes > STREAM_FRAME_PLAINTEXT_BYTES {
            return Err(Error::Validation(format!(
                "ciphertext frame declared {} plaintext bytes; the maximum supported frame size is {} bytes",
                frame_plaintext_bytes, STREAM_FRAME_PLAINTEXT_BYTES
            )));
        }
        if frame_plaintext_bytes == 0 {
            return Err(Error::Validation(
                "ciphertext frame length must not be zero".to_string(),
            ));
        }

        let sealed_len = checked_add(frame_plaintext_bytes, AEAD_TAG_BYTES, "ciphertext frame")?;
        let mut sealed = vec![0u8; sealed_len];
        reader.read_exact(&mut sealed).map_err(|error| {
            Error::Validation(format!(
                "ciphertext stream ended before frame {chunk_index} was fully read: {error}"
            ))
        })?;

        let nonce = frame_nonce(&nonce_prefix, chunk_index);
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), sealed.as_ref())
            .map_err(|_| {
                Error::Validation("AEAD decryption failed: invalid ciphertext or key".to_string())
            })?;
        write_all(output, &plaintext, "plaintext output")?;
        plaintext_bytes = checked_add(plaintext_bytes, plaintext.len(), "plaintext")?;
        ciphertext_bytes = checked_add(
            ciphertext_bytes,
            FRAME_LENGTH_BYTES + sealed.len(),
            "ciphertext",
        )?;
        chunk_index = chunk_index.checked_add(1).ok_or_else(|| {
            Error::Validation("ciphertext exceeded the maximum supported chunk count".to_string())
        })?;
    }

    Ok(StreamIoStats {
        plaintext_bytes,
        ciphertext_bytes,
    })
}

fn read_frame_length(reader: &mut impl Read) -> Result<Option<u32>> {
    let mut first = [0u8; 1];
    let read = reader.read(&mut first).map_err(|error| {
        Error::State(format!("failed to read ciphertext frame header: {error}"))
    })?;
    if read == 0 {
        return Ok(None);
    }

    let mut rest = [0u8; FRAME_LENGTH_BYTES - 1];
    reader.read_exact(&mut rest).map_err(|error| {
        Error::Validation(format!(
            "ciphertext stream ended in the middle of a frame header: {error}"
        ))
    })?;

    let mut header = [0u8; FRAME_LENGTH_BYTES];
    header[0] = first[0];
    header[1..].copy_from_slice(&rest);
    Ok(Some(u32::from_le_bytes(header)))
}

fn frame_nonce(prefix: &[u8; STORED_NONCE_PREFIX_LEN], chunk_index: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..STORED_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[STORED_NONCE_PREFIX_LEN..].copy_from_slice(&chunk_index.to_le_bytes());
    nonce
}

fn write_all(output: &mut (impl Write + ?Sized), bytes: &[u8], label: &str) -> Result<()> {
    output
        .write_all(bytes)
        .map_err(|error| Error::State(format!("failed to write {label}: {error}")))
}

fn checked_add(current: usize, amount: usize, label: &str) -> Result<usize> {
    current
        .checked_add(amount)
        .ok_or_else(|| Error::Validation(format!("{label} exceeded the maximum supported size")))
}

fn aead_encrypt_legacy(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
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

fn aead_decrypt_legacy(key: &[u8; 32], envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < NONCE_LEN + AEAD_TAG_BYTES {
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

fn to_key_bytes(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        Error::Internal(format!(
            "symmetric key derivation produced {} bytes instead of 32",
            bytes.len()
        ))
    })?;
    Ok(Zeroizing::new(key))
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
        let default_decrypt = decrypt(
            &identity,
            &hex_decode(&ciphertext),
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("seed decrypt default");
        let inline_decrypt = decrypt_with_policy(
            &identity,
            &hex_decode(&ciphertext),
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
            PlaintextOutputPolicy::AllowInline,
        )
        .expect("seed decrypt inline");

        assert_eq!(default_decrypt.mode, Mode::Seed);
        assert_eq!(default_decrypt.encoding, "suppressed");
        assert!(default_decrypt.plaintext.is_none());
        assert_eq!(default_decrypt.plaintext_bytes, plaintext.len());
        assert_eq!(
            hex_decode(inline_decrypt.plaintext.as_deref().expect("plaintext")),
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
        let default_decrypt = decrypt(
            &identity,
            &hex_decode(&ciphertext),
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("prf decrypt default");
        let inline_decrypt = decrypt_with_policy(
            &identity,
            &hex_decode(&ciphertext),
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
            PlaintextOutputPolicy::AllowInline,
        )
        .expect("prf decrypt inline");

        assert_eq!(default_decrypt.mode, Mode::Prf);
        assert_eq!(default_decrypt.encoding, "suppressed");
        assert!(default_decrypt.plaintext.is_none());
        assert_eq!(default_decrypt.plaintext_bytes, plaintext.len());
        assert_eq!(
            hex_decode(inline_decrypt.plaintext.as_deref().expect("plaintext")),
            plaintext
        );
        assert_eq!(runner.invocations().len(), 3);
    }

    #[test]
    fn stream_encrypt_decrypt_round_trip_large_payload() {
        let state_root = tempdir().expect("state root");
        let identity = seed_identity(state_root.path());
        let backend = FakeSeedBackend::new(&[0x33; 32]);
        let runner = RecordingPrfRunner::new(b"unused");
        let plaintext = vec![0x7a; STREAM_FRAME_PLAINTEXT_BYTES * 3 + 123];
        let mut ciphertext = Vec::new();

        let encrypt_result = encrypt_stream(
            &identity,
            &mut Cursor::new(&plaintext),
            &mut ciphertext,
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("stream encrypt");
        let mut decrypted = Vec::new();
        let decrypt_result = decrypt_stream(
            &identity,
            &mut Cursor::new(&ciphertext),
            &mut decrypted,
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("stream decrypt");

        assert_eq!(encrypt_result.encoding, "binary");
        assert_eq!(decrypt_result.encoding, "binary");
        assert_eq!(decrypted, plaintext);
        assert!(ciphertext.starts_with(&STREAM_ENVELOPE_MAGIC));
        assert!(encrypt_result.ciphertext.is_none());
        assert!(decrypt_result.plaintext.is_none());
    }

    #[test]
    fn stream_decrypt_accepts_legacy_ciphertext_envelopes() {
        let key = [0x44; 32];
        let plaintext = b"legacy compatibility plaintext";
        let ciphertext = aead_encrypt_legacy(&key, plaintext).expect("legacy encrypt");
        let mut decrypted = Vec::new();

        let stats = decrypt_reader_to_writer(&key, &mut Cursor::new(&ciphertext), &mut decrypted)
            .expect("legacy decrypt through streaming path");

        assert_eq!(stats.ciphertext_bytes, ciphertext.len());
        assert_eq!(stats.plaintext_bytes, plaintext.len());
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_ciphertext_to_writer_avoids_plaintext_hex_round_trip() {
        let state_root = tempdir().expect("state root");
        let identity = seed_identity(state_root.path());
        let backend = FakeSeedBackend::new(&[0x21; 32]);
        let runner = RecordingPrfRunner::new(b"unused");
        let plaintext = b"stream to file";

        let encrypted = encrypt(
            &identity,
            plaintext,
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("encrypt");
        let ciphertext = hex_decode(encrypted.ciphertext.as_deref().expect("ciphertext"));
        let mut output = Vec::new();

        let result = decrypt_ciphertext_to_writer(
            &identity,
            &ciphertext,
            &mut output,
            &DerivationOverrides::default(),
            &runner,
            &backend,
            &HkdfSha256SeedDeriver,
        )
        .expect("decrypt to writer");

        assert_eq!(result.encoding, "binary");
        assert!(result.plaintext.is_none());
        assert_eq!(output, plaintext);
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
