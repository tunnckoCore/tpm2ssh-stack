use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::Diagnostic;

use super::{
    DigestAlgorithm, NativeEcPoint, NativeIdentityCreateRequest, NativeKeyRef, NativeKeySemantics,
    NativeKeyUse, NativePublicKeyEncoding, NativePublicKeyExportRequest, NativeSignRequest,
    NativeSignatureFormat, NativeSignatureScheme, Validate,
};

const OWNER_HIERARCHY: &str = "owner";
const PERSISTENT_HANDLE_MIN: u32 = 0x8100_0000;
const PERSISTENT_HANDLE_MAX: u32 = 0x81ff_ffff;
pub const P256_P1363_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeCommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

impl NativeCommandSpec {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NativeKeyLocator {
    SerializedHandle { path: PathBuf },
    PersistentHandle { handle: String },
    ContextFile { path: PathBuf },
}

impl NativeKeyLocator {
    pub fn as_tpm2_context_arg(&self) -> Result<String> {
        match self {
            Self::SerializedHandle { path } | Self::ContextFile { path } => {
                validate_non_empty_path(path)?;
                Ok(path.display().to_string())
            }
            Self::PersistentHandle { handle } => validate_persistent_handle(handle),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeAuthSource {
    Empty,
    Stdin,
    FilePath(PathBuf),
}

impl NativeAuthSource {
    fn tool_arg(&self) -> Result<Option<String>> {
        match self {
            Self::Empty => Ok(None),
            Self::Stdin => Ok(Some("file:-".to_string())),
            Self::FilePath(path) => {
                validate_non_empty_path(path)?;
                Ok(Some(format!("file:{}", path.display())))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativePersistentHandle {
    pub handle: String,
    pub serialized_handle_path: PathBuf,
}

impl NativePersistentHandle {
    pub fn validated_handle(&self) -> Result<String> {
        validate_non_empty_path(&self.serialized_handle_path)?;
        validate_persistent_handle(&self.handle)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeSetupArtifacts {
    pub scratch_dir: PathBuf,
    pub key_id: String,
    pub persistent: NativePersistentHandle,
}

impl NativeSetupArtifacts {
    pub fn key_ref(&self, identity: &str) -> Result<NativeKeyRef> {
        validate_identifier("identity", identity)?;
        validate_identifier("key_id", &self.key_id)?;
        validate_non_empty_path(&self.scratch_dir)?;

        Ok(NativeKeyRef {
            identity: identity.to_string(),
            key_id: self.key_id.clone(),
        })
    }

    pub fn primary_context_path(&self) -> PathBuf {
        self.scratch_dir.join("primary.ctx")
    }

    pub fn public_blob_path(&self) -> PathBuf {
        self.scratch_dir.join(format!("{}.pub", self.key_id))
    }

    pub fn private_blob_path(&self) -> PathBuf {
        self.scratch_dir.join(format!("{}.priv", self.key_id))
    }

    pub fn loaded_context_path(&self) -> PathBuf {
        self.scratch_dir.join(format!("{}.ctx", self.key_id))
    }

    pub fn name_path(&self) -> PathBuf {
        self.scratch_dir.join(format!("{}.name", self.key_id))
    }

    pub fn retained_locator(&self) -> NativeKeyLocator {
        NativeKeyLocator::SerializedHandle {
            path: self.persistent.serialized_handle_path.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeSetupPlan {
    pub key: NativeKeyRef,
    pub allowed_uses: Vec<NativeKeyUse>,
    pub semantics: NativeKeySemantics,
    pub commands: Vec<NativeCommandSpec>,
    pub retained_locator: NativeKeyLocator,
    pub cleanup_paths: Vec<PathBuf>,
    pub warnings: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeSignArtifacts {
    pub digest_path: PathBuf,
    pub signature_path: PathBuf,
    pub plain_signature_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeSignOptions {
    pub locator: NativeKeyLocator,
    pub auth: NativeAuthSource,
    pub artifacts: NativeSignArtifacts,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeSignPlan {
    pub key: NativeKeyRef,
    pub semantics: NativeKeySemantics,
    pub command: NativeCommandSpec,
    pub output_path: PathBuf,
    pub post_process: Option<NativePostProcessAction>,
    pub warnings: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativePublicKeyExportOptions {
    pub locator: NativeKeyLocator,
    pub output_dir: PathBuf,
    pub file_stem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativePublicKeyExportOutput {
    pub encoding: NativePublicKeyEncoding,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativePublicKeyExportPlan {
    pub key: NativeKeyRef,
    pub semantics: NativeKeySemantics,
    pub commands: Vec<NativeCommandSpec>,
    pub outputs: Vec<NativePublicKeyExportOutput>,
    pub post_process: Vec<NativePostProcessAction>,
    pub cleanup_paths: Vec<PathBuf>,
    pub warnings: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NativePostProcessAction {
    P256PlainToDer {
        input_path: PathBuf,
        output_path: PathBuf,
    },
    ExtractP256Sec1FromSpkiDer {
        input_path: PathBuf,
        output_path: PathBuf,
    },
}

impl NativePostProcessAction {
    pub fn apply(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::P256PlainToDer { .. } => {
                finalize_p256_signature(NativeSignatureFormat::Der, input)
            }
            Self::ExtractP256Sec1FromSpkiDer { .. } => extract_p256_sec1_from_spki_der(input),
        }
    }
}

pub fn plan_setup(
    request: &NativeIdentityCreateRequest,
    artifacts: &NativeSetupArtifacts,
) -> Result<NativeSetupPlan> {
    request.validate()?;
    ensure_signing_setup(request)?;

    let key = artifacts.key_ref(&request.identity)?;
    let persistent_handle = artifacts.persistent.validated_handle()?;
    let primary_context = artifacts.primary_context_path();
    let public_blob = artifacts.public_blob_path();
    let private_blob = artifacts.private_blob_path();
    let loaded_context = artifacts.loaded_context_path();
    let name_path = artifacts.name_path();

    let commands = vec![
        NativeCommandSpec::new(
            "tpm2_createprimary",
            [
                "-C".to_string(),
                OWNER_HIERARCHY.to_string(),
                "-g".to_string(),
                digest_name(DigestAlgorithm::Sha256).to_string(),
                "-c".to_string(),
                primary_context.display().to_string(),
            ],
        ),
        NativeCommandSpec::new(
            "tpm2_create",
            [
                "-C".to_string(),
                primary_context.display().to_string(),
                "-g".to_string(),
                digest_name(DigestAlgorithm::Sha256).to_string(),
                "-G".to_string(),
                tpm2_key_algorithm_spec().to_string(),
                "-a".to_string(),
                tpm2_key_attributes(request.allowed_uses.as_slice()).to_string(),
                "-u".to_string(),
                public_blob.display().to_string(),
                "-r".to_string(),
                private_blob.display().to_string(),
            ],
        ),
        NativeCommandSpec::new(
            "tpm2_load",
            [
                "-C".to_string(),
                primary_context.display().to_string(),
                "-u".to_string(),
                public_blob.display().to_string(),
                "-r".to_string(),
                private_blob.display().to_string(),
                "-c".to_string(),
                loaded_context.display().to_string(),
                "-n".to_string(),
                name_path.display().to_string(),
            ],
        ),
        NativeCommandSpec::new(
            "tpm2_evictcontrol",
            [
                "-C".to_string(),
                OWNER_HIERARCHY.to_string(),
                "-c".to_string(),
                loaded_context.display().to_string(),
                "-o".to_string(),
                artifacts
                    .persistent
                    .serialized_handle_path
                    .display()
                    .to_string(),
                persistent_handle,
            ],
        ),
    ];

    let mut warnings = vec![Diagnostic::info(
        "native-persistent-handle",
        "setup plan persists the TPM key and keeps only a serialized handle; transient TPM-protected blobs should be deleted after setup",
    )];

    if request.key_label.is_some() {
        warnings.push(Diagnostic::info(
            "native-key-label-metadata",
            "key_label is retained as host metadata only; tpm2-tools key creation does not persist an operator label inside the TPM object",
        ));
    }

    Ok(NativeSetupPlan {
        key,
        allowed_uses: request.allowed_uses.clone(),
        semantics: NativeKeySemantics::hardware_backed_non_exportable(),
        commands,
        retained_locator: artifacts.retained_locator(),
        cleanup_paths: vec![
            primary_context,
            public_blob,
            private_blob,
            loaded_context,
            name_path,
        ],
        warnings,
    })
}

pub fn plan_sign(
    request: &NativeSignRequest,
    options: &NativeSignOptions,
) -> Result<NativeSignPlan> {
    request.validate()?;
    ensure_ecdsa_scheme(request.scheme)?;
    validate_non_empty_path(&options.artifacts.digest_path)?;
    validate_non_empty_path(&options.artifacts.signature_path)?;

    let key_context = options.locator.as_tpm2_context_arg()?;
    let mut args = vec![
        "-c".to_string(),
        key_context,
        "-g".to_string(),
        digest_name(request.digest_algorithm).to_string(),
        "-s".to_string(),
        signature_scheme_name(request.scheme).to_string(),
        "-d".to_string(),
        options.artifacts.digest_path.display().to_string(),
        "-f".to_string(),
        "plain".to_string(),
    ];

    if let Some(auth) = options.auth.tool_arg()? {
        args.push("-p".to_string());
        args.push(auth);
    }

    let (command_output_path, post_process, output_path) = match request.format {
        NativeSignatureFormat::P1363 => (
            options.artifacts.signature_path.clone(),
            None,
            options.artifacts.signature_path.clone(),
        ),
        NativeSignatureFormat::Der => {
            let plain_signature_path =
                options
                    .artifacts
                    .plain_signature_path
                    .clone()
                    .ok_or_else(|| {
                        Error::Validation(
                        "DER native-sign planning requires an intermediate plain-signature path"
                            .to_string(),
                    )
                    })?;
            validate_non_empty_path(&plain_signature_path)?;
            (
                plain_signature_path.clone(),
                Some(NativePostProcessAction::P256PlainToDer {
                    input_path: plain_signature_path,
                    output_path: options.artifacts.signature_path.clone(),
                }),
                options.artifacts.signature_path.clone(),
            )
        }
    };

    args.push("-o".to_string());
    args.push(command_output_path.display().to_string());

    let warnings = match options.locator {
        NativeKeyLocator::PersistentHandle { .. } => vec![Diagnostic::warning(
            "native-raw-handle",
            "sign plan uses a raw persistent handle; a serialized handle file is preferable when wiring this into CLI state",
        )],
        NativeKeyLocator::SerializedHandle { .. } | NativeKeyLocator::ContextFile { .. } => {
            Vec::new()
        }
    };

    Ok(NativeSignPlan {
        key: request.key.clone(),
        semantics: NativeKeySemantics::hardware_backed_non_exportable(),
        command: NativeCommandSpec::new("tpm2_sign", args),
        output_path,
        post_process,
        warnings,
    })
}

pub fn plan_export_public_key(
    request: &NativePublicKeyExportRequest,
    options: &NativePublicKeyExportOptions,
) -> Result<NativePublicKeyExportPlan> {
    request.validate()?;
    validate_non_empty_path(&options.output_dir)?;
    validate_identifier("file_stem", &options.file_stem)?;

    let key_context = options.locator.as_tpm2_context_arg()?;
    let mut commands = Vec::new();
    let mut outputs = Vec::new();
    let mut post_process = Vec::new();
    let mut cleanup_paths = Vec::new();
    let mut warnings = Vec::new();

    let needs_der = request.encodings.iter().any(|encoding| {
        matches!(
            encoding,
            NativePublicKeyEncoding::SpkiDer | NativePublicKeyEncoding::Sec1Uncompressed
        )
    });

    let der_path = options
        .output_dir
        .join(format!("{}.spki.der", options.file_stem));
    if needs_der {
        commands.push(NativeCommandSpec::new(
            "tpm2_readpublic",
            [
                "-c".to_string(),
                key_context.clone(),
                "-f".to_string(),
                "der".to_string(),
                "-o".to_string(),
                der_path.display().to_string(),
            ],
        ));
    }

    for encoding in &request.encodings {
        match encoding {
            NativePublicKeyEncoding::SpkiDer => {
                outputs.push(NativePublicKeyExportOutput {
                    encoding: *encoding,
                    path: der_path.clone(),
                });
            }
            NativePublicKeyEncoding::Pem => {
                let pem_path = options
                    .output_dir
                    .join(format!("{}.pem", options.file_stem));
                commands.push(NativeCommandSpec::new(
                    "tpm2_readpublic",
                    [
                        "-c".to_string(),
                        key_context.clone(),
                        "-f".to_string(),
                        "pem".to_string(),
                        "-o".to_string(),
                        pem_path.display().to_string(),
                    ],
                ));
                outputs.push(NativePublicKeyExportOutput {
                    encoding: *encoding,
                    path: pem_path,
                });
            }
            NativePublicKeyEncoding::Tpm2bPublic => {
                let tss_path = options
                    .output_dir
                    .join(format!("{}.tpm2b-public", options.file_stem));
                commands.push(NativeCommandSpec::new(
                    "tpm2_readpublic",
                    [
                        "-c".to_string(),
                        key_context.clone(),
                        "-f".to_string(),
                        "tss".to_string(),
                        "-o".to_string(),
                        tss_path.display().to_string(),
                    ],
                ));
                outputs.push(NativePublicKeyExportOutput {
                    encoding: *encoding,
                    path: tss_path,
                });
            }
            NativePublicKeyEncoding::Sec1Uncompressed => {
                let sec1_path = options
                    .output_dir
                    .join(format!("{}.sec1-uncompressed.bin", options.file_stem));
                post_process.push(NativePostProcessAction::ExtractP256Sec1FromSpkiDer {
                    input_path: der_path.clone(),
                    output_path: sec1_path.clone(),
                });
                outputs.push(NativePublicKeyExportOutput {
                    encoding: *encoding,
                    path: sec1_path,
                });
                if !request
                    .encodings
                    .contains(&NativePublicKeyEncoding::SpkiDer)
                {
                    cleanup_paths.push(der_path.clone());
                }
            }
        }
    }

    if request
        .encodings
        .contains(&NativePublicKeyEncoding::Sec1Uncompressed)
    {
        warnings.push(Diagnostic::info(
            "native-sec1-derived-from-spki",
            "SEC1 uncompressed export is derived from SPKI DER after tpm2_readpublic completes",
        ));
    }

    Ok(NativePublicKeyExportPlan {
        key: request.key.clone(),
        semantics: NativeKeySemantics::hardware_backed_non_exportable(),
        commands,
        outputs,
        post_process,
        cleanup_paths,
        warnings,
    })
}

pub fn finalize_p256_signature(
    format: NativeSignatureFormat,
    plain_signature: &[u8],
) -> Result<Vec<u8>> {
    validate_p256_plain_signature(plain_signature)?;

    match format {
        NativeSignatureFormat::P1363 => Ok(plain_signature.to_vec()),
        NativeSignatureFormat::Der => encode_p256_der_signature(plain_signature),
    }
}

pub fn extract_p256_sec1_from_spki_der(der: &[u8]) -> Result<Vec<u8>> {
    let point = decode_p256_spki_der(der)?;
    let mut sec1 = Vec::with_capacity(1 + point.x.len() + point.y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&point.x);
    sec1.extend_from_slice(&point.y);
    Ok(sec1)
}

pub fn decode_p256_spki_der(der: &[u8]) -> Result<NativeEcPoint> {
    let mut cursor = DerCursor::new(der);
    let spki = cursor.read_tagged(0x30)?;
    cursor.finish()?;

    let mut spki = DerCursor::new(spki);
    let algorithm_identifier = spki.read_tagged(0x30)?;
    let bit_string = spki.read_tagged(0x03)?;
    spki.finish()?;

    let mut algorithm_identifier = DerCursor::new(algorithm_identifier);
    let algorithm_oid = algorithm_identifier.read_tagged(0x06)?;
    let curve_oid = algorithm_identifier.read_tagged(0x06)?;
    algorithm_identifier.finish()?;

    if algorithm_oid != [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] {
        return Err(Error::Validation(
            "SPKI DER did not contain id-ecPublicKey algorithm identifier".to_string(),
        ));
    }

    if curve_oid != [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] {
        return Err(Error::Validation(
            "SPKI DER did not contain prime256v1 / nistP256 curve identifier".to_string(),
        ));
    }

    if bit_string.first().copied() != Some(0x00) {
        return Err(Error::Validation(
            "SPKI public-key bit string must use zero unused bits".to_string(),
        ));
    }

    let encoded_point = &bit_string[1..];
    if encoded_point.len() != 65 || encoded_point.first().copied() != Some(0x04) {
        return Err(Error::Validation(
            "SPKI public key must contain a 65-byte uncompressed P-256 SEC1 point".to_string(),
        ));
    }

    Ok(NativeEcPoint {
        x: encoded_point[1..33].to_vec(),
        y: encoded_point[33..65].to_vec(),
    })
}

fn ensure_signing_setup(request: &NativeIdentityCreateRequest) -> Result<()> {
    if !request.allowed_uses.contains(&NativeKeyUse::Sign) {
        return Err(Error::Unsupported(
            "native subprocess setup currently requires sign capability; verify-only native keys are not wired in this vertical slice"
                .to_string(),
        ));
    }

    Ok(())
}

fn ensure_ecdsa_scheme(scheme: NativeSignatureScheme) -> Result<()> {
    match scheme {
        NativeSignatureScheme::Ecdsa => Ok(()),
    }
}

fn tpm2_key_algorithm_spec() -> &'static str {
    "ecc256"
}

fn tpm2_key_attributes(allowed_uses: &[NativeKeyUse]) -> &'static str {
    if allowed_uses.contains(&NativeKeyUse::Sign) {
        "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda"
    } else {
        "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda"
    }
}

fn signature_scheme_name(scheme: NativeSignatureScheme) -> &'static str {
    match scheme {
        NativeSignatureScheme::Ecdsa => "ecdsa",
    }
}

fn digest_name(algorithm: DigestAlgorithm) -> &'static str {
    match algorithm {
        DigestAlgorithm::Sha256 => "sha256",
        DigestAlgorithm::Sha384 => "sha384",
        DigestAlgorithm::Sha512 => "sha512",
    }
}

fn validate_p256_plain_signature(signature: &[u8]) -> Result<()> {
    if signature.len() != P256_P1363_SIGNATURE_BYTES {
        return Err(Error::Validation(format!(
            "plain P-256 signature must be {P256_P1363_SIGNATURE_BYTES} bytes, got {}",
            signature.len()
        )));
    }

    Ok(())
}

fn encode_p256_der_signature(signature: &[u8]) -> Result<Vec<u8>> {
    let r = der_encode_integer(&signature[..32]);
    let s = der_encode_integer(&signature[32..]);
    let mut body = Vec::with_capacity(r.len() + s.len());
    body.extend_from_slice(&r);
    body.extend_from_slice(&s);

    let mut out = vec![0x30];
    der_push_length(&mut out, body.len())?;
    out.extend_from_slice(&body);
    Ok(out)
}

fn der_encode_integer(raw: &[u8]) -> Vec<u8> {
    let mut value = raw;
    while value.len() > 1 && value.first() == Some(&0) && value[1] < 0x80 {
        value = &value[1..];
    }

    let needs_pad = value.first().is_some_and(|byte| byte & 0x80 != 0);
    let mut out = vec![0x02];
    let encoded_len = value.len() + usize::from(needs_pad);
    der_push_length_infallible(&mut out, encoded_len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(value);
    out
}

fn der_push_length(out: &mut Vec<u8>, len: usize) -> Result<()> {
    if len < 0x80 {
        out.push(len as u8);
        return Ok(());
    }

    let mut encoded = Vec::new();
    let mut remaining = len;
    while remaining > 0 {
        encoded.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    encoded.reverse();

    if encoded.len() > 0xff {
        return Err(Error::Validation(
            "DER length encoding exceeded implementation limits".to_string(),
        ));
    }

    out.push(0x80 | (encoded.len() as u8));
    out.extend_from_slice(&encoded);
    Ok(())
}

fn der_push_length_infallible(out: &mut Vec<u8>, len: usize) {
    der_push_length(out, len).expect("small DER lengths fit");
}

fn validate_persistent_handle(handle: &str) -> Result<String> {
    let trimmed = handle.trim();
    if trimmed.is_empty() {
        return Err(Error::Validation(
            "persistent handle must not be empty".to_string(),
        ));
    }

    let normalized = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let value = u32::from_str_radix(normalized, 16).map_err(|_| {
        Error::Validation(format!(
            "persistent handle must be a hexadecimal value, got {trimmed}"
        ))
    })?;

    if !(PERSISTENT_HANDLE_MIN..=PERSISTENT_HANDLE_MAX).contains(&value) {
        return Err(Error::Validation(format!(
            "persistent handle must be in TPM persistent-object range 0x{PERSISTENT_HANDLE_MIN:08x}..=0x{PERSISTENT_HANDLE_MAX:08x}"
        )));
    }

    Ok(format!("0x{value:08x}"))
}

fn validate_non_empty_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(Error::Validation("path must not be empty".to_string()));
    }

    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Validation(format!("{field} must not be empty")));
    }

    Ok(())
}

struct DerCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_tagged(&mut self, tag: u8) -> Result<&'a [u8]> {
        let actual_tag = self.read_byte()?;
        if actual_tag != tag {
            return Err(Error::Validation(format!(
                "unexpected DER tag: expected 0x{tag:02x}, got 0x{actual_tag:02x}"
            )));
        }

        let len = self.read_len()?;
        if self.offset + len > self.bytes.len() {
            return Err(Error::Validation(
                "DER object length exceeded input size".to_string(),
            ));
        }

        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..start + len])
    }

    fn read_byte(&mut self) -> Result<u8> {
        let byte = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| Error::Validation("unexpected end of DER input".to_string()))?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_len(&mut self) -> Result<usize> {
        let first = self.read_byte()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }

        let count = (first & 0x7f) as usize;
        if count == 0 {
            return Err(Error::Validation(
                "indefinite DER lengths are not supported".to_string(),
            ));
        }

        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | usize::from(self.read_byte()?);
        }
        Ok(len)
    }

    fn finish(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(Error::Validation(
                "DER input contained trailing bytes".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::native::{
        NativeAlgorithm, NativeCurve, NativeHardwareBinding, NativeIdentityCreateRequest,
        NativePrivateKeyPolicy, NativeSignRequest,
    };

    fn setup_request(allowed_uses: Vec<NativeKeyUse>) -> NativeIdentityCreateRequest {
        NativeIdentityCreateRequest {
            identity: "prod-signer".to_string(),
            key_label: Some("API signing key".to_string()),
            algorithm: NativeAlgorithm::P256,
            curve: NativeCurve::NistP256,
            allowed_uses,
            hardware_binding: NativeHardwareBinding::Required,
            private_key_policy: NativePrivateKeyPolicy::NonExportable,
        }
    }

    fn setup_artifacts() -> NativeSetupArtifacts {
        NativeSetupArtifacts {
            scratch_dir: PathBuf::from("/tmp/native-setup"),
            key_id: "p256-signing-key".to_string(),
            persistent: NativePersistentHandle {
                handle: "0x81010001".to_string(),
                serialized_handle_path: PathBuf::from("/tmp/native-state/p256-signing-key.handle"),
            },
        }
    }

    fn sign_request(format: NativeSignatureFormat) -> NativeSignRequest {
        NativeSignRequest {
            key: NativeKeyRef {
                identity: "prod-signer".to_string(),
                key_id: "p256-signing-key".to_string(),
            },
            scheme: NativeSignatureScheme::Ecdsa,
            format,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest: vec![0xabu8; 32],
        }
    }

    #[test]
    fn setup_plan_builds_persistent_native_signing_flow() {
        let plan = plan_setup(
            &setup_request(vec![NativeKeyUse::Sign, NativeKeyUse::Verify]),
            &setup_artifacts(),
        )
        .expect("setup plan");

        assert_eq!(plan.commands.len(), 4);
        assert_eq!(plan.commands[0].program, "tpm2_createprimary");
        assert_eq!(plan.commands[1].program, "tpm2_create");
        assert!(plan.commands[1]
            .args
            .iter()
            .any(|arg| arg == "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda"));
        assert_eq!(plan.commands[3].program, "tpm2_evictcontrol");
        assert_eq!(
            plan.retained_locator,
            NativeKeyLocator::SerializedHandle {
                path: PathBuf::from("/tmp/native-state/p256-signing-key.handle")
            }
        );
        assert!(
            plan.cleanup_paths
                .iter()
                .any(|path| path.ends_with("p256-signing-key.priv"))
        );
    }

    #[test]
    fn setup_plan_rejects_verify_only_vertical_slice() {
        let error = plan_setup(
            &setup_request(vec![NativeKeyUse::Verify]),
            &setup_artifacts(),
        )
        .expect_err("verify-only should not be wired");

        assert!(matches!(error, Error::Unsupported(message) if message.contains("verify-only")));
    }

    #[test]
    fn sign_plan_uses_plain_output_for_p1363() {
        let plan = plan_sign(
            &sign_request(NativeSignatureFormat::P1363),
            &NativeSignOptions {
                locator: NativeKeyLocator::SerializedHandle {
                    path: PathBuf::from("/tmp/native-state/p256-signing-key.handle"),
                },
                auth: NativeAuthSource::Empty,
                artifacts: NativeSignArtifacts {
                    digest_path: PathBuf::from("/tmp/native-sign/digest.bin"),
                    signature_path: PathBuf::from("/tmp/native-sign/signature.bin"),
                    plain_signature_path: None,
                },
            },
        )
        .expect("p1363 sign plan");

        assert_eq!(plan.command.program, "tpm2_sign");
        assert!(
            plan.command
                .args
                .windows(2)
                .any(|pair| pair == ["-f", "plain"])
        );
        assert!(plan.post_process.is_none());
        assert_eq!(
            plan.output_path,
            PathBuf::from("/tmp/native-sign/signature.bin")
        );
    }

    #[test]
    fn sign_plan_requires_intermediate_plain_path_for_der() {
        let error = plan_sign(
            &sign_request(NativeSignatureFormat::Der),
            &NativeSignOptions {
                locator: NativeKeyLocator::PersistentHandle {
                    handle: "0x81010001".to_string(),
                },
                auth: NativeAuthSource::Empty,
                artifacts: NativeSignArtifacts {
                    digest_path: PathBuf::from("/tmp/native-sign/digest.bin"),
                    signature_path: PathBuf::from("/tmp/native-sign/signature.der"),
                    plain_signature_path: None,
                },
            },
        )
        .expect_err("der path should require intermediate plain file");

        assert!(
            matches!(error, Error::Validation(message) if message.contains("intermediate plain-signature path"))
        );
    }

    #[test]
    fn finalize_der_signature_adds_positive_integer_padding() {
        let mut plain = vec![0u8; P256_P1363_SIGNATURE_BYTES];
        plain[0] = 0x80;
        plain[32] = 0x7f;

        let der = finalize_p256_signature(NativeSignatureFormat::Der, &plain).expect("der");

        assert_eq!(der[0], 0x30);
        assert!(der.windows(3).any(|window| window == [0x02, 0x21, 0x00]));
    }

    #[test]
    fn export_plan_builds_der_once_for_spki_and_sec1() {
        let plan = plan_export_public_key(
            &NativePublicKeyExportRequest {
                key: NativeKeyRef {
                    identity: "prod-signer".to_string(),
                    key_id: "p256-signing-key".to_string(),
                },
                encodings: vec![
                    NativePublicKeyEncoding::SpkiDer,
                    NativePublicKeyEncoding::Sec1Uncompressed,
                    NativePublicKeyEncoding::Pem,
                ],
            },
            &NativePublicKeyExportOptions {
                locator: NativeKeyLocator::SerializedHandle {
                    path: PathBuf::from("/tmp/native-state/p256-signing-key.handle"),
                },
                output_dir: PathBuf::from("/tmp/native-export"),
                file_stem: "p256-signing-key".to_string(),
            },
        )
        .expect("export plan");

        assert_eq!(
            plan.commands
                .iter()
                .filter(|command| command.program == "tpm2_readpublic")
                .count(),
            2
        );
        assert_eq!(plan.post_process.len(), 1);
        assert!(
            plan.outputs
                .iter()
                .any(|output| output.encoding == NativePublicKeyEncoding::SpkiDer)
        );
        assert!(
            plan.outputs
                .iter()
                .any(|output| output.encoding == NativePublicKeyEncoding::Sec1Uncompressed)
        );
    }

    #[test]
    fn sec1_can_be_extracted_from_p256_spki_der() {
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        der.extend_from_slice(&[0x11; 32]);
        der.extend_from_slice(&[0x22; 32]);

        let sec1 = extract_p256_sec1_from_spki_der(&der).expect("sec1");
        let point = decode_p256_spki_der(&der).expect("point");

        assert_eq!(sec1.len(), 65);
        assert_eq!(sec1[0], 0x04);
        assert_eq!(point.x, vec![0x11; 32]);
        assert_eq!(point.y, vec![0x22; 32]);
    }
}
