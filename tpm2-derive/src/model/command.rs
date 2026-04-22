use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::{Algorithm, Identity, Mode, ModePreference, UseCase};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct InspectRequest {
    pub algorithm: Option<Algorithm>,
    pub uses: Vec<UseCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct IdentityCreateRequest {
    pub identity: String,
    pub algorithm: Algorithm,
    pub uses: Vec<UseCase>,
    pub requested_mode: ModePreference,
    pub defaults: DerivationOverrides,
    pub state_dir: Option<PathBuf>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct IdentityCreateResult {
    pub identity: Identity,
    pub dry_run: bool,
    pub persisted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct DerivationOverrides {
    pub org: Option<String>,
    pub purpose: Option<String>,
    pub context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DeriveRequest {
    pub identity: String,
    pub derivation: DerivationOverrides,
    pub length: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DeriveResult {
    pub identity: String,
    pub mode: Mode,
    pub length: u16,
    pub encoding: String,
    pub material: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignRequest {
    pub identity: String,
    pub input: InputSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct VerifyRequest {
    pub identity: String,
    pub input: InputSource,
    pub signature: InputSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct EncryptRequest {
    pub identity: String,
    pub input: InputSource,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct EncryptResult {
    pub identity: String,
    pub mode: Mode,
    pub algorithm: Algorithm,
    pub input_bytes: usize,
    pub ciphertext_bytes: usize,
    pub nonce_bytes: usize,
    pub output_path: Option<PathBuf>,
    pub encoding: String,
    pub ciphertext: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DecryptRequest {
    pub identity: String,
    pub input: InputSource,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DecryptResult {
    pub identity: String,
    pub mode: Mode,
    pub algorithm: Algorithm,
    pub ciphertext_bytes: usize,
    pub plaintext_bytes: usize,
    pub output_path: Option<PathBuf>,
    pub encoding: String,
    pub plaintext: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum KeygenKind {
    Auto,
    Prf,
    Seed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum KeygenFormat {
    Hex,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct KeygenRequest {
    pub identity: String,
    pub kind: KeygenKind,
    pub format: KeygenFormat,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct KeygenResult {
    pub identity: String,
    pub mode: Mode,
    pub algorithm: Algorithm,
    pub secret_key_hex: String,
    pub public_key_hex: String,
    pub output_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExportKind {
    PublicKey,
    RecoveryBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExportRequest {
    pub identity: String,
    pub kind: ExportKind,
    pub output: Option<PathBuf>,
    pub public_key_format: Option<PublicKeyExportFormat>,
    pub state_dir: Option<PathBuf>,
    pub reason: Option<String>,
    pub confirm: bool,
    pub confirm_phrase: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PublicKeyExportFormat {
    SpkiDer,
    SpkiPem,
    SpkiHex,
    Openssh,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExportFormat {
    SpkiDer,
    SpkiPem,
    SpkiHex,
    Openssh,
    RecoveryBundleJson,
}

impl From<PublicKeyExportFormat> for ExportFormat {
    fn from(value: PublicKeyExportFormat) -> Self {
        match value {
            PublicKeyExportFormat::SpkiDer => Self::SpkiDer,
            PublicKeyExportFormat::SpkiPem => Self::SpkiPem,
            PublicKeyExportFormat::SpkiHex => Self::SpkiHex,
            PublicKeyExportFormat::Openssh => Self::Openssh,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExportArtifact {
    pub format: ExportFormat,
    pub path: PathBuf,
    pub bytes_written: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExportResult {
    pub identity: String,
    pub mode: Mode,
    pub kind: ExportKind,
    pub artifact: ExportArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RecoveryImportRequest {
    pub bundle_path: PathBuf,
    pub identity: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub overwrite_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RecoveryImportResult {
    pub identity: Identity,
    pub restored_from_identity: String,
    pub seed_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SshAddRequest {
    pub identity: String,
    pub comment: Option<String>,
    pub socket: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SshAddResult {
    pub identity: String,
    pub mode: Mode,
    pub algorithm: Algorithm,
    pub socket: PathBuf,
    pub comment: String,
    pub public_key_openssh: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum InputSource {
    Stdin,
    Path { path: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PendingOperation {
    pub implemented: bool,
    pub operation: String,
    pub identity: Option<String>,
    pub summary: String,
}
