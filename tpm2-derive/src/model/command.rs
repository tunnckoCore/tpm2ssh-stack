use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::{Algorithm, Mode, ModePreference, Profile, UseCase};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct InspectRequest {
    pub algorithm: Option<Algorithm>,
    pub uses: Vec<UseCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SetupRequest {
    pub profile: String,
    pub algorithm: Algorithm,
    pub uses: Vec<UseCase>,
    pub requested_mode: ModePreference,
    pub state_dir: Option<PathBuf>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SetupResult {
    pub profile: Profile,
    pub dry_run: bool,
    pub persisted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DerivationContext {
    pub version: u32,
    pub purpose: String,
    pub namespace: String,
    pub label: Option<String>,
    pub context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DeriveRequest {
    pub profile: String,
    pub context: DerivationContext,
    pub length: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DeriveResult {
    pub profile: String,
    pub mode: Mode,
    pub length: u16,
    pub encoding: String,
    pub material: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignRequest {
    pub profile: String,
    pub input: InputSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct VerifyRequest {
    pub profile: String,
    pub input: InputSource,
    pub signature: InputSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct EncryptRequest {
    pub profile: String,
    pub input: InputSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DecryptRequest {
    pub profile: String,
    pub input: InputSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExportKind {
    PublicKey,
    RecoveryBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExportRequest {
    pub profile: String,
    pub kind: ExportKind,
    pub output: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub reason: Option<String>,
    pub confirm_recovery_export: bool,
    pub confirm_sealed_at_rest_boundary: bool,
    pub confirmation_phrase: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExportFormat {
    SpkiDer,
    RecoveryBundleJson,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExportArtifact {
    pub format: ExportFormat,
    pub path: PathBuf,
    pub bytes_written: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExportResult {
    pub profile: String,
    pub mode: Mode,
    pub kind: ExportKind,
    pub artifact: ExportArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SshAgentAddRequest {
    pub profile: String,
    pub comment: Option<String>,
    pub socket: Option<PathBuf>,
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
    pub profile: Option<String>,
    pub summary: String,
}
