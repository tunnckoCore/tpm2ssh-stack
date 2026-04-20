use serde::{Deserialize, Serialize};

use crate::model::{Algorithm, Diagnostic, Mode, UseCase};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TpmStatus {
    pub present: Option<bool>,
    pub accessible: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeCapabilitySummary {
    pub supported_algorithms: Vec<Algorithm>,
    pub supported_uses: Vec<UseCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CapabilityReport {
    pub tpm: TpmStatus,
    pub native: NativeCapabilitySummary,
    pub prf_available: Option<bool>,
    pub seed_available: Option<bool>,
    pub recommended_mode: Option<Mode>,
    pub recommendation_reasons: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}
