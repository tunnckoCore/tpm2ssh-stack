use crate::model::{
    Algorithm, CapabilityReport, Diagnostic, DiagnosticLevel, Mode, NativeCapabilitySummary,
    TpmStatus, UseCase,
};

use super::CapabilityProbe;

#[derive(Debug, Default, Clone, Copy)]
pub struct TssEsapiCapabilityProbe;

impl CapabilityProbe for TssEsapiCapabilityProbe {
    fn detect(&self, algorithm: Option<Algorithm>, _uses: &[UseCase]) -> CapabilityReport {
        CapabilityReport {
            tpm: TpmStatus {
                present: None,
                accessible: None,
            },
            native: NativeCapabilitySummary {
                algorithms: Vec::new(),
            },
            prf_available: None,
            seed_available: None,
            recommended_mode: algorithm.map(|_| Mode::Seed),
            recommendation_reasons: vec![
                "backend-tss-esapi is reserved for a future typed TPM backend; the subprocess backend remains the active implementation"
                    .to_string(),
            ],
            diagnostics: vec![Diagnostic {
                level: DiagnosticLevel::Warning,
                code: "TSS_ESAPI_BACKEND_STUB".to_string(),
                message:
                    "the optional tss-esapi capability backend is a compile-time placeholder only"
                        .to_string(),
            }],
        }
    }
}
