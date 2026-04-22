use crate::model::{
    Algorithm, CapabilityReport, Mode, NativeAlgorithmCapability, NativeCapabilitySummary,
    TpmStatus, UseCase,
};

mod parser;
pub(crate) mod recommend;
mod subprocess;
#[cfg(feature = "backend-tss-esapi")]
mod tss_esapi;

pub use subprocess::{
    CapabilityGroup, CommandInvocation, CommandOutput, CommandRunner, ProcessCommandRunner,
    SubprocessCapabilityProbe, ToolAvailability, default_probe, resolve_trusted_program_path,
};
#[cfg(feature = "backend-tss-esapi")]
pub use tss_esapi::TssEsapiCapabilityProbe;

pub trait CapabilityProbe {
    fn detect(&self, algorithm: Option<Algorithm>, uses: &[UseCase]) -> CapabilityReport;

    fn supports_mode(&self, algorithm: Algorithm, uses: &[UseCase], mode: Mode) -> bool {
        let report = self.detect(Some(algorithm), uses);
        recommend::report_supports_mode(&report, algorithm, uses, mode)
    }
}

#[derive(Debug, Default)]
pub struct HeuristicProbe;

impl CapabilityProbe for HeuristicProbe {
    fn detect(&self, algorithm: Option<Algorithm>, uses: &[UseCase]) -> CapabilityReport {
        let mut recommendation_reasons = vec![
            "heuristic probe assumes the common prototype surface: native p256 sign/verify, TPM PRF, and sealed-seed fallback"
                .to_string(),
        ];
        let diagnostics = Vec::new();

        let native = NativeCapabilitySummary {
            algorithms: vec![NativeAlgorithmCapability {
                algorithm: Algorithm::P256,
                sign: true,
                verify: true,
                encrypt: false,
                decrypt: false,
            }],
        };

        let recommended_mode = algorithm.and_then(|algorithm| {
            [Mode::Native, Mode::Prf, Mode::Seed]
                .into_iter()
                .find(|mode| {
                    recommend::report_supports_mode(
                        &CapabilityReport {
                            tpm: TpmStatus {
                                present: None,
                                accessible: None,
                            },
                            native: native.clone(),
                            prf_available: Some(true),
                            seed_available: Some(true),
                            recommended_mode: None,
                            recommendation_reasons: Vec::new(),
                            diagnostics: Vec::new(),
                        },
                        algorithm,
                        uses,
                        *mode,
                    )
                })
        });

        if recommended_mode == Some(Mode::Native) {
            recommendation_reasons.push(
                "heuristic probe prefers native first when the requested p256 use set is fully supported"
                    .to_string(),
            );
        }

        CapabilityReport {
            tpm: TpmStatus {
                present: None,
                accessible: None,
            },
            native,
            prf_available: Some(true),
            seed_available: Some(true),
            recommended_mode,
            recommendation_reasons,
            diagnostics,
        }
    }
}
