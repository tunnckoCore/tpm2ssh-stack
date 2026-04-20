use crate::model::{
    Algorithm, CapabilityReport, Diagnostic, Mode, NativeCapabilitySummary, TpmStatus, UseCase,
};

pub trait CapabilityProbe {
    fn detect(&self, algorithm: Option<Algorithm>, uses: &[UseCase]) -> CapabilityReport;
}

#[derive(Debug, Default)]
pub struct HeuristicProbe;

impl CapabilityProbe for HeuristicProbe {
    fn detect(&self, algorithm: Option<Algorithm>, uses: &[UseCase]) -> CapabilityReport {
        let mut recommendation_reasons = Vec::new();
        let mut diagnostics = Vec::new();

        let recommended_mode = match algorithm {
            Some(Algorithm::Ed25519) => {
                recommendation_reasons
                    .push("ed25519 is typically not TPM-native on TPM 2.0 chips".to_string());
                Some(Mode::Prf)
            }
            Some(Algorithm::Secp256k1) => {
                recommendation_reasons
                    .push("secp256k1 is typically not TPM-native on TPM 2.0 chips".to_string());
                Some(Mode::Prf)
            }
            Some(Algorithm::P256)
                if uses
                    .iter()
                    .all(|use_case| matches!(use_case, UseCase::Sign | UseCase::Verify)) =>
            {
                recommendation_reasons.push(
                    "p256 sign/verify is the best candidate for native TPM MVP support"
                        .to_string(),
                );
                Some(Mode::Native)
            }
            Some(Algorithm::P256) => {
                recommendation_reasons.push(
                    "p256 supports native, PRF, and seed strategies depending on requested operations"
                        .to_string(),
                );
                Some(Mode::Prf)
            }
            None => None,
        };

        if uses.iter().any(|use_case| {
            matches!(
                use_case,
                UseCase::SshAgent | UseCase::Derive | UseCase::Ethereum
            )
        }) {
            recommendation_reasons.push(
                "requested operation benefits from deterministic derived output; prefer PRF and fall back to seed mode"
                    .to_string(),
            );
        }

        if uses
            .iter()
            .any(|use_case| matches!(use_case, UseCase::Encrypt | UseCase::Decrypt))
        {
            diagnostics.push(Diagnostic::warning(
                "mvp-not-implemented",
                "encrypt/decrypt is planned but not part of the initial scaffold MVP",
            ));
        }

        CapabilityReport {
            tpm: TpmStatus {
                present: None,
                accessible: None,
            },
            native: NativeCapabilitySummary {
                supported_algorithms: vec![Algorithm::P256],
                supported_uses: vec![UseCase::Sign, UseCase::Verify],
            },
            prf_available: None,
            seed_available: None,
            recommended_mode,
            recommendation_reasons,
            diagnostics,
        }
    }
}
