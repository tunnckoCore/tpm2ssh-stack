use serde::{Deserialize, Serialize};

use crate::model::{Algorithm, Diagnostic, Mode, UseCase};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TpmStatus {
    pub present: Option<bool>,
    pub accessible: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeAlgorithmCapability {
    pub algorithm: Algorithm,
    pub sign: bool,
    pub verify: bool,
    pub encrypt: bool,
    pub decrypt: bool,
}

impl NativeAlgorithmCapability {
    pub fn supported_uses(&self) -> Vec<UseCase> {
        let mut supported = Vec::new();
        if self.sign {
            supported.push(UseCase::Sign);
            supported.push(UseCase::Ssh);
            if self.verify {
                supported.push(UseCase::Verify);
            }
        }
        if self.encrypt {
            supported.push(UseCase::Encrypt);
        }
        if self.decrypt {
            supported.push(UseCase::Decrypt);
        }
        supported
    }

    pub fn supports_use(&self, use_case: UseCase) -> bool {
        match use_case {
            UseCase::All => false,
            UseCase::Sign => self.sign,
            UseCase::Verify => self.sign && self.verify,
            UseCase::Ssh => self.sign,
            UseCase::Encrypt => self.encrypt,
            UseCase::Decrypt => self.decrypt,
            UseCase::ExportSecret => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct NativeCapabilitySummary {
    pub algorithms: Vec<NativeAlgorithmCapability>,
}

impl NativeCapabilitySummary {
    pub fn for_algorithm(&self, algorithm: Algorithm) -> Option<&NativeAlgorithmCapability> {
        self.algorithms
            .iter()
            .find(|capability| capability.algorithm == algorithm)
    }

    pub fn supports_use(&self, algorithm: Algorithm, use_case: UseCase) -> bool {
        self.for_algorithm(algorithm)
            .is_some_and(|capability| capability.supports_use(use_case))
    }

    pub fn supported_algorithms(&self) -> Vec<Algorithm> {
        self.algorithms
            .iter()
            .filter(|capability| !capability.supported_uses().is_empty())
            .map(|capability| capability.algorithm)
            .collect()
    }

    pub fn supported_uses(&self, algorithm: Algorithm) -> Vec<UseCase> {
        self.for_algorithm(algorithm)
            .map(NativeAlgorithmCapability::supported_uses)
            .unwrap_or_default()
    }
}

pub fn mode_supported_uses(
    mode: Mode,
    algorithm: Option<Algorithm>,
    native: &NativeCapabilitySummary,
) -> Vec<UseCase> {
    let mut uses = match mode {
        Mode::Native => algorithm
            .map(|algorithm| native.supported_uses(algorithm))
            .unwrap_or_default(),
        Mode::Prf => UseCase::allowed_for_mode(Mode::Prf)
            .iter()
            .copied()
            .filter(|use_case| {
                !matches!(use_case, UseCase::ExportSecret)
                    && !matches!(use_case, UseCase::Ssh)
                        .then_some(())
                        .is_some_and(|_| {
                            !algorithm.is_some_and(|algorithm| {
                                matches!(algorithm, Algorithm::Ed25519 | Algorithm::P256)
                            })
                        })
            })
            .collect(),
        Mode::Seed => UseCase::allowed_for_mode(Mode::Seed)
            .iter()
            .copied()
            .filter(|use_case| {
                !matches!(use_case, UseCase::ExportSecret)
                    && !matches!(use_case, UseCase::Ssh)
                        .then_some(())
                        .is_some_and(|_| {
                            !algorithm.is_some_and(|algorithm| {
                                matches!(algorithm, Algorithm::Ed25519 | Algorithm::P256)
                            })
                        })
            })
            .collect(),
    };
    uses.sort();
    uses.dedup();
    uses
}

pub fn expand_mode_requested_uses(
    mode: Mode,
    algorithm: Option<Algorithm>,
    native: &NativeCapabilitySummary,
    requested_uses: &[UseCase],
) -> Vec<UseCase> {
    let mut expanded = requested_uses
        .iter()
        .copied()
        .filter(|use_case| !use_case.is_all())
        .collect::<Vec<_>>();

    if requested_uses.iter().any(|use_case| use_case.is_all()) {
        expanded.extend(mode_supported_uses(mode, algorithm, native));
    }

    expanded.sort();
    expanded.dedup();
    expanded
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
