use crate::model::{
    Algorithm, CapabilityReport, Diagnostic, DiagnosticLevel, Mode, NativeCapabilitySummary,
    TpmStatus, UseCase,
};

use super::subprocess::ProbeSnapshot;

pub fn build_report(
    snapshot: &ProbeSnapshot,
    algorithm: Option<Algorithm>,
    uses: &[UseCase],
) -> CapabilityReport {
    let support = SupportMatrix::from_snapshot(snapshot);
    let mut reasons = Vec::new();
    let mut warnings = snapshot.diagnostics.clone();

    if let Some(summary) = snapshot.manufacturer_summary() {
        reasons.push(summary);
    }

    if support.native_p256_sign || support.native_p256_verify {
        reasons.push(
            "detected TPM ECC P-256 support through algorithms/commands/ecc-curves probing"
                .to_string(),
        );
    }

    if support.prf {
        reasons.push(
            "detected HMAC/keyed-hash and supporting commands; PRF mode is feasible on this backend"
                .to_string(),
        );
    }

    if support.seed {
        reasons.push(
            "detected create/load/unseal support and required subprocess tools; sealed seed fallback is feasible"
                .to_string(),
        );
    }

    if uses
        .iter()
        .any(|use_case| matches!(use_case, UseCase::Encrypt | UseCase::Decrypt))
    {
        warnings.push(Diagnostic {
            level: DiagnosticLevel::Warning,
            code: "MVP_NOT_IMPLEMENTED".to_string(),
            message: "encrypt/decrypt remains out of scope for the current tpm2-derive MVP"
                .to_string(),
        });
    }

    let recommended_mode = recommend_mode(&support, algorithm, uses, &mut reasons);

    CapabilityReport {
        tpm: TpmStatus {
            present: snapshot.tpm_present,
            accessible: snapshot.tpm_accessible,
        },
        native: NativeCapabilitySummary {
            supported_algorithms: support.native_supported_algorithms(),
            supported_uses: support.native_supported_uses(),
        },
        prf_available: Some(support.prf),
        seed_available: Some(support.seed),
        recommended_mode,
        recommendation_reasons: reasons,
        diagnostics: warnings,
    }
}

pub fn report_supports_mode(
    report: &CapabilityReport,
    algorithm: Algorithm,
    uses: &[UseCase],
    mode: Mode,
) -> bool {
    match mode {
        Mode::Native => {
            report.native.supported_algorithms.contains(&algorithm)
                && uses
                    .iter()
                    .all(|use_case| report.native.supported_uses.contains(use_case))
        }
        Mode::Seed => report.seed_available == Some(true),
        Mode::Prf => {
            report.prf_available == Some(true)
                || (matches!(algorithm, Algorithm::P256)
                    && !is_sign_verify_only(uses)
                    && report.seed_available == Some(true))
        }
    }
}

pub fn snapshot_supports_mode(
    snapshot: &ProbeSnapshot,
    algorithm: Algorithm,
    uses: &[UseCase],
    mode: Mode,
) -> bool {
    let support = SupportMatrix::from_snapshot(snapshot);
    match mode {
        Mode::Native => match algorithm {
            Algorithm::P256 => uses.iter().all(|use_case| match use_case {
                UseCase::Sign => support.native_p256_sign,
                UseCase::Verify => support.native_p256_verify,
                _ => false,
            }),
            Algorithm::Ed25519 | Algorithm::Secp256k1 => false,
        },
        Mode::Prf => support.prf,
        Mode::Seed => support.seed,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SupportMatrix {
    native_p256_sign: bool,
    native_p256_verify: bool,
    prf: bool,
    seed: bool,
}

impl SupportMatrix {
    fn from_snapshot(snapshot: &ProbeSnapshot) -> Self {
        let has_ecc = snapshot.has_algorithm("ecc");
        let has_sha256 = snapshot.has_algorithm("sha256");
        let has_hmac = snapshot.has_algorithm("hmac");
        let has_keyedhash = snapshot.has_algorithm("keyedhash");
        let has_p256 = snapshot.has_curve("tpm2_ecc_nist_p256");

        let native_sign = has_ecc
            && has_p256
            && has_sha256
            && snapshot.has_command("tpm2_cc_sign")
            && snapshot.tool_available("tpm2_sign");
        let native_verify = has_ecc
            && has_p256
            && has_sha256
            && snapshot.has_command("tpm2_cc_verifysignature")
            && snapshot.tool_available("tpm2_verifysignature");

        let prf = (has_hmac || has_keyedhash)
            && has_sha256
            && snapshot.has_command("tpm2_cc_create")
            && snapshot.has_command("tpm2_cc_load")
            && (snapshot.has_command("tpm2_cc_hmac") || snapshot.has_command("tpm2_cc_hmac_start"))
            && snapshot.tool_available("tpm2_create")
            && snapshot.tool_available("tpm2_load")
            && snapshot.tool_available("tpm2_hmac");

        let seed = snapshot.has_command("tpm2_cc_create")
            && snapshot.has_command("tpm2_cc_load")
            && snapshot.has_command("tpm2_cc_unseal")
            && snapshot.tool_available("tpm2_create")
            && snapshot.tool_available("tpm2_load")
            && snapshot.tool_available("tpm2_unseal");

        Self {
            native_p256_sign: native_sign,
            native_p256_verify: native_verify,
            prf,
            seed,
        }
    }

    fn native_supported_algorithms(self) -> Vec<Algorithm> {
        if self.native_p256_sign || self.native_p256_verify {
            vec![Algorithm::P256]
        } else {
            Vec::new()
        }
    }

    fn native_supported_uses(self) -> Vec<UseCase> {
        let mut supported = Vec::new();
        if self.native_p256_sign {
            supported.push(UseCase::Sign);
        }
        if self.native_p256_verify {
            supported.push(UseCase::Verify);
        }
        supported
    }
}

fn recommend_mode(
    support: &SupportMatrix,
    algorithm: Option<Algorithm>,
    uses: &[UseCase],
    reasons: &mut Vec<String>,
) -> Option<Mode> {
    let sign_verify_only = is_sign_verify_only(uses);
    let deterministic_workflow = needs_deterministic_output(uses);

    match algorithm {
        Some(Algorithm::P256) if sign_verify_only && support.native_p256_sign => {
            reasons.push(
                "p256 sign/verify workloads prefer native mode when the TPM exposes P-256 signing support"
                    .to_string(),
            );
            Some(Mode::Native)
        }
        Some(Algorithm::Ed25519) => recommend_prf_then_seed(
            support,
            reasons,
            "ed25519 is not expected to be TPM-native on TPM 2.0; prefer PRF and fall back to sealed-seed derivation",
        ),
        Some(Algorithm::Secp256k1) => recommend_prf_then_seed(
            support,
            reasons,
            "secp256k1 is not expected to be TPM-native on TPM 2.0; prefer PRF and fall back to sealed-seed derivation",
        ),
        Some(Algorithm::P256) if deterministic_workflow || !sign_verify_only => {
            reasons.push(
                "requested workflow benefits from deterministic derived output, so PRF is preferred over native signing"
                    .to_string(),
            );
            recommend_prf_seed_native(support)
        }
        Some(Algorithm::P256) => recommend_prf_seed_native(support),
        None if deterministic_workflow => {
            reasons.push(
                "deterministic derivation-oriented uses prefer PRF and fall back to sealed seed when PRF is unavailable"
                    .to_string(),
            );
            recommend_prf_then_seed(
                support,
                reasons,
                "mode chosen from requested uses because no algorithm was supplied",
            )
        }
        None if support.prf => Some(Mode::Prf),
        None if support.seed => Some(Mode::Seed),
        None if support.native_p256_sign => Some(Mode::Native),
        None => {
            reasons.push(
                "capability probe could not find a supported mode recommendation from the current TPM/tooling surface"
                    .to_string(),
            );
            None
        }
    }
}

fn recommend_prf_then_seed(
    support: &SupportMatrix,
    reasons: &mut Vec<String>,
    rationale: &str,
) -> Option<Mode> {
    reasons.push(rationale.to_string());
    if support.prf {
        Some(Mode::Prf)
    } else if support.seed {
        Some(Mode::Seed)
    } else {
        None
    }
}

fn recommend_prf_seed_native(support: &SupportMatrix) -> Option<Mode> {
    if support.prf {
        Some(Mode::Prf)
    } else if support.seed {
        Some(Mode::Seed)
    } else if support.native_p256_sign {
        Some(Mode::Native)
    } else {
        None
    }
}

fn is_sign_verify_only(uses: &[UseCase]) -> bool {
    !uses.is_empty()
        && uses
            .iter()
            .all(|use_case| matches!(use_case, UseCase::Sign | UseCase::Verify))
}

fn needs_deterministic_output(uses: &[UseCase]) -> bool {
    uses.iter().any(|use_case| {
        matches!(
            use_case,
            UseCase::Derive | UseCase::SshAgent
        )
    })
}

#[cfg(test)]
mod tests {
    use crate::model::{Algorithm, Mode, UseCase};

    use super::{SupportMatrix, is_sign_verify_only, needs_deterministic_output, recommend_mode};

    #[test]
    fn detects_sign_verify_only() {
        assert!(is_sign_verify_only(&[UseCase::Sign, UseCase::Verify]));
        assert!(!is_sign_verify_only(&[]));
        assert!(!is_sign_verify_only(&[UseCase::Sign, UseCase::SshAgent]));
    }

    #[test]
    fn detects_deterministic_workflows() {
        assert!(needs_deterministic_output(&[UseCase::Derive]));
        assert!(needs_deterministic_output(&[UseCase::SshAgent]));
        assert!(!needs_deterministic_output(&[UseCase::Sign]));
    }

    #[test]
    fn prefers_native_for_p256_signing() {
        let mut reasons = Vec::new();
        let mode = recommend_mode(
            &SupportMatrix {
                native_p256_sign: true,
                native_p256_verify: true,
                prf: true,
                seed: true,
            },
            Some(Algorithm::P256),
            &[UseCase::Sign],
            &mut reasons,
        );

        assert_eq!(mode, Some(Mode::Native));
        assert!(reasons.iter().any(|reason| reason.contains("native mode")));
    }

    #[test]
    fn prefers_prf_then_seed_for_ed25519() {
        let mut reasons = Vec::new();
        let mode = recommend_mode(
            &SupportMatrix {
                native_p256_sign: false,
                native_p256_verify: false,
                prf: false,
                seed: true,
            },
            Some(Algorithm::Ed25519),
            &[UseCase::SshAgent],
            &mut reasons,
        );

        assert_eq!(mode, Some(Mode::Seed));
        assert!(reasons.iter().any(|reason| reason.contains("ed25519")));
    }
}
