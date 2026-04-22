use crate::model::{
    Algorithm, CapabilityReport, Mode, NativeAlgorithmCapability, NativeCapabilitySummary,
    TpmStatus, UseCase, expand_mode_requested_uses,
};

use super::subprocess::ProbeSnapshot;

pub fn build_report(
    snapshot: &ProbeSnapshot,
    algorithm: Option<Algorithm>,
    uses: &[UseCase],
) -> CapabilityReport {
    let support = SupportMatrix::from_snapshot(snapshot);
    let mut reasons = Vec::new();

    if let Some(summary) = snapshot.manufacturer_summary() {
        reasons.push(summary);
    }

    if support
        .native
        .supported_algorithms()
        .contains(&Algorithm::P256)
    {
        reasons.push(
            "detected TPM ECC P-256 sign/verify support through algorithms/commands/ecc-curves probing"
                .to_string(),
        );
        reasons.push(
            "native encrypt/decrypt remains disabled because the current subprocess backend only wires truthful P-256 sign/verify + public-key export flows"
                .to_string(),
        );
    }

    if support.prf {
        reasons.push(
            "detected TPM HMAC/keyed-hash support plus required commands/tools; actual TPM-backed PRF mode is feasible"
                .to_string(),
        );
    }

    if support.seed {
        reasons.push(
            "detected create/load/unseal support plus required commands/tools; sealed-seed mode is feasible"
                .to_string(),
        );
    }

    let recommended_mode = recommend_mode(&support, algorithm, uses, &mut reasons);

    CapabilityReport {
        tpm: TpmStatus {
            present: snapshot.tpm_present,
            accessible: snapshot.tpm_accessible,
        },
        native: support.native,
        prf_available: Some(support.prf),
        seed_available: Some(support.seed),
        recommended_mode,
        recommendation_reasons: reasons,
        diagnostics: snapshot.diagnostics.clone(),
    }
}

pub fn report_supports_mode(
    report: &CapabilityReport,
    algorithm: Algorithm,
    uses: &[UseCase],
    mode: Mode,
) -> bool {
    supports_mode(
        &report.native,
        report.prf_available == Some(true),
        report.seed_available == Some(true),
        Some(algorithm),
        uses,
        mode,
    )
}

pub fn mode_rejection_reason(
    report: &CapabilityReport,
    algorithm: Algorithm,
    uses: &[UseCase],
    mode: Mode,
) -> String {
    unsupported_mode_reason(
        &report.native,
        report.prf_available == Some(true),
        report.seed_available == Some(true),
        Some(algorithm),
        uses,
        mode,
    )
}

pub fn snapshot_supports_mode(
    snapshot: &ProbeSnapshot,
    algorithm: Algorithm,
    uses: &[UseCase],
    mode: Mode,
) -> bool {
    let support = SupportMatrix::from_snapshot(snapshot);
    supports_mode(
        &support.native,
        support.prf,
        support.seed,
        Some(algorithm),
        uses,
        mode,
    )
}

#[derive(Debug, Clone, Default)]
struct SupportMatrix {
    native: NativeCapabilitySummary,
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
            native: NativeCapabilitySummary {
                algorithms: vec![NativeAlgorithmCapability {
                    algorithm: Algorithm::P256,
                    sign: native_sign,
                    verify: native_verify,
                    encrypt: false,
                    decrypt: false,
                }],
            },
            prf,
            seed,
        }
    }
}

fn recommend_mode(
    support: &SupportMatrix,
    algorithm: Option<Algorithm>,
    uses: &[UseCase],
    reasons: &mut Vec<String>,
) -> Option<Mode> {
    for mode in [Mode::Native, Mode::Prf, Mode::Seed] {
        if supports_mode(
            &support.native,
            support.prf,
            support.seed,
            algorithm,
            uses,
            mode,
        ) {
            reasons.push(selection_reason(mode, algorithm, uses));
            return Some(mode);
        }

        reasons.push(unsupported_mode_reason(
            &support.native,
            support.prf,
            support.seed,
            algorithm,
            uses,
            mode,
        ));
    }

    None
}

fn selection_reason(mode: Mode, algorithm: Option<Algorithm>, uses: &[UseCase]) -> String {
    let requested = describe_requested_uses(uses);
    match algorithm {
        Some(algorithm) => {
            format!(
                "{mode:?} mode satisfies the full requested use set {requested} for {algorithm:?}"
            )
        }
        None => format!("{mode:?} mode satisfies the requested use set {requested}"),
    }
}

fn supports_mode(
    native: &NativeCapabilitySummary,
    prf_available: bool,
    seed_available: bool,
    algorithm: Option<Algorithm>,
    uses: &[UseCase],
    mode: Mode,
) -> bool {
    if uses.is_empty() {
        return match mode {
            Mode::Native => algorithm.is_some_and(|algorithm| {
                native
                    .for_algorithm(algorithm)
                    .is_some_and(|capability| !capability.supported_uses().is_empty())
            }),
            Mode::Prf => prf_available,
            Mode::Seed => seed_available,
        };
    }

    let concrete_uses = expand_mode_requested_uses(mode, algorithm, native, uses);
    if uses.iter().any(|use_case| use_case.is_all()) && concrete_uses.is_empty() {
        return false;
    }

    match mode {
        Mode::Native => {
            let Some(algorithm) = algorithm else {
                return false;
            };
            !concrete_uses.is_empty()
                && concrete_uses
                    .iter()
                    .all(|use_case| native.supports_use(algorithm, *use_case))
        }
        Mode::Prf => {
            prf_available
                && concrete_uses
                    .iter()
                    .all(|use_case| UseCase::allowed_for_mode(Mode::Prf).contains(use_case))
        }
        Mode::Seed => {
            seed_available
                && concrete_uses
                    .iter()
                    .all(|use_case| UseCase::allowed_for_mode(Mode::Seed).contains(use_case))
        }
    }
}

fn unsupported_mode_reason(
    native: &NativeCapabilitySummary,
    prf_available: bool,
    seed_available: bool,
    algorithm: Option<Algorithm>,
    uses: &[UseCase],
    mode: Mode,
) -> String {
    let requested = describe_requested_uses(uses);
    match mode {
        Mode::Native => {
            let Some(algorithm) = algorithm else {
                return format!(
                    "Native mode cannot be evaluated for requested uses {requested} without an explicit algorithm"
                );
            };

            let Some(capability) = native.for_algorithm(algorithm) else {
                return format!(
                    "Native mode does not expose truthful support for {algorithm:?} on this TPM/backend"
                );
            };

            let concrete_uses = expand_mode_requested_uses(mode, Some(algorithm), native, uses);
            if uses.iter().any(|use_case| use_case.is_all()) && concrete_uses.is_empty() {
                return format!(
                    "Native mode has no supported actions to expand --use all for {algorithm:?} on this TPM/backend"
                );
            }

            let missing = concrete_uses
                .iter()
                .copied()
                .filter(|use_case| !capability.supports_use(*use_case))
                .collect::<Vec<_>>();
            if missing.is_empty() {
                format!("Native mode cannot satisfy requested uses {requested} for {algorithm:?}")
            } else {
                format!(
                    "Native mode cannot satisfy requested uses {requested} for {algorithm:?}; missing native actions: {}",
                    describe_use_list(&missing)
                )
            }
        }
        Mode::Prf => {
            if !prf_available {
                return "PRF mode is unavailable because the TPM/backend does not expose actual PRF support"
                    .to_string();
            }

            let concrete_uses = expand_mode_requested_uses(mode, algorithm, native, uses);
            let missing = concrete_uses
                .iter()
                .copied()
                .filter(|use_case| !UseCase::allowed_for_mode(Mode::Prf).contains(use_case))
                .collect::<Vec<_>>();
            if missing.is_empty() {
                "PRF mode could not satisfy the request for an unspecified reason".to_string()
            } else {
                format!(
                    "PRF mode does not currently support requested uses {}",
                    describe_use_list(&missing)
                )
            }
        }
        Mode::Seed => {
            if !seed_available {
                return "Seed mode is unavailable because the TPM/backend cannot create/load/unseal sealed seed material"
                    .to_string();
            }

            let concrete_uses = expand_mode_requested_uses(mode, algorithm, native, uses);
            let missing = concrete_uses
                .iter()
                .copied()
                .filter(|use_case| !UseCase::allowed_for_mode(Mode::Seed).contains(use_case))
                .collect::<Vec<_>>();
            if missing.is_empty() {
                "Seed mode could not satisfy the request for an unspecified reason".to_string()
            } else {
                format!(
                    "Seed mode does not currently support requested uses {}",
                    describe_use_list(&missing)
                )
            }
        }
    }
}

fn describe_requested_uses(uses: &[UseCase]) -> String {
    if uses.is_empty() {
        return "[]".to_string();
    }

    describe_use_list(uses)
}

fn describe_use_list(uses: &[UseCase]) -> String {
    format!(
        "[{}]",
        uses.iter()
            .map(|use_case| format!("{use_case:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests {
    use crate::model::{
        Algorithm, Mode, NativeAlgorithmCapability, NativeCapabilitySummary, UseCase,
    };

    use super::{mode_rejection_reason, report_supports_mode, supports_mode};
    use crate::model::{CapabilityReport, TpmStatus};

    fn native_summary(sign: bool, verify: bool) -> NativeCapabilitySummary {
        NativeCapabilitySummary {
            algorithms: vec![NativeAlgorithmCapability {
                algorithm: Algorithm::P256,
                sign,
                verify,
                encrypt: false,
                decrypt: false,
            }],
        }
    }

    fn report(
        native: NativeCapabilitySummary,
        prf_available: bool,
        seed_available: bool,
    ) -> CapabilityReport {
        CapabilityReport {
            tpm: TpmStatus {
                present: Some(true),
                accessible: Some(true),
            },
            native,
            prf_available: Some(prf_available),
            seed_available: Some(seed_available),
            recommended_mode: None,
            recommendation_reasons: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn native_requires_every_requested_action() {
        let native = native_summary(true, true);
        assert!(supports_mode(
            &native,
            true,
            true,
            Some(Algorithm::P256),
            &[UseCase::Sign, UseCase::Verify],
            Mode::Native,
        ));
        assert!(!supports_mode(
            &native,
            true,
            true,
            Some(Algorithm::P256),
            &[UseCase::Sign, UseCase::Encrypt],
            Mode::Native,
        ));
    }

    #[test]
    fn prf_support_matches_the_current_identity_surface() {
        let report = report(native_summary(true, true), true, true);

        for uses in [
            vec![UseCase::Sign],
            vec![UseCase::Verify],
            vec![UseCase::Derive],
            vec![UseCase::Encrypt, UseCase::Decrypt],
            vec![UseCase::Ssh],
            vec![UseCase::ExportSecret],
        ] {
            assert!(report_supports_mode(
                &report,
                Algorithm::P256,
                &uses,
                Mode::Prf
            ));
        }
    }

    #[test]
    fn use_all_expands_against_candidate_mode() {
        let report = report(native_summary(true, true), true, true);

        assert!(report_supports_mode(
            &report,
            Algorithm::P256,
            &[UseCase::All],
            Mode::Native,
        ));
        assert!(report_supports_mode(
            &report,
            Algorithm::P256,
            &[UseCase::All],
            Mode::Prf,
        ));
        assert!(report_supports_mode(
            &report,
            Algorithm::P256,
            &[UseCase::All],
            Mode::Seed,
        ));
    }

    #[test]
    fn explicit_prf_request_does_not_fall_back_to_seed() {
        let report = report(native_summary(true, true), false, true);
        assert!(!report_supports_mode(
            &report,
            Algorithm::Ed25519,
            &[UseCase::Derive],
            Mode::Prf,
        ));

        let reason =
            mode_rejection_reason(&report, Algorithm::Ed25519, &[UseCase::Derive], Mode::Prf);
        assert!(reason.contains("actual PRF support"));
    }

    #[test]
    fn rejection_reason_lists_missing_native_actions() {
        let report = report(native_summary(true, false), true, true);
        let reason = mode_rejection_reason(
            &report,
            Algorithm::P256,
            &[UseCase::Sign, UseCase::Verify],
            Mode::Native,
        );

        assert!(reason.contains("Verify"));
    }
}
