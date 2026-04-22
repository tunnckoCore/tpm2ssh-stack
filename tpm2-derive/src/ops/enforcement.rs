//! Tests for mode/use enforcement rules across the entire ops surface.

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::backend::{CapabilityProbe, HeuristicProbe};
    use crate::error::Error;
    use crate::model::{
        Algorithm, CapabilityReport, Mode, ModePreference, NativeAlgorithmCapability,
        NativeCapabilitySummary, SetupRequest, TpmStatus, UseCase,
    };
    use crate::ops;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "tpm2-derive-enforcement-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    /// A probe that always recommends the requested mode.
    #[derive(Debug, Clone)]
    struct AlwaysAvailableProbe;

    impl CapabilityProbe for AlwaysAvailableProbe {
        fn detect(&self, _algorithm: Option<Algorithm>, _uses: &[UseCase]) -> CapabilityReport {
            CapabilityReport {
                tpm: TpmStatus {
                    present: Some(true),
                    accessible: Some(true),
                },
                native: NativeCapabilitySummary {
                    algorithms: vec![NativeAlgorithmCapability {
                        algorithm: Algorithm::P256,
                        sign: true,
                        verify: true,
                        encrypt: false,
                        decrypt: false,
                    }],
                },
                prf_available: Some(true),
                seed_available: Some(true),
                recommended_mode: Some(Mode::Seed),
                recommendation_reasons: vec!["test probe".to_string()],
                diagnostics: Vec::new(),
            }
        }
    }

    // ── UseCase::validate_for_mode unit tests ───────────────────────

    #[test]
    fn validate_prf_allows_derive_encrypt_and_decrypt() {
        UseCase::validate_for_mode(
            &[UseCase::Derive, UseCase::Encrypt, UseCase::Decrypt],
            Mode::Prf,
        )
        .expect("prf should allow derive + encrypt + decrypt");
    }

    #[test]
    fn validate_prf_rejects_sign() {
        let error = UseCase::validate_for_mode(&[UseCase::Sign], Mode::Prf)
            .expect_err("prf should reject sign");
        assert!(matches!(error, Error::PolicyRefusal(_)));
        assert!(error.to_string().contains("not allowed in Prf mode"));
    }

    #[test]
    fn validate_prf_rejects_verify() {
        let error = UseCase::validate_for_mode(&[UseCase::Verify], Mode::Prf)
            .expect_err("prf should reject verify");
        assert!(matches!(error, Error::PolicyRefusal(_)));
    }

    #[test]
    fn validate_prf_rejects_ssh_agent() {
        let error = UseCase::validate_for_mode(&[UseCase::SshAgent], Mode::Prf)
            .expect_err("prf should reject ssh-agent until ssh-add is wired");
        assert!(matches!(error, Error::PolicyRefusal(_)));
    }

    #[test]
    fn validate_native_allows_sign_and_verify() {
        UseCase::validate_for_mode(&[UseCase::Sign, UseCase::Verify], Mode::Native)
            .expect("native should allow sign + verify");
    }

    #[test]
    fn validate_native_rejects_derive() {
        let error = UseCase::validate_for_mode(&[UseCase::Derive], Mode::Native)
            .expect_err("native should reject derive");
        assert!(matches!(error, Error::PolicyRefusal(_)));
        assert!(error.to_string().contains("not allowed in Native mode"));
    }

    #[test]
    fn validate_native_rejects_ssh_agent() {
        let error = UseCase::validate_for_mode(&[UseCase::SshAgent], Mode::Native)
            .expect_err("native should reject ssh-agent");
        assert!(matches!(error, Error::PolicyRefusal(_)));
    }

    #[test]
    fn validate_native_rejects_encrypt() {
        let error = UseCase::validate_for_mode(&[UseCase::Encrypt], Mode::Native)
            .expect_err("native should reject encrypt");
        assert!(matches!(error, Error::PolicyRefusal(_)));
    }

    #[test]
    fn validate_native_rejects_decrypt() {
        let error = UseCase::validate_for_mode(&[UseCase::Decrypt], Mode::Native)
            .expect_err("native should reject decrypt");
        assert!(matches!(error, Error::PolicyRefusal(_)));
    }

    #[test]
    fn validate_seed_allows_everything() {
        for use_case in [
            UseCase::Sign,
            UseCase::Verify,
            UseCase::Derive,
            UseCase::SshAgent,
            UseCase::Encrypt,
            UseCase::Decrypt,
        ] {
            UseCase::validate_for_mode(&[use_case], Mode::Seed)
                .unwrap_or_else(|_| panic!("seed should allow {:?}", use_case));
        }
    }

    // ── Setup-time enforcement tests ────────────────────────────────

    #[test]
    fn setup_rejects_native_mode_with_derive_use() {
        let root_dir = unique_temp_path("setup-native-derive");
        let error = ops::resolve_profile(
            &HeuristicProbe,
            &SetupRequest {
                profile: "test-native-derive".to_string(),
                algorithm: Algorithm::P256,
                uses: vec![UseCase::Derive],
                requested_mode: ModePreference::Native,
                state_dir: Some(root_dir.clone()),
                dry_run: true,
            },
        )
        .expect_err("native + derive should fail at setup");

        assert!(matches!(
            error,
            Error::PolicyRefusal(_) | Error::CapabilityMismatch(_)
        ));
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_rejects_native_mode_with_ssh_agent() {
        let root_dir = unique_temp_path("setup-native-ssh");
        let error = ops::resolve_profile(
            &HeuristicProbe,
            &SetupRequest {
                profile: "test-native-ssh".to_string(),
                algorithm: Algorithm::P256,
                uses: vec![UseCase::SshAgent],
                requested_mode: ModePreference::Native,
                state_dir: Some(root_dir.clone()),
                dry_run: true,
            },
        )
        .expect_err("native + ssh-agent should fail at setup");

        assert!(matches!(
            error,
            Error::PolicyRefusal(_) | Error::CapabilityMismatch(_)
        ));
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_rejects_prf_mode_with_sign_use() {
        let root_dir = unique_temp_path("setup-prf-sign");
        let error = ops::resolve_profile(
            &AlwaysAvailableProbe,
            &SetupRequest {
                profile: "test-prf-sign".to_string(),
                algorithm: Algorithm::Ed25519,
                uses: vec![UseCase::Sign],
                requested_mode: ModePreference::Prf,
                state_dir: Some(root_dir.clone()),
                dry_run: true,
            },
        )
        .expect_err("prf + sign should fail at setup");

        assert!(matches!(
            error,
            Error::PolicyRefusal(_) | Error::CapabilityMismatch(_)
        ));
        assert!(error.to_string().contains("PRF mode"));
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_rejects_prf_mode_with_verify_use() {
        let root_dir = unique_temp_path("setup-prf-verify");
        let error = ops::resolve_profile(
            &AlwaysAvailableProbe,
            &SetupRequest {
                profile: "test-prf-verify".to_string(),
                algorithm: Algorithm::Ed25519,
                uses: vec![UseCase::Verify],
                requested_mode: ModePreference::Prf,
                state_dir: Some(root_dir.clone()),
                dry_run: true,
            },
        )
        .expect_err("prf + verify should fail at setup");

        assert!(matches!(
            error,
            Error::PolicyRefusal(_) | Error::CapabilityMismatch(_)
        ));
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_allows_prf_mode_with_derive_use() {
        let root_dir = unique_temp_path("setup-prf-derive");
        let result = ops::resolve_profile(
            &AlwaysAvailableProbe,
            &SetupRequest {
                profile: "test-prf-derive".to_string(),
                algorithm: Algorithm::Ed25519,
                uses: vec![UseCase::Derive],
                requested_mode: ModePreference::Prf,
                state_dir: Some(root_dir.clone()),
                dry_run: true,
            },
        )
        .expect("prf + derive should succeed at setup (dry-run)");

        assert_eq!(result.profile.mode.resolved, Mode::Prf);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_allows_seed_mode_with_everything() {
        let root_dir = unique_temp_path("setup-seed-all");
        let result = ops::resolve_profile(
            &AlwaysAvailableProbe,
            &SetupRequest {
                profile: "test-seed-all".to_string(),
                algorithm: Algorithm::Ed25519,
                uses: vec![
                    UseCase::Sign,
                    UseCase::Verify,
                    UseCase::Derive,
                    UseCase::SshAgent,
                    UseCase::Encrypt,
                    UseCase::Decrypt,
                ],
                requested_mode: ModePreference::Seed,
                state_dir: Some(root_dir.clone()),
                dry_run: true,
            },
        )
        .expect("seed + all uses should succeed at setup (dry-run)");

        assert_eq!(result.profile.mode.resolved, Mode::Seed);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_allows_native_mode_with_sign_verify() {
        let root_dir = unique_temp_path("setup-native-sign-verify");
        let result = ops::resolve_profile(
            &HeuristicProbe,
            &SetupRequest {
                profile: "test-native-sv".to_string(),
                algorithm: Algorithm::P256,
                uses: vec![UseCase::Sign, UseCase::Verify],
                requested_mode: ModePreference::Native,
                state_dir: Some(root_dir.clone()),
                dry_run: true,
            },
        )
        .expect("native + sign+verify should succeed at setup (dry-run)");

        assert_eq!(result.profile.mode.resolved, Mode::Native);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn auto_chooses_seed_when_prf_cannot_satisfy_signing_request() {
        let root_dir = unique_temp_path("setup-auto-sign-seed");
        let result = ops::resolve_profile(
            &AlwaysAvailableProbe,
            &SetupRequest {
                profile: "test-auto-sign-seed".to_string(),
                algorithm: Algorithm::Ed25519,
                uses: vec![UseCase::Sign],
                requested_mode: ModePreference::Auto,
                state_dir: Some(root_dir.clone()),
                dry_run: true,
            },
        )
        .expect("auto should skip PRF and choose seed for sign support");

        assert_eq!(result.profile.mode.resolved, Mode::Seed);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn use_all_expands_for_native_setup() {
        let root_dir = unique_temp_path("setup-native-all");
        let result = ops::resolve_profile(
            &HeuristicProbe,
            &SetupRequest {
                profile: "test-native-all".to_string(),
                algorithm: Algorithm::P256,
                uses: vec![UseCase::All],
                requested_mode: ModePreference::Native,
                state_dir: Some(root_dir.clone()),
                dry_run: true,
            },
        )
        .expect("native --use all should expand to supported native uses");

        assert_eq!(result.profile.uses, vec![UseCase::Sign, UseCase::Verify]);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    // ── UseCase enum variant correctness ────────────────────────────

    #[test]
    fn use_case_enum_has_exactly_seven_variants() {
        let all = [
            UseCase::All,
            UseCase::Sign,
            UseCase::Verify,
            UseCase::SshAgent,
            UseCase::Derive,
            UseCase::Encrypt,
            UseCase::Decrypt,
        ];
        assert_eq!(all.len(), 7);

        for use_case in &all {
            let json = serde_json::to_string(use_case).expect("serialize");
            let deserialized: UseCase = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*use_case, deserialized);
        }
    }

    #[test]
    fn ssh_and_ethereum_variants_do_not_exist_in_serde() {
        let error = serde_json::from_str::<UseCase>("\"ssh\"");
        assert!(error.is_err(), "\"ssh\" should not deserialize");

        let error = serde_json::from_str::<UseCase>("\"ethereum\"");
        assert!(error.is_err(), "\"ethereum\" should not deserialize");
    }
}
