//! Tests for mode/use enforcement rules across the entire ops surface.

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::backend::{CapabilityProbe, HeuristicProbe};
    use crate::error::Error;
    use crate::model::{
        Algorithm, CapabilityReport, DerivationOverrides, IdentityCreateRequest, Mode,
        ModePreference, NativeCapabilitySummary, TpmStatus, UseCase,
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
                    supported_algorithms: vec![Algorithm::P256],
                    supported_uses: vec![UseCase::Sign, UseCase::Verify],
                },
                prf_available: Some(true),
                seed_available: Some(true),
                recommended_mode: Some(Mode::Seed),
                recommendation_reasons: vec!["test probe".to_string()],
                diagnostics: Vec::new(),
            }
        }
    }

    fn request(
        identity: &str,
        algorithm: Algorithm,
        uses: Vec<UseCase>,
        requested_mode: ModePreference,
        state_dir: PathBuf,
    ) -> IdentityCreateRequest {
        IdentityCreateRequest {
            identity: identity.to_string(),
            algorithm,
            uses,
            requested_mode,
            defaults: DerivationOverrides::default(),
            state_dir: Some(state_dir),
            dry_run: true,
        }
    }

    // ── UseCase::validate_for_mode unit tests ───────────────────────

    #[test]
    fn validate_prf_allows_full_identity_surface() {
        UseCase::validate_for_mode(
            &[
                UseCase::Sign,
                UseCase::Verify,
                UseCase::Encrypt,
                UseCase::Decrypt,
                UseCase::Derive,
                UseCase::Ssh,
                UseCase::ExportSecret,
            ],
            Mode::Prf,
        )
        .expect("prf should allow the shared identity surface");
    }

    #[test]
    fn validate_native_allows_sign_verify_encrypt_decrypt_and_ssh() {
        UseCase::validate_for_mode(
            &[
                UseCase::Sign,
                UseCase::Verify,
                UseCase::Encrypt,
                UseCase::Decrypt,
                UseCase::Ssh,
            ],
            Mode::Native,
        )
        .expect("native should allow its declared identity surface");
    }

    #[test]
    fn validate_native_rejects_derive() {
        let error = UseCase::validate_for_mode(&[UseCase::Derive], Mode::Native)
            .expect_err("native should reject derive");
        assert!(matches!(error, Error::PolicyRefusal(_)));
        assert!(error.to_string().contains("not allowed in Native mode"));
    }

    #[test]
    fn validate_native_rejects_export_secret() {
        let error = UseCase::validate_for_mode(&[UseCase::ExportSecret], Mode::Native)
            .expect_err("native should reject export-secret");
        assert!(matches!(error, Error::PolicyRefusal(_)));
    }

    #[test]
    fn validate_seed_allows_everything() {
        for use_case in [
            UseCase::Sign,
            UseCase::Verify,
            UseCase::Derive,
            UseCase::Ssh,
            UseCase::Encrypt,
            UseCase::Decrypt,
            UseCase::ExportSecret,
        ] {
            UseCase::validate_for_mode(&[use_case], Mode::Seed)
                .unwrap_or_else(|_| panic!("seed should allow {:?}", use_case));
        }
    }

    // ── Setup-time enforcement tests ────────────────────────────────

    #[test]
    fn setup_rejects_native_mode_with_derive_use() {
        let root_dir = unique_temp_path("setup-native-derive");
        let error = ops::resolve_identity(
            &HeuristicProbe,
            &request(
                "test-native-derive",
                Algorithm::P256,
                vec![UseCase::Derive],
                ModePreference::Native,
                root_dir.clone(),
            ),
        )
        .expect_err("native + derive should fail at setup");

        assert!(matches!(
            error,
            Error::PolicyRefusal(_) | Error::CapabilityMismatch(_)
        ));
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_currently_rejects_native_mode_with_ssh_use_until_capability_workstream_lands() {
        let root_dir = unique_temp_path("setup-native-ssh");
        let error = ops::resolve_identity(
            &HeuristicProbe,
            &request(
                "test-native-ssh",
                Algorithm::P256,
                vec![UseCase::Ssh],
                ModePreference::Native,
                root_dir.clone(),
            ),
        )
        .expect_err("native + ssh still depends on capability workstream support");

        assert!(matches!(error, Error::CapabilityMismatch(_)));
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_allows_prf_mode_with_sign_use() {
        let root_dir = unique_temp_path("setup-prf-sign");
        let result = ops::resolve_identity(
            &AlwaysAvailableProbe,
            &request(
                "test-prf-sign",
                Algorithm::Ed25519,
                vec![UseCase::Sign],
                ModePreference::Prf,
                root_dir.clone(),
            ),
        )
        .expect("prf + sign should succeed at setup (dry-run)");

        assert_eq!(result.identity.mode.resolved, Mode::Prf);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_allows_prf_mode_with_verify_use() {
        let root_dir = unique_temp_path("setup-prf-verify");
        let result = ops::resolve_identity(
            &AlwaysAvailableProbe,
            &request(
                "test-prf-verify",
                Algorithm::Ed25519,
                vec![UseCase::Verify],
                ModePreference::Prf,
                root_dir.clone(),
            ),
        )
        .expect("prf + verify should succeed at setup (dry-run)");

        assert_eq!(result.identity.mode.resolved, Mode::Prf);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_allows_prf_mode_with_derive_use() {
        let root_dir = unique_temp_path("setup-prf-derive");
        let result = ops::resolve_identity(
            &AlwaysAvailableProbe,
            &request(
                "test-prf-derive",
                Algorithm::Ed25519,
                vec![UseCase::Derive],
                ModePreference::Prf,
                root_dir.clone(),
            ),
        )
        .expect("prf + derive should succeed at setup (dry-run)");

        assert_eq!(result.identity.mode.resolved, Mode::Prf);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_allows_seed_mode_with_everything() {
        let root_dir = unique_temp_path("setup-seed-all");
        let result = ops::resolve_identity(
            &AlwaysAvailableProbe,
            &request(
                "test-seed-all",
                Algorithm::Ed25519,
                vec![
                    UseCase::Sign,
                    UseCase::Verify,
                    UseCase::Derive,
                    UseCase::Ssh,
                    UseCase::Encrypt,
                    UseCase::Decrypt,
                    UseCase::ExportSecret,
                ],
                ModePreference::Seed,
                root_dir.clone(),
            ),
        )
        .expect("seed + all uses should succeed at setup (dry-run)");

        assert_eq!(result.identity.mode.resolved, Mode::Seed);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_allows_native_mode_with_sign_verify() {
        let root_dir = unique_temp_path("setup-native-sign-verify");
        let result = ops::resolve_identity(
            &HeuristicProbe,
            &request(
                "test-native-sv",
                Algorithm::P256,
                vec![UseCase::Sign, UseCase::Verify],
                ModePreference::Native,
                root_dir.clone(),
            ),
        )
        .expect("native + sign+verify should succeed at setup (dry-run)");

        assert_eq!(result.identity.mode.resolved, Mode::Native);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    // ── UseCase enum variant correctness ────────────────────────────

    #[test]
    fn use_case_enum_has_expected_variants() {
        let all = [
            UseCase::Sign,
            UseCase::Verify,
            UseCase::Ssh,
            UseCase::Derive,
            UseCase::Encrypt,
            UseCase::Decrypt,
            UseCase::ExportSecret,
        ];
        assert_eq!(all.len(), 7);

        for use_case in &all {
            let json = serde_json::to_string(use_case).expect("serialize");
            let deserialized: UseCase = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*use_case, deserialized);
        }
    }

    #[test]
    fn legacy_removed_variants_do_not_exist_in_serde() {
        let error = serde_json::from_str::<UseCase>("\"ssh-agent\"");
        assert!(error.is_err(), "legacy ssh-agent should not deserialize");

        let error = serde_json::from_str::<UseCase>("\"ethereum\"");
        assert!(error.is_err(), "ethereum should not deserialize");
    }
}
