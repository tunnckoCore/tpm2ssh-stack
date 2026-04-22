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
        ModePreference, NativeAlgorithmCapability, NativeCapabilitySummary, TpmStatus, UseCase,
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
    fn validate_native_rejects_export_secret() {
        let error = UseCase::validate_for_mode(&[UseCase::ExportSecret], Mode::Native)
            .expect_err("native should reject export-secret");
        assert!(matches!(error, Error::PolicyRefusal(_)));
    }

    #[test]
    fn validate_seed_allows_everything_when_coupled_uses_are_present() {
        let allowed_sets = [
            vec![UseCase::Sign],
            vec![UseCase::Sign, UseCase::Verify],
            vec![UseCase::Sign, UseCase::Ssh],
            vec![UseCase::Encrypt],
            vec![UseCase::Encrypt, UseCase::Decrypt],
            vec![UseCase::ExportSecret],
        ];

        for uses in allowed_sets {
            UseCase::validate_for_mode(&uses, Mode::Seed)
                .unwrap_or_else(|_| panic!("seed should allow {:?}", uses));
        }
    }

    // ── Setup-time enforcement tests ────────────────────────────────

    #[test]
    fn setup_allows_native_mode_with_sign_and_ssh_use() {
        let root_dir = unique_temp_path("setup-native-ssh");
        let result = ops::resolve_identity(
            &HeuristicProbe,
            &request(
                "test-native-ssh",
                Algorithm::P256,
                vec![UseCase::Sign, UseCase::Ssh],
                ModePreference::Native,
                root_dir.clone(),
            ),
        )
        .expect("native sign+ssh should be allowed as a signing-backed intent bit");

        assert_eq!(result.identity.mode.resolved, Mode::Native);
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
    fn setup_allows_prf_mode_with_sign_and_verify_use() {
        let root_dir = unique_temp_path("setup-prf-verify");
        let result = ops::resolve_identity(
            &AlwaysAvailableProbe,
            &request(
                "test-prf-verify",
                Algorithm::Ed25519,
                vec![UseCase::Sign, UseCase::Verify],
                ModePreference::Prf,
                root_dir.clone(),
            ),
        )
        .expect("prf + sign+verify should succeed at setup (dry-run)");

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

    #[test]
    fn setup_rejects_verify_only_use_contract() {
        let root_dir = unique_temp_path("setup-native-verify-only");
        let error = ops::resolve_identity(
            &HeuristicProbe,
            &request(
                "test-native-verify-only",
                Algorithm::P256,
                vec![UseCase::Verify],
                ModePreference::Native,
                root_dir.clone(),
            ),
        )
        .expect_err("verify-only should be rejected by the coupled use contract");

        assert!(matches!(
            error,
            Error::CapabilityMismatch(_) | Error::PolicyRefusal(_)
        ));
        assert!(
            error.to_string().contains("use=verify requires use=sign")
                || error
                    .to_string()
                    .contains("verify-only native identities are not wired")
        );
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn auto_chooses_seed_when_prf_cannot_satisfy_signing_request() {
        let root_dir = unique_temp_path("setup-auto-sign-seed");
        let result = ops::resolve_identity(
            &AlwaysAvailableProbe,
            &request(
                "test-auto-sign-seed",
                Algorithm::Ed25519,
                vec![UseCase::Sign],
                ModePreference::Auto,
                root_dir.clone(),
            ),
        )
        .expect("auto should skip PRF and choose seed for sign support");

        assert_eq!(result.identity.mode.resolved, Mode::Seed);
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn use_all_expands_for_native_setup() {
        let root_dir = unique_temp_path("setup-native-all");
        let result = ops::resolve_identity(
            &HeuristicProbe,
            &request(
                "test-native-all",
                Algorithm::P256,
                vec![UseCase::All],
                ModePreference::Native,
                root_dir.clone(),
            ),
        )
        .expect("native --use all should expand to supported native uses");

        assert_eq!(
            result.identity.uses,
            vec![UseCase::Sign, UseCase::Verify, UseCase::Ssh]
        );
    }

    #[test]
    fn setup_rejects_decrypt_without_encrypt_use_contract() {
        let root_dir = unique_temp_path("setup-decrypt-without-encrypt");
        let error = ops::resolve_identity(
            &AlwaysAvailableProbe,
            &request(
                "test-decrypt-without-encrypt",
                Algorithm::Ed25519,
                vec![UseCase::Decrypt],
                ModePreference::Seed,
                root_dir.clone(),
            ),
        )
        .expect_err("decrypt-only should be rejected by the coupled use contract");

        assert!(matches!(error, Error::PolicyRefusal(_)));
        assert!(
            error
                .to_string()
                .contains("use=decrypt requires use=encrypt")
        );
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn use_all_for_prf_does_not_expand_export_secret() {
        let root_dir = unique_temp_path("setup-prf-all-no-export-secret");
        let result = ops::resolve_identity(
            &AlwaysAvailableProbe,
            &request(
                "test-prf-all",
                Algorithm::Ed25519,
                vec![UseCase::All],
                ModePreference::Prf,
                root_dir.clone(),
            ),
        )
        .expect("prf --use all should expand without export-secret");

        assert!(!result.identity.uses.contains(&UseCase::ExportSecret));
        let _ = std::fs::remove_dir_all(root_dir);
    }

    #[test]
    fn setup_rejects_ssh_without_sign_use_contract() {
        let root_dir = unique_temp_path("setup-secp256k1-ssh");
        let error = ops::resolve_identity(
            &AlwaysAvailableProbe,
            &request(
                "test-ssh-without-sign",
                Algorithm::Ed25519,
                vec![UseCase::Ssh],
                ModePreference::Prf,
                root_dir.clone(),
            ),
        )
        .expect_err("ssh-only should be rejected by the coupled use contract");

        assert!(matches!(
            error,
            Error::PolicyRefusal(_) | Error::CapabilityMismatch(_)
        ));
        assert!(error.to_string().contains("use=ssh requires use=sign"));
        let _ = std::fs::remove_dir_all(root_dir);
    }

    // ── UseCase enum variant correctness ────────────────────────────

    #[test]
    fn use_case_enum_has_expected_variants() {
        let all = [
            UseCase::All,
            UseCase::Sign,
            UseCase::Verify,
            UseCase::Ssh,
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
