pub mod native;
pub mod prf;
pub mod seed;

use std::path::PathBuf;

use crate::backend::CapabilityProbe;
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, CapabilityReport, InspectRequest, Mode, ModeResolution, Profile, SetupRequest,
    SetupResult, StateLayout, UseCase,
};

pub fn inspect(probe: &dyn CapabilityProbe, request: &InspectRequest) -> CapabilityReport {
    probe.detect(request.algorithm, &normalize_uses(request.uses.clone()))
}

pub fn resolve_profile(probe: &dyn CapabilityProbe, request: &SetupRequest) -> Result<SetupResult> {
    validate_profile_name(&request.profile)?;

    let uses = normalize_uses(request.uses.clone());
    if uses.is_empty() {
        return Err(Error::Validation(
            "at least one --use value is required for setup".to_string(),
        ));
    }

    let report = probe.detect(Some(request.algorithm), &uses);
    let resolved_mode = resolve_mode(
        probe,
        request.requested_mode,
        request.algorithm,
        &uses,
        &report,
    )?;
    let reasons = if let Some(explicit) = request.requested_mode.explicit() {
        vec![format!("mode explicitly requested as {explicit:?}")]
    } else {
        report.recommendation_reasons.clone()
    };

    let state_layout = StateLayout::from_optional_root(request.state_dir.clone());
    let profile = Profile::new(
        request.profile.clone(),
        request.algorithm,
        uses,
        ModeResolution {
            requested: request.requested_mode,
            resolved: resolved_mode,
            reasons,
        },
        state_layout,
    );

    let persisted = if request.dry_run {
        false
    } else {
        profile.persist()?;
        true
    };

    Ok(SetupResult {
        profile,
        dry_run: request.dry_run,
        persisted,
    })
}

pub fn load_profile(profile: &str, state_dir: Option<PathBuf>) -> Result<Profile> {
    validate_profile_name(profile)?;
    Profile::load_named(profile, state_dir)
}

fn resolve_mode(
    probe: &dyn CapabilityProbe,
    requested_mode: crate::model::ModePreference,
    algorithm: Algorithm,
    uses: &[UseCase],
    report: &CapabilityReport,
) -> Result<Mode> {
    match requested_mode.explicit() {
        Some(mode) if probe.supports_mode(algorithm, uses, mode) => Ok(mode),
        Some(mode) => Err(Error::CapabilityMismatch(format!(
            "requested mode {mode:?} is not supported for {algorithm:?} with uses {uses:?}"
        ))),
        None => report
            .recommended_mode
            .ok_or_else(|| Error::CapabilityMismatch("unable to recommend a mode".to_string())),
    }
}

fn validate_profile_name(profile: &str) -> Result<()> {
    if profile.trim().is_empty() {
        return Err(Error::Validation(
            "profile name must not be empty".to_string(),
        ));
    }

    if !profile
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(Error::Validation(
            "profile name may contain only ASCII letters, numbers, '.', '-', and '_'".to_string(),
        ));
    }

    if profile.contains("..") {
        return Err(Error::Validation(
            "profile name must not contain '..'".to_string(),
        ));
    }

    Ok(())
}

fn normalize_uses(mut uses: Vec<UseCase>) -> Vec<UseCase> {
    uses.sort();
    uses.dedup();
    uses
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::backend::HeuristicProbe;
    use crate::model::ModePreference;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "tpm2-derive-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn setup_persists_profile_when_not_dry_run() {
        let root_dir = unique_temp_path("setup-persist");
        let request = SetupRequest {
            profile: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Verify, UseCase::Sign],
            requested_mode: ModePreference::Auto,
            state_dir: Some(root_dir.clone()),
            dry_run: false,
        };

        let result = resolve_profile(&HeuristicProbe, &request).expect("setup should succeed");
        let profile_path = root_dir.join("profiles").join("prod-signer.json");

        assert!(result.persisted);
        assert_eq!(result.profile.storage.profile_path, profile_path);
        assert!(profile_path.is_file());

        let loaded = load_profile("prod-signer", Some(root_dir.clone())).expect("profile loads");
        assert_eq!(loaded, result.profile);

        fs::remove_dir_all(root_dir).expect("temporary setup state should be removed");
    }

    #[test]
    fn setup_dry_run_does_not_touch_state() {
        let root_dir = unique_temp_path("setup-dry-run");
        let request = SetupRequest {
            profile: "prod-signer".to_string(),
            algorithm: Algorithm::P256,
            uses: vec![UseCase::Sign],
            requested_mode: ModePreference::Auto,
            state_dir: Some(root_dir.clone()),
            dry_run: true,
        };

        let result = resolve_profile(&HeuristicProbe, &request).expect("setup should succeed");

        assert!(!result.persisted);
        assert!(!root_dir.exists());

        if root_dir.exists() {
            fs::remove_dir_all(root_dir).expect("temporary dry-run state should be removed");
        }
    }
}
