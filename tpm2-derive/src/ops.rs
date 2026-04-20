pub mod native;
pub mod prf;
pub mod seed;

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
    let resolved_mode = resolve_mode(probe, request.requested_mode, request.algorithm, &uses, &report)?;
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

    Ok(SetupResult {
        profile,
        dry_run: request.dry_run,
        persisted: false,
    })
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
        return Err(Error::Validation("profile name must not be empty".to_string()));
    }

    if !profile
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(Error::Validation(
            "profile name may contain only ASCII letters, numbers, '.', '-', and '_'"
                .to_string(),
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
