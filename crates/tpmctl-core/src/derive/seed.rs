use zeroize::Zeroizing;

use crate::{
    CommandContext, Error, ObjectSelector, Result,
    hmac::{HmacRequest, HmacResult},
    output::BinaryFormat,
    seal::UnsealRequest,
};

use super::{DeriveParams, primitives::DeriveMode};

pub(super) fn resolve_seed(
    command: &CommandContext,
    selector: &ObjectSelector,
    params: &DeriveParams,
) -> Result<Zeroizing<Vec<u8>>> {
    match (UnsealRequest {
        selector: selector.clone(),
        force_binary_stdout: true,
    })
    .execute_with_context(command)
    {
        Ok(seed) => Ok(seed),
        Err(Error::NotFound(_)) if matches!(selector, ObjectSelector::Id(_)) => {
            hmac_prf_seed(command, selector, params)
        }
        Err(Error::InvalidInput { .. }) | Err(Error::Tpm { .. })
            if matches!(selector, ObjectSelector::Handle(_)) =>
        {
            hmac_prf_seed(command, selector, params)
        }
        Err(error) => Err(error),
    }
}

fn hmac_prf_seed(
    command: &CommandContext,
    selector: &ObjectSelector,
    params: &DeriveParams,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut input = Vec::new();
    input.extend_from_slice(b"tpmctl derive prf v1\0");
    input.extend_from_slice(params.algorithm.domain());
    input.push(0);
    if let Some(label) = &params.label {
        input.extend_from_slice(label);
    }
    let result = HmacRequest {
        selector: selector.clone(),
        input: Zeroizing::new(input),
        hash: None,
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
    .execute_with_context(command)?;

    match result {
        HmacResult::Output(seed) => Ok(seed),
        HmacResult::Sealed { .. } | HmacResult::SealedWithOutput { .. } => Err(Error::invalid(
            "derive",
            "HMAC PRF seed derivation unexpectedly sealed its output",
        )),
    }
}

pub(super) fn resolve_mode(params: &DeriveParams) -> Result<DeriveMode> {
    if let Some(label) = &params.label {
        Ok(DeriveMode::deterministic(label.clone()))
    } else {
        let entropy = params.entropy.as_ref().ok_or_else(|| {
            Error::invalid("entropy", "entropy is required when label is omitted")
        })?;
        Ok(DeriveMode::ephemeral(
            Vec::new(),
            entropy.as_slice().to_vec(),
        ))
    }
}

#[cfg(test)]
#[path = "seed.test.rs"]
mod tests;
