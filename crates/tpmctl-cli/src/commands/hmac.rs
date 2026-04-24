use crate::{
    args::{CliError, HmacArgs},
    commands::io::{
        read_input, seal_target_from_destination, selector_from_material, write_output,
        write_stdout, write_stdout_line,
    },
};
use tpmctl_core::{SealTarget, hmac as core_hmac};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &HmacArgs) -> Result<(), CliError> {
    let seal_target = args
        .seal_destination()
        .as_ref()
        .map(seal_target_from_destination)
        .transpose()?;
    let request = core_hmac::HmacRequest {
        selector: selector_from_material(&args.material.material())?,
        input: read_input(&args.input)?,
        hash: args.hash.map(Into::into),
        format: args.format.into(),
        seal_target,
        emit_prf_when_sealing: false,
    };
    let result = request.execute()?;
    match result {
        core_hmac::HmacResult::Output(bytes) => {
            let output: tpmctl_core::OutputTarget = (&args.output).into();
            write_output(&output, &bytes)?;
        }
        core_hmac::HmacResult::Sealed { target, hash } => {
            write_sealed_result(runtime.json, &target, hash)?
        }
        core_hmac::HmacResult::SealedWithOutput {
            target,
            hash,
            output,
        } => {
            write_sealed_result(runtime.json, &target, hash)?;
            let target: tpmctl_core::OutputTarget = (&args.output).into();
            write_output(&target, &output)?;
        }
    }
    Ok(())
}

fn write_sealed_result(
    json: bool,
    target: &SealTarget,
    hash: tpmctl_core::HashAlgorithm,
) -> Result<(), CliError> {
    if json {
        let payload = match target {
            SealTarget::Id(id) => {
                serde_json::json!({ "sealed_id": id.to_string(), "hash": hash.to_string() })
            }
            SealTarget::Handle(handle) => {
                serde_json::json!({ "sealed_at": handle.to_string(), "hash": hash.to_string() })
            }
        };
        write_stdout(&serde_json::to_vec_pretty(&payload).expect("hmac JSON is serializable"))?;
        write_stdout(b"\n")?;
    } else {
        match target {
            SealTarget::Id(id) => write_stdout_line(&format!("sealed {hash} HMAC output as {id}"))?,
            SealTarget::Handle(handle) => {
                write_stdout_line(&format!("sealed {hash} HMAC output at {handle}"))?
            }
        }
    }
    Ok(())
}
