use crate::args::{CliError, HmacArgs};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &HmacArgs) -> Result<(), CliError> {
    tpmctl_core::hmac(tpmctl_core::HmacRequest {
        runtime,
        material: args.material.material()?,
        input: args.input.clone(),
        input_format: args.input_format.into(),
        hash: args.hash.map(Into::into),
        output_format: args.output_format.into(),
        output: (&args.output).into(),
        seal: args.seal_destination(),
        force: args.force,
    })?;
    Ok(())
}
