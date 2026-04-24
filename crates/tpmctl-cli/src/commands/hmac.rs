use crate::args::{CliError, HmacArgs};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &HmacArgs) -> Result<(), CliError> {
    let request = tpmctl_core::HmacRequest {
        runtime,
        material: args.material.material(),
        input: args.input.clone(),
        hash: args.hash.map(Into::into),
        format: args.format.into(),
        output: (&args.output).into(),
        seal: args.seal_destination(),
        force: args.force,
    };
    tpmctl_core::hmac(request)?;
    Ok(())
}
