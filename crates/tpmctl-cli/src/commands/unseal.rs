use crate::args::{CliError, UnsealArgs};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &UnsealArgs) -> Result<(), CliError> {
    let request = tpmctl_core::UnsealRequest {
        runtime,
        material: args.material.material(),
        output: (&args.output).into(),
        force: args.force,
    };
    tpmctl_core::unseal(request)?;
    Ok(())
}
