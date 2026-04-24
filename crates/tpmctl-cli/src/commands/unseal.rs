use crate::{
    args::{CliError, UnsealArgs},
    commands::io::{selector_from_material, write_output},
};
use tpmctl_core::seal as core_seal;

pub fn run(_runtime: tpmctl_core::RuntimeOptions, args: &UnsealArgs) -> Result<(), CliError> {
    let request = core_seal::UnsealRequest {
        selector: selector_from_material(&args.material.material())?,
        force_binary_stdout: args.force,
    };
    let bytes = request.execute()?;
    let output: tpmctl_core::OutputTarget = (&args.output).into();
    write_output(&output, &bytes)?;
    Ok(())
}
