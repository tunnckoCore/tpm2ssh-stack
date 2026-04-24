use crate::args::{CliError, SealArgs};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &SealArgs) -> Result<(), CliError> {
    let request = tpmctl_core::SealRequest {
        runtime,
        input: args.input.clone(),
        destination: args.destination(),
        force: args.force,
    };
    tpmctl_core::seal(request)?;
    Ok(())
}
