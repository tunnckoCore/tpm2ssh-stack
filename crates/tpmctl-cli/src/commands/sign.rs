use crate::args::{CliError, SignArgs};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &SignArgs) -> Result<(), CliError> {
    let request = tpmctl_core::SignRequest {
        runtime,
        material: args.material.material(),
        input: args.sign_input(),
        hash: args.hash.into(),
        format: args.format.into(),
        output: (&args.output).into(),
        force: args.force,
    };
    tpmctl_core::sign(request)?;
    Ok(())
}
