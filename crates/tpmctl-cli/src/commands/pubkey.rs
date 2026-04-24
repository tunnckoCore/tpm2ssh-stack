use crate::args::{CliError, PubkeyArgs};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &PubkeyArgs) -> Result<(), CliError> {
    let request = tpmctl_core::PubkeyRequest {
        runtime,
        material: args.material.material(),
        format: args.format.into(),
        output: (&args.output).into(),
        force: args.force,
    };
    tpmctl_core::pubkey(request)?;
    Ok(())
}
