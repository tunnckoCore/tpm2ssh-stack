use crate::args::{CliError, DeriveArgs};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &DeriveArgs) -> Result<(), CliError> {
    tpmctl_core::derive(tpmctl_core::DeriveRequest {
        runtime,
        material: args.material.material()?,
        label: args.label.clone(),
        algorithm: args.algorithm.into(),
        usage: args.usage.into(),
        input: args.sign_input(),
        input_format: args.input_format.into(),
        hash: args.hash.map(Into::into),
        output_format: args.output_format.into(),
        compressed: args.compressed,
        output: (&args.output).into(),
        force: args.force,
    })?;
    Ok(())
}
