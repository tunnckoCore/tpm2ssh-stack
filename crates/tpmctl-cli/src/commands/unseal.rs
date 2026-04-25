use crate::{
    args::{CliError, UnsealArgs},
    commands::io::{selector_from_material, write_output_with_force},
};
use tpmctl_core::{CommandContext, StoreOptions, seal as core_seal};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &UnsealArgs) -> Result<(), CliError> {
    let request = core_seal::UnsealRequest {
        selector: selector_from_material(&args.material.material()?)?,
        force_binary_stdout: args.force,
    };
    let command = CommandContext {
        store: StoreOptions {
            root: Some(runtime.store.root.clone()),
        },
        tcti: None,
    };
    let bytes = request.execute_with_context(&command)?;
    let output: tpmctl_core::OutputTarget = (&args.output).into();
    write_output_with_force(&output, &bytes, args.force)?;
    Ok(())
}
