use crate::args::{CliError, KeygenArgs};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &KeygenArgs) -> Result<(), CliError> {
    let request = tpmctl_core::KeygenRequest {
        runtime,
        usage: args.usage.into(),
        id: args.id.clone(),
        handle: args.handle,
        force: args.force,
    };
    tpmctl_core::keygen(request)?;
    Ok(())
}
