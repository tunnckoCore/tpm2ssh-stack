use crate::args::{CliError, EcdhArgs};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &EcdhArgs) -> Result<(), CliError> {
    let request = tpmctl_core::EcdhRequest {
        runtime,
        material: args.material.material(),
        peer_pub: args.peer_pub.clone(),
        format: args.format.into(),
        output: (&args.output).into(),
        force: args.force,
    };
    tpmctl_core::ecdh(request)?;
    Ok(())
}
