use crate::args::{CliError, DeriveAlgorithmArg, DeriveArgs, DeriveUseArg, HashArg};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &DeriveArgs) -> Result<(), CliError> {
    if args.should_warn_ephemeral() {
        eprintln!(
            "warning: --label was not provided; derived material is ephemeral and will change on each invocation"
        );
    }

    let request = tpmctl_core::DeriveRequest {
        runtime,
        material: args.material.material(),
        label: args.label.clone(),
        algorithm: args.algorithm.into(),
        usage: args.usage.into(),
        input: args.sign_input(),
        hash: derive_hash(args).map(Into::into),
        format: args.format.into(),
        compressed: args.compressed,
        output: (&args.output).into(),
        force: args.force,
    };
    tpmctl_core::derive(request)?;
    Ok(())
}

fn derive_hash(args: &DeriveArgs) -> Option<HashArg> {
    if args.usage == DeriveUseArg::Sign
        && matches!(
            args.algorithm,
            DeriveAlgorithmArg::P256 | DeriveAlgorithmArg::Secp256k1
        )
    {
        Some(args.hash.unwrap_or(HashArg::Sha256))
    } else {
        args.hash
    }
}
