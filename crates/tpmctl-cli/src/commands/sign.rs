use crate::{
    args::{CliError, SignArgs},
    commands::io::{read_input, selector_from_material, write_output},
};
use tpmctl_core::sign as core_sign;

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &SignArgs) -> Result<(), CliError> {
    let input = match args.sign_input() {
        tpmctl_core::SignInput::Message(source) => {
            core_sign::SignInput::Message(read_input(&source)?)
        }
        tpmctl_core::SignInput::Digest(source) => {
            core_sign::SignInput::Digest(read_input(&source)?)
        }
    };
    let request = core_sign::SignRequest {
        selector: selector_from_material(&args.material.material())?,
        input,
        hash: args.hash.into(),
        format: args.format.into(),
    };
    let store = tpmctl_core::Store::new(runtime.store.root);
    let bytes = request.execute(&store)?;
    let output: tpmctl_core::OutputTarget = (&args.output).into();
    write_output(&output, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Cli;
    use std::fs;

    #[test]
    fn sign_reads_digest_file_and_validates_length_before_tpm_call() {
        let path = crate::commands::io::temp_file_path("bad-digest");
        fs::write(&path, [0_u8; 31]).unwrap();
        let cli = Cli::try_parse_args([
            "tpmctl",
            "sign",
            "--id",
            "alice",
            "--digest",
            path.to_str().unwrap(),
            "--format",
            "hex",
        ])
        .unwrap();
        let crate::args::Command::Sign(args) = cli.command else {
            panic!("expected sign command");
        };
        let runtime = tpmctl_core::RuntimeOptions {
            store: tpmctl_core::StoreConfig::resolve(None).unwrap(),
            json: false,
        };
        let error = run(runtime, &args).unwrap_err();
        assert!(error.to_string().contains("digest must be 32 bytes"));
        let _ = fs::remove_file(path);
    }
}
