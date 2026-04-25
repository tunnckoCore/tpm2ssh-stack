use crate::{
    args::{CliError, SignArgs},
    commands::io::{read_input, selector_from_material, write_output_with_force},
};
use tpmctl_core::{InputFormat, sign as core_sign};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &SignArgs) -> Result<(), CliError> {
    let input = match args.sign_input() {
        tpmctl_core::SignInput::Message(source) => core_sign::SignInput::Message(
            decode_input_bytes(read_input(&source)?, args.input_format.into())?,
        ),
        tpmctl_core::SignInput::DigestFile(source) => {
            core_sign::SignInput::Digest(read_input(&source)?)
        }
        tpmctl_core::SignInput::DigestHex(hex) => core_sign::SignInput::Digest(
            hex::decode(hex.trim().strip_prefix("0x").unwrap_or(hex.trim()))
                .map_err(|error| CliError::Usage(format!("invalid --digest hex: {error}")))?,
        ),
    };
    let request = core_sign::SignRequest {
        selector: selector_from_material(&args.material.material()?)?,
        input,
        hash: args.hash.into(),
        output_format: args.output_format.into(),
    };
    let store = tpmctl_core::Store::new(runtime.store.root);
    let bytes = request.execute(&store)?;
    let output: tpmctl_core::OutputTarget = (&args.output).into();
    write_output_with_force(&output, &bytes, args.force)?;
    Ok(())
}

fn decode_input_bytes(input: Vec<u8>, input_format: InputFormat) -> Result<Vec<u8>, CliError> {
    match input_format {
        InputFormat::Raw => Ok(input),
        InputFormat::Hex => {
            let text = std::str::from_utf8(&input)
                .map_err(|error| CliError::Usage(format!("hex input is not UTF-8: {error}")))?;
            hex::decode(text.trim().strip_prefix("0x").unwrap_or(text.trim())).map_err(|error| {
                CliError::Usage(format!("invalid --input-format hex input: {error}"))
            })
        }
    }
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
            "--digest-file",
            path.to_str().unwrap(),
            "--output-format",
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
