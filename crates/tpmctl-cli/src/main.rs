mod args;
mod commands;
mod io;
mod validation;

use args::{Cli, Command, InputMode};
use clap::Parser;
use io::OutputKind;
use std::process::ExitCode;
use tpmctl_core::HashAlgorithm;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    for warning in validation::validate_command(&cli.command)? {
        eprintln!("{warning}");
    }

    preflight_io_guards(&cli)?;

    // Dispatch is intentionally thin. Domain semantics belong in tpmctl-core.
    let result = commands::dispatch(&cli)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    Ok(())
}

fn preflight_io_guards(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.command {
        Command::Sign(args) => {
            if let InputMode::Digest(path) = args.data.mode() {
                if !io::is_dash(&path) {
                    let digest = io::read_input(&path)?;
                    validation::validate_digest_len(&digest, HashAlgorithm::from(args.hash))?;
                }
            }
            io::guard_binary_stdout(
                validation::output_path_is_stdout(args.io.output.as_ref())
                    && args.format.is_binary(),
                cli.force,
            )?;
        }
        Command::Pubkey(args) => io::guard_binary_stdout(
            validation::output_path_is_stdout(args.io.output.as_ref()) && args.format.is_binary(),
            cli.force,
        )?,
        Command::Ecdh(args) => io::guard_binary_stdout(
            validation::output_path_is_stdout(args.io.output.as_ref()) && args.format.is_binary(),
            cli.force,
        )?,
        Command::Hmac(args) => {
            if args.seal_at.is_none() && args.seal_id.is_none() {
                io::guard_binary_stdout(
                    validation::output_path_is_stdout(args.io.output.as_ref())
                        && args.format.is_binary(),
                    cli.force,
                )?;
            }
        }
        Command::Unseal(args) => io::guard_binary_stdout(
            validation::output_path_is_stdout(args.io.output.as_ref()),
            cli.force,
        )?,
        Command::Derive(args) => {
            if let Some(InputMode::Digest(path)) = args.data.mode() {
                if !io::is_dash(&path) {
                    let digest = io::read_input(&path)?;
                    if args.algorithm != args::DeriveAlgorithm::Ed25519 {
                        let hash = args.hash.unwrap_or(args::HashArg::Sha256);
                        validation::validate_digest_len(&digest, HashAlgorithm::from(hash))?;
                    }
                }
            }
            io::guard_binary_stdout(
                validation::output_path_is_stdout(args.io.output.as_ref())
                    && args.effective_format().is_binary(),
                cli.force,
            )?;
        }
        Command::Keygen(_) | Command::Seal(_) => {}
    }
    Ok(())
}
