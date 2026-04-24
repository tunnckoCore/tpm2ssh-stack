mod args;
mod commands;

use clap::error::ErrorKind;

use crate::args::{Cli, CliError};

fn main() {
    let cli = Cli::parse_args();
    if let Err(error) = run(cli) {
        eprintln!("error: {error}");
        std::process::exit(exit_code(&error));
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    cli.validate()?;
    commands::run(&cli)
}

fn exit_code(error: &CliError) -> i32 {
    match error {
        CliError::Usage(_) => 2,
        CliError::Core(_) => 1,
    }
}

#[allow(dead_code)]
fn clap_exit_code(kind: ErrorKind) -> i32 {
    match kind {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
        _ => 2,
    }
}
