mod args;
mod commands;

use clap::Parser as _;

fn main() {
    if let Err(error) = run() {
        eprintln!("tpmctl: {error}");
        std::process::exit(1);
    }
}

fn run() -> tpmctl_core::Result<()> {
    let cli = args::Cli::parse();
    commands::dispatch(cli)
}
