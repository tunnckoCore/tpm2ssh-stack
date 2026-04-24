mod args;
mod commands;

use clap::Parser;

fn main() {
    let cli = args::Cli::parse();
    if let Err(error) = commands::dispatch(cli) {
        eprintln!("tpmctl: {error}");
        std::process::exit(1);
    }
}
