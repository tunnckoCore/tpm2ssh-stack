//! Thin command adapters from validated CLI arguments to `tpmctl-core` contracts.

use crate::args::{Cli, CliError, Command};

pub mod derive;
pub mod ecdh;
pub mod hmac;
mod io;
pub mod keygen;
pub mod pubkey;
pub mod seal;
pub mod sign;
pub mod unseal;

pub fn run(cli: &Cli) -> Result<(), CliError> {
    let runtime = cli.runtime()?;
    match &cli.command {
        Command::Keygen(args) => keygen::run(runtime, args),
        Command::Sign(args) => sign::run(runtime, args),
        Command::Pubkey(args) => pubkey::run(runtime, args),
        Command::Ecdh(args) => ecdh::run(runtime, args),
        Command::Hmac(args) => hmac::run(runtime, args),
        Command::Seal(args) => seal::run(runtime, args),
        Command::Unseal(args) => unseal::run(runtime, args),
        Command::Derive(args) => derive::run(runtime, args),
    }
}
