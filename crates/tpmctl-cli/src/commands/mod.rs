use crate::args::{Cli, Command};

pub mod derive;
pub mod ecdh;
pub mod hmac;
pub mod keygen;
pub mod pubkey;
pub mod seal;
pub mod sign;

pub fn dispatch(cli: Cli) -> tpmctl_core::Result<()> {
    match cli.command {
        Some(Command::Keygen) => keygen::run(),
        Some(Command::Sign) => sign::run(),
        Some(Command::Pubkey) => pubkey::run(),
        Some(Command::Ecdh) => ecdh::run(),
        Some(Command::Hmac) => hmac::run(),
        Some(Command::Seal) => seal::run_seal(),
        Some(Command::Unseal) => seal::run_unseal(),
        Some(Command::Derive) => derive::run(),
        None => Ok(()),
    }
}
