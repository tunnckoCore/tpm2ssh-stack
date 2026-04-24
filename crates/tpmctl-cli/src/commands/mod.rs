pub mod derive;
pub mod ecdh;
pub mod hmac;
pub mod keygen;
pub mod pubkey;
pub mod seal;
pub mod sign;

pub fn dispatch(cli: crate::args::Cli) -> tpmctl_core::Result<()> {
    match cli.command {
        Some(crate::args::Command::Keygen) => keygen::run(),
        Some(crate::args::Command::Sign) => sign::run(),
        Some(crate::args::Command::Pubkey) => pubkey::run(),
        Some(crate::args::Command::Ecdh) => ecdh::run(),
        Some(crate::args::Command::Hmac) => hmac::run(),
        Some(crate::args::Command::Seal) => seal::run_seal(),
        Some(crate::args::Command::Unseal) => seal::run_unseal(),
        Some(crate::args::Command::Derive) => derive::run(),
        None => Ok(()),
    }
}
