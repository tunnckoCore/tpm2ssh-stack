use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "tpmctl", version, about = "TPM-backed key management CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Keygen,
    Sign,
    Pubkey,
    Ecdh,
    Hmac,
    Seal,
    Unseal,
    Derive,
}
