use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "tpmctl", version, about = "TPM-backed key management helper")]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,

    #[arg(long, global = true, value_name = "PATH")]
    pub store: Option<PathBuf>,

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
