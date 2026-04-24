use crate::{args::*, io::OutputKind};
use tpmctl_core::{self as core, GlobalOptions};

pub fn dispatch(cli: &Cli) -> core::Result<core::CommandResult> {
    let globals = GlobalOptions {
        store: cli.store.clone(),
        json: cli.json,
    };
    match &cli.command {
        Command::Keygen(_) => core::keygen::run(&globals, core::keygen::Request),
        Command::Sign(args) => {
            let _target = args.target.target();
            let _input_mode = args.data.mode();
            let _binary = args.format.is_binary();
            core::sign::run(&globals, core::sign::Request)
        }
        Command::Pubkey(args) => {
            let _target = args.target.target();
            let _binary = args.format.is_binary();
            core::pubkey::run(&globals, core::pubkey::Request)
        }
        Command::Ecdh(args) => {
            let _target = args.target.target();
            let _binary = args.format.is_binary();
            core::ecdh::run(&globals, core::ecdh::Request)
        }
        Command::Hmac(args) => {
            let _target = args.target.target();
            let _binary = args.format.is_binary();
            core::hmac::run(&globals, core::hmac::Request)
        }
        Command::Seal(args) => {
            let _target = args.target.target();
            core::seal::run(&globals, core::seal::Request)
        }
        Command::Unseal(args) => {
            let _target = args.target.target();
            let _binary = true;
            core::unseal::run(&globals, core::unseal::Request)
        }
        Command::Derive(args) => {
            let _target = args.target.target();
            let _binary = args.effective_format().is_binary();
            core::derive::run(&globals, core::derive::Request)
        }
    }
}
