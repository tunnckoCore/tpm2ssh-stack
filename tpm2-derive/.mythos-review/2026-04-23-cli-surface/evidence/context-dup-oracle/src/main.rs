use std::collections::BTreeMap;

use clap::Parser as _;

#[path = "../../../../../src/cli/args.rs"]
mod args;

fn main() {
    let cli = args::Cli::try_parse_from([
        "tpm2-derive",
        "identity",
        "dupctx",
        "--algorithm",
        "ed25519",
        "--mode",
        "seed",
        "--use",
        "encrypt",
        "--context",
        "tenant=alpha",
        "--context",
        "tenant=beta",
    ])
    .expect("parse duplicate context flags");

    match cli.command {
        args::Command::Identity(identity) => {
            let collected: BTreeMap<_, _> = identity.defaults.context.clone().into_iter().collect();
            println!("raw_context_pairs={:?}", identity.defaults.context);
            println!("collected_map={:?}", collected);
            println!("effective_tenant={}", collected.get("tenant").unwrap());
        }
        other => panic!("expected identity command, got {other:?}"),
    }
}
