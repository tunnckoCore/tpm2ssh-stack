use clap::Parser;

fn main() {
    let cli = tpm2_derive::cli::Cli::parse();

    match tpm2_derive::cli::run(cli) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
