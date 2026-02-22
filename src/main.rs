use hkdf::Hkdf;
use p256::SecretKey;
use rpassword::prompt_password;
use sha2::Sha256;
use ssh_key::{PrivateKey, private::EcdsaKeypair, private::KeypairData};
use std::env;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

fn get_stdio(verbose: bool) -> Stdio {
    if verbose {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

fn setup(verbose: bool) {
    let home = env::var("HOME").expect("HOME not set");
    let tpm_dir = format!("{}/.ssh/tpm2", home);
    fs::create_dir_all(&tpm_dir).unwrap();

    let pin = prompt_password("Enter new TPM PIN: ").unwrap();
    let pin_confirm = prompt_password("Confirm TPM PIN: ").unwrap();
    if pin != pin_confirm {
        eprintln!("PINs do not match.");
        std::process::exit(1);
    }

    println!("Creating primary context...");
    Command::new("tpm2_createprimary")
        .args(&["-c", &format!("{}/primary.ctx", tpm_dir)])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .unwrap();

    println!("Generating secure seed...");
    Command::new("tpm2_getrandom")
        .args(&["32", "-o", &format!("{}/seed.dat", tpm_dir)])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .unwrap();

    println!("Sealing seed into TPM...");
    Command::new("tpm2_create")
        .args(&[
            "-C",
            &format!("{}/primary.ctx", tpm_dir),
            "-p",
            &pin,
            "-i",
            &format!("{}/seed.dat", tpm_dir),
            "-u",
            &format!("{}/seal.pub", tpm_dir),
            "-r",
            &format!("{}/seal.priv", tpm_dir),
        ])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .unwrap();

    println!("Loading sealed object...");
    Command::new("tpm2_load")
        .args(&[
            "-C",
            &format!("{}/primary.ctx", tpm_dir),
            "-u",
            &format!("{}/seal.pub", tpm_dir),
            "-r",
            &format!("{}/seal.priv", tpm_dir),
            "-c",
            &format!("{}/seal.ctx", tpm_dir),
        ])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .unwrap();

    println!("Ensuring handle 0x81000001 is available...");
    let output = Command::new("tpm2_getcap")
        .args(&["handles-persistent"])
        .output()
        .unwrap();
    let handles = String::from_utf8_lossy(&output.stdout);
    if handles.contains("0x81000001") {
        if verbose {
            println!("Evicting existing object at 0x81000001...");
        }
        let _ = Command::new("tpm2_evictcontrol")
            .args(&["-C", "o", "-c", "0x81000001"])
            .stdout(get_stdio(verbose))
            .stderr(get_stdio(verbose))
            .status();
    }

    println!("Making it persistent at handle 0x81000001...");
    let status = Command::new("tpm2_evictcontrol")
        .args(&[
            "-C",
            "o",
            "-c",
            &format!("{}/seal.ctx", tpm_dir),
            "0x81000001",
        ])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .unwrap();

    if status.success() {
        println!("TPM Setup complete! You can now use --login.");
        // Clean up
        let _ = fs::remove_file(format!("{}/seed.dat", tpm_dir));
        let _ = fs::remove_file(format!("{}/primary.ctx", tpm_dir));
        let _ = fs::remove_file(format!("{}/seal.ctx", tpm_dir));
        let _ = fs::remove_file(format!("{}/seal.priv", tpm_dir));
        let _ = fs::remove_file(format!("{}/seal.pub", tpm_dir));
    } else {
        eprintln!("Failed to make object persistent.");
        std::process::exit(1);
    }
}

fn login(verbose: bool) {
    let seed = {
        let pin = match prompt_password("Enter TPM PIN: ") {
            Ok(p) => p,
            Err(_) => std::process::exit(1),
        };

        let output = Command::new("tpm2_unseal")
            .args(&["-c", "0x81000001", "-p", &pin])
            .stderr(get_stdio(verbose))
            .output()
            .unwrap();

        if !output.status.success() {
            eprintln!("Failed to unseal. Wrong PIN or TPM error.");
            std::process::exit(1);
        }
        output.stdout
    };

    let hkdf = Hkdf::<Sha256>::new(Some(&b"tmp2-based-passkeys"[..]), &seed);
    let mut expanded_key_material = [0u8; 32];
    hkdf.expand(b"charlike-tpm2ssh-info", &mut expanded_key_material)
        .unwrap();

    let secret_key = SecretKey::from_slice(&expanded_key_material).unwrap();
    let public_key_ec = secret_key.public_key();

    let ecdsa_keypair = EcdsaKeypair::NistP256 {
        private: secret_key.into(),
        public: public_key_ec.into(),
    };

    let keypair_data = KeypairData::from(ecdsa_keypair);
    // Add the comment "tpm2-derived-key"
    let private_key = PrivateKey::new(keypair_data, "tpm2-derived-key").unwrap();
    let openssh_pem = private_key.to_openssh(ssh_key::LineEnding::LF).unwrap();

    // Write public key to file for Git signing
    let home = env::var("HOME").expect("HOME not set");
    let pub_key_path = format!("{}/.ssh/tpm2/id_nistp256_tpm.pub", home);
    let public_key = private_key.public_key();
    let public_key_ssh = public_key.to_openssh().unwrap();
    fs::write(&pub_key_path, public_key_ssh).expect("Failed to write public key file");

    println!("---- THIS IS YOUR PRIVATE KEY: NO NEED TO SAVE IT BUT JUST IN CASE ----");
    println!("");
    println!("{}", openssh_pem.to_string());

    // Pipe it into ssh-add
    let socket = format!("/run/user/{}/ssh-agent.socket", unsafe { libc::getuid() });

    let mut child = Command::new("ssh-add")
        .args(&["-q", "-"])
        .env("SSH_AUTH_SOCK", &socket)
        .stdin(Stdio::piped())
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .spawn()
        .expect("Failed to spawn ssh-add");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(openssh_pem.as_bytes()).unwrap();
    }

    let status = child.wait().unwrap();
    if status.success() {
        println!("Key successfully added to ssh-agent!");
        println!("Public key written to: {}", pub_key_path);
    } else {
        eprintln!("ssh-add failed.");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let verbose = args.iter().any(|arg| arg == "--verbose" || arg == "-v");

    if args.contains(&"--setup".to_string()) {
        setup(verbose);
    } else if args.contains(&"--login".to_string()) {
        login(verbose);
    }
}
