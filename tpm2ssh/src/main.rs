use hkdf::Hkdf;
use p256::SecretKey;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use ssh_key::{PrivateKey, private::EcdsaKeypair, private::Ed25519Keypair, private::KeypairData};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tpm2_derive::backend::{ProcessCommandRunner, default_probe};
use tpm2_derive::{
    Algorithm, DerivationContext, DeriveRequest, ModePreference, SetupRequest, UseCase,
};

const DEFAULT_HANDLE: &str = "0x81006969";
const MANAGED_CONFIG_SCHEMA_VERSION: u32 = 1;
const DERIVED_KEY_BYTES: usize = 32;

#[derive(Debug, Clone)]
struct Tpm2SshPaths {
    root_dir: PathBuf,
    managed_state_dir: PathBuf,
    managed_config_path: PathBuf,
    legacy_handle_path: PathBuf,
}

impl Tpm2SshPaths {
    fn discover() -> Result<Self, String> {
        let home = env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        let root_dir = Path::new(&home).join(".ssh").join("tpm2ssh");
        Ok(Self {
            managed_state_dir: root_dir.join("tpm2-derive-state"),
            managed_config_path: root_dir.join("managed-profiles.json"),
            legacy_handle_path: root_dir.join("handle.txt"),
            root_dir,
        })
    }

    fn ensure_root_dir(&self) -> Result<(), String> {
        fs::create_dir_all(&self.root_dir).map_err(|error| {
            format!(
                "failed to create tpm2ssh directory '{}': {error}",
                self.root_dir.display()
            )
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum LoginAlgorithm {
    P256,
    Ed25519,
}

impl LoginAlgorithm {
    fn from_choice(choice: &str) -> Self {
        if ["2", "ed", "ed25519"].contains(&choice.trim()) {
            Self::Ed25519
        } else {
            Self::P256
        }
    }

    const fn as_tpm2_derive_algorithm(self) -> Algorithm {
        match self {
            Self::P256 => Algorithm::P256,
            Self::Ed25519 => Algorithm::Ed25519,
        }
    }

    const fn profile_suffix(self) -> &'static str {
        match self {
            Self::P256 => "p256",
            Self::Ed25519 => "ed25519",
        }
    }

    const fn ssh_alg_name(self) -> &'static str {
        match self {
            Self::P256 => "nistp256",
            Self::Ed25519 => "ed25519",
        }
    }

    const fn comment(self) -> &'static str {
        match self {
            Self::P256 => "tpm2ssh-nistp256-derived-key",
            Self::Ed25519 => "tpm2ssh-ed25519-derived-key",
        }
    }

    fn default_profile_name(self) -> String {
        format!("tpm2ssh-{}", self.profile_suffix())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
struct ManagedProfilesConfig {
    schema_version: u32,
    state_dir: PathBuf,
    ed25519_profile: Option<String>,
    p256_profile: Option<String>,
}

impl ManagedProfilesConfig {
    fn new(state_dir: PathBuf) -> Self {
        Self {
            schema_version: MANAGED_CONFIG_SCHEMA_VERSION,
            state_dir,
            ed25519_profile: None,
            p256_profile: None,
        }
    }

    fn profile_for(&self, algorithm: LoginAlgorithm) -> Option<&str> {
        match algorithm {
            LoginAlgorithm::Ed25519 => self.ed25519_profile.as_deref(),
            LoginAlgorithm::P256 => self.p256_profile.as_deref(),
        }
    }

    fn set_profile(&mut self, algorithm: LoginAlgorithm, profile: String) {
        match algorithm {
            LoginAlgorithm::Ed25519 => self.ed25519_profile = Some(profile),
            LoginAlgorithm::P256 => self.p256_profile = Some(profile),
        }
    }
}

fn get_stdio(verbose: bool) -> Stdio {
    if verbose {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

fn prompt(question: &str, default: &str) -> String {
    print!("{} [{}]: ", question, default);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn read_managed_profiles_config(path: &Path) -> Result<Option<ManagedProfilesConfig>, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to read managed profile config '{}': {error}",
                path.display()
            ));
        }
    };

    let config: ManagedProfilesConfig = serde_json::from_str(&contents).map_err(|error| {
        format!(
            "failed to parse managed profile config '{}': {error}",
            path.display()
        )
    })?;

    if config.schema_version != MANAGED_CONFIG_SCHEMA_VERSION {
        return Err(format!(
            "unsupported managed profile config schema {} in '{}'",
            config.schema_version,
            path.display()
        ));
    }

    Ok(Some(config))
}

fn write_managed_profiles_config(
    path: &Path,
    config: &ManagedProfilesConfig,
) -> Result<(), String> {
    let payload = format!(
        "{}\n",
        serde_json::to_string_pretty(config)
            .map_err(|error| format!("failed to serialize managed profile config: {error}"))?
    );
    fs::write(path, payload).map_err(|error| {
        format!(
            "failed to write managed profile config '{}': {error}",
            path.display()
        )
    })
}

fn get_persistent_handles() -> Vec<String> {
    let output = Command::new("tpm2_getcap")
        .args(["handles-persistent"])
        .output()
        .expect("Failed to run tpm2_getcap");

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("- ") {
                Some(trimmed[2..].to_string())
            } else if trimmed.starts_with("0x") {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn find_first_free_handle(taken: &[String]) -> String {
    for i in 0x0000..=0xFFFF {
        let handle = format!("0x8100{i:04x}");
        if !taken.contains(&handle) {
            return handle;
        }
    }

    "0x8100ffff".to_string()
}

fn setup(verbose: bool) -> Result<(), String> {
    let paths = Tpm2SshPaths::discover()?;
    paths.ensure_root_dir()?;

    println!("Choose setup backend:");
    println!("1: Managed tpm2-derive profile (recommended)");
    println!("2: Legacy persistent-handle sealed seed");
    let backend_choice = prompt("Setup backend", "1");

    if backend_choice.trim() == "2" {
        setup_legacy(verbose, &paths)
    } else {
        setup_managed(&paths)
    }
}

fn setup_managed(paths: &Tpm2SshPaths) -> Result<(), String> {
    println!("Choose algorithm to provision:");
    println!("1: NIST P-256 (nistp256r1, p256)");
    println!("2: Ed25519 (ed25519)");
    let algorithm = LoginAlgorithm::from_choice(&prompt("Algorithm", "1"));
    let default_profile_name = algorithm.default_profile_name();
    let profile_name = prompt("Managed profile name", &default_profile_name);

    let existing_config = read_managed_profiles_config(&paths.managed_config_path)?;
    let mut config = existing_config
        .unwrap_or_else(|| ManagedProfilesConfig::new(paths.managed_state_dir.clone()));
    config.state_dir = paths.managed_state_dir.clone();

    let existing_profile_path = config
        .state_dir
        .join("profiles")
        .join(format!("{profile_name}.json"));

    let profile = if existing_profile_path.is_file() {
        let profile = tpm2_derive::ops::load_profile(&profile_name, Some(config.state_dir.clone()))
            .map_err(|error| format!("failed to load existing managed profile: {error}"))?;
        if profile.algorithm != algorithm.as_tpm2_derive_algorithm() {
            return Err(format!(
                "existing managed profile '{}' uses {:?}, expected {:?}",
                profile_name,
                profile.algorithm,
                algorithm.as_tpm2_derive_algorithm()
            ));
        }
        profile
    } else {
        let request = SetupRequest {
            profile: profile_name.clone(),
            algorithm: algorithm.as_tpm2_derive_algorithm(),
            uses: vec![UseCase::Ssh, UseCase::SshAgent, UseCase::Derive],
            requested_mode: ModePreference::Auto,
            state_dir: Some(config.state_dir.clone()),
            dry_run: false,
        };
        let probe = default_probe();
        tpm2_derive::ops::resolve_profile(&probe, &request)
            .map_err(|error| format!("failed to provision managed profile: {error}"))?
            .profile
    };

    config.set_profile(algorithm, profile.name.clone());
    write_managed_profiles_config(&paths.managed_config_path, &config)?;

    println!("Managed setup complete.");
    println!("Profile: {}", profile.name);
    println!("Algorithm: {}", algorithm.profile_suffix());
    println!("Resolved mode: {:?}", profile.mode.resolved);
    println!("State dir: {}", config.state_dir.display());
    if !profile.mode.reasons.is_empty() {
        println!("Reasons:");
        for reason in &profile.mode.reasons {
            println!("- {reason}");
        }
    }
    println!(
        "Managed profile config written to: {}",
        paths.managed_config_path.display()
    );

    Ok(())
}

fn setup_legacy(verbose: bool, paths: &Tpm2SshPaths) -> Result<(), String> {
    let temp_tpm2ssh_dir = PathBuf::from("/tmp/tpm2ssh-temp");
    fs::create_dir_all(&temp_tpm2ssh_dir).map_err(|error| {
        format!(
            "failed to create temporary directory '{}': {error}",
            temp_tpm2ssh_dir.display()
        )
    })?;

    let pin = prompt_password("Enter new TPM PIN: ").map_err(|error| error.to_string())?;
    let pin_confirm = prompt_password("Confirm TPM PIN: ").map_err(|error| error.to_string())?;
    if pin != pin_confirm {
        return Err("PINs do not match.".to_string());
    }

    let seed_hex = prompt(
        "Provide 32-byte hex seed to import? (Leave empty for new)",
        "",
    );
    let seed_bytes = if !seed_hex.is_empty() {
        match hex::decode(seed_hex.trim()) {
            Ok(bytes) => {
                if bytes.len() != DERIVED_KEY_BYTES {
                    return Err(
                        "Error: Seed must be exactly 32 bytes (64 hex characters).".to_string()
                    );
                }
                bytes
            }
            Err(error) => return Err(format!("Error decoding hex seed: {error}")),
        }
    } else {
        println!("Generating secure seed...");
        let output = Command::new("tpm2_getrandom")
            .args(["32"])
            .output()
            .map_err(|error| format!("failed to run tpm2_getrandom: {error}"))?;
        if !output.status.success() {
            return Err("Failed to generate random seed from TPM.".to_string());
        }
        output.stdout
    };

    let show_seed = prompt("Show final seed for backup? (y/n)", "n").to_lowercase() == "y";
    if show_seed {
        println!("---- SEED BACKUP (HEX) ----");
        println!("{}", hex::encode(&seed_bytes));
        println!("---------------------------");
    }

    let seed_path = temp_tpm2ssh_dir.join("seed.dat");
    fs::write(&seed_path, &seed_bytes)
        .map_err(|error| format!("failed to write temporary seed file: {error}"))?;

    println!("Discovering free TPM handle...");
    let taken = get_persistent_handles();
    let chosen_handle = if taken.contains(&DEFAULT_HANDLE.to_string()) {
        let suggested = find_first_free_handle(&taken);
        prompt(
            &format!("Default handle {} is busy. Use suggested?", DEFAULT_HANDLE),
            &suggested,
        )
    } else {
        DEFAULT_HANDLE.to_string()
    };

    let primary_context = temp_tpm2ssh_dir.join("primary.ctx");
    let seal_public = temp_tpm2ssh_dir.join("seal.pub");
    let seal_private = temp_tpm2ssh_dir.join("seal.priv");
    let seal_context = temp_tpm2ssh_dir.join("seal.ctx");

    println!("Creating primary context...");
    let status = Command::new("tpm2_createprimary")
        .args(["-c", &primary_context.display().to_string()])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .map_err(|error| format!("failed to run tpm2_createprimary: {error}"))?;
    if !status.success() {
        return Err("tpm2_createprimary failed".to_string());
    }

    println!("Sealing seed into TPM...");
    run_tpm_command_with_auth(
        Command::new("tpm2_create")
            .args([
                "-C",
                &primary_context.display().to_string(),
                "-p",
                "file:-",
                "-i",
                &seed_path.display().to_string(),
                "-u",
                &seal_public.display().to_string(),
                "-r",
                &seal_private.display().to_string(),
            ])
            .stdout(get_stdio(verbose))
            .stderr(Stdio::piped()),
        &pin,
    )
    .map_err(|error| format!("failed to seal legacy seed: {error}"))?;

    println!("Loading sealed object...");
    let status = Command::new("tpm2_load")
        .args([
            "-C",
            &primary_context.display().to_string(),
            "-u",
            &seal_public.display().to_string(),
            "-r",
            &seal_private.display().to_string(),
            "-c",
            &seal_context.display().to_string(),
        ])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .map_err(|error| format!("failed to run tpm2_load: {error}"))?;
    if !status.success() {
        return Err("tpm2_load failed".to_string());
    }

    println!("Making it persistent at handle {}...", chosen_handle);
    let status = Command::new("tpm2_evictcontrol")
        .args([
            "-C",
            "o",
            "-c",
            &seal_context.display().to_string(),
            &chosen_handle,
        ])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .map_err(|error| format!("failed to run tpm2_evictcontrol: {error}"))?;

    let _ = fs::remove_file(&seed_path);
    let _ = fs::remove_file(&primary_context);
    let _ = fs::remove_file(&seal_context);
    let _ = fs::remove_file(&seal_private);
    let _ = fs::remove_file(&seal_public);

    if status.success() {
        fs::write(&paths.legacy_handle_path, &chosen_handle).map_err(|error| {
            format!(
                "failed to write legacy handle file '{}': {error}",
                paths.legacy_handle_path.display()
            )
        })?;
        println!("Legacy TPM setup complete! Handle saved to handle.txt.");
        Ok(())
    } else {
        Err(format!(
            "Failed to make object persistent. Cleaned the temp dir {}",
            temp_tpm2ssh_dir.display()
        ))
    }
}

fn login(verbose: bool) -> Result<(), String> {
    let paths = Tpm2SshPaths::discover()?;
    paths.ensure_root_dir()?;

    let username = prompt("Identity username", &whoami::username().unwrap());

    println!("Choose algorithm:");
    println!("1: NIST P-256 (nistp256r1, p256, passkey)");
    println!("2: Ed25519 (ed, ed25519)");
    let algorithm = LoginAlgorithm::from_choice(&prompt("Algorithm", "1"));

    let show_priv = prompt("Show private key for backup? (y/n)", "n").to_lowercase() == "y";

    if try_login_with_managed_profile(&paths, algorithm, &username, show_priv, verbose)? {
        return Ok(());
    }

    login_legacy(&paths, algorithm, &username, show_priv, verbose)
}

fn try_login_with_managed_profile(
    paths: &Tpm2SshPaths,
    algorithm: LoginAlgorithm,
    username: &str,
    show_priv: bool,
    verbose: bool,
) -> Result<bool, String> {
    let Some(config) = read_managed_profiles_config(&paths.managed_config_path)? else {
        return Ok(false);
    };

    let Some(profile_name) = config.profile_for(algorithm).map(ToOwned::to_owned) else {
        return Ok(false);
    };

    let profile = tpm2_derive::ops::load_profile(&profile_name, Some(config.state_dir.clone()))
        .map_err(|error| format!("failed to load managed profile '{}': {error}", profile_name))?;

    if profile.algorithm != algorithm.as_tpm2_derive_algorithm() {
        return Err(format!(
            "managed profile '{}' resolves to {:?}, but login requested {:?}",
            profile_name,
            profile.algorithm,
            algorithm.as_tpm2_derive_algorithm()
        ));
    }

    let mut context_fields = BTreeMap::new();
    context_fields.insert(
        "algorithm".to_string(),
        algorithm.profile_suffix().to_string(),
    );
    context_fields.insert("format".to_string(), "openssh-private-key".to_string());
    context_fields.insert("flow".to_string(), "ssh-agent-add".to_string());

    let request = DeriveRequest {
        profile: profile.name.clone(),
        context: DerivationContext {
            version: 1,
            purpose: "ssh-agent-add".to_string(),
            namespace: "tpm2ssh".to_string(),
            label: Some("openssh-key".to_string()),
            context: context_fields,
        },
        length: DERIVED_KEY_BYTES as u16,
    };

    let runner = ProcessCommandRunner;
    let result = tpm2_derive::ops::derive::execute_with_defaults(&profile, &request, &runner)
        .map_err(|error| {
            format!(
                "managed derive failed for profile '{}': {error}",
                profile.name
            )
        })?;
    let key_material = decode_key_material(&result.material)?;

    let private_key = build_private_key(algorithm, &key_material)?;
    let socket =
        add_private_key_to_agent(paths, username, algorithm, &private_key, show_priv, verbose)?;

    println!("Key successfully added to ssh-agent through managed profile!");
    println!("Managed profile: {}", profile.name);
    println!("Resolved mode: {:?}", result.mode);
    println!("SSH_AUTH_SOCK={socket}");

    Ok(true)
}

fn login_legacy(
    paths: &Tpm2SshPaths,
    algorithm: LoginAlgorithm,
    username: &str,
    show_priv: bool,
    verbose: bool,
) -> Result<(), String> {
    let handle = fs::read_to_string(&paths.legacy_handle_path)
        .unwrap_or_else(|_| DEFAULT_HANDLE.to_string());
    let pin = prompt_password("Enter TPM PIN: ").map_err(|error| error.to_string())?;
    let output = run_tpm_command_with_auth(
        Command::new("tpm2_unseal")
            .args(["-c", handle.trim(), "-p", "file:-"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        &pin,
    )
    .map_err(|error| format!("failed to unseal legacy seed: {error}"))?;

    if verbose && !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    let seed = output.stdout;
    let hkdf = Hkdf::<Sha256>::new(Some(&b"tpm2ssh-v1-based-keys"[..]), &seed);
    let mut expanded_key_material = [0u8; DERIVED_KEY_BYTES];
    hkdf.expand(b"tpm2ssh-hkdf-info", &mut expanded_key_material)
        .map_err(|_| "failed to expand legacy HKDF key material".to_string())?;

    let private_key = build_private_key(algorithm, &expanded_key_material)?;
    let socket =
        add_private_key_to_agent(paths, username, algorithm, &private_key, show_priv, verbose)?;

    println!("Key successfully added to ssh-agent!");
    println!("SSH_AUTH_SOCK={socket}");
    Ok(())
}

fn build_private_key(algorithm: LoginAlgorithm, material: &[u8]) -> Result<PrivateKey, String> {
    if material.len() != DERIVED_KEY_BYTES {
        return Err(format!(
            "expected {DERIVED_KEY_BYTES} bytes of key material, got {}",
            material.len()
        ));
    }

    let keypair_data = match algorithm {
        LoginAlgorithm::Ed25519 => {
            let mut seed = [0u8; DERIVED_KEY_BYTES];
            seed.copy_from_slice(material);
            KeypairData::from(Ed25519Keypair::from_seed(&seed))
        }
        LoginAlgorithm::P256 => {
            let secret_key = p256_secret_key_from_material(material)?;
            let public_key_ec = secret_key.public_key();
            KeypairData::from(EcdsaKeypair::NistP256 {
                private: secret_key.into(),
                public: public_key_ec.into(),
            })
        }
    };

    PrivateKey::new(keypair_data, algorithm.comment())
        .map_err(|error| format!("failed to construct OpenSSH private key: {error}"))
}

fn p256_secret_key_from_material(material: &[u8]) -> Result<SecretKey, String> {
    if let Ok(secret_key) = SecretKey::from_slice(material) {
        return Ok(secret_key);
    }

    for counter in 1u32..=1024 {
        let mut hasher = Sha256::new();
        hasher.update(b"tpm2ssh-p256-scalar-fallback-v1");
        hasher.update(material);
        hasher.update(counter.to_be_bytes());
        let candidate = hasher.finalize();
        if let Ok(secret_key) = SecretKey::from_slice(candidate.as_slice()) {
            return Ok(secret_key);
        }
    }

    Err("failed to deterministically normalize P-256 key material".to_string())
}

fn decode_key_material(material_hex: &str) -> Result<[u8; DERIVED_KEY_BYTES], String> {
    let bytes = hex::decode(material_hex.trim())
        .map_err(|error| format!("failed to decode derived key material: {error}"))?;
    let array: [u8; DERIVED_KEY_BYTES] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "expected {DERIVED_KEY_BYTES} bytes of derived key material, got {}",
            bytes.len()
        )
    })?;
    Ok(array)
}

fn add_private_key_to_agent(
    paths: &Tpm2SshPaths,
    username: &str,
    algorithm: LoginAlgorithm,
    private_key: &PrivateKey,
    show_priv: bool,
    verbose: bool,
) -> Result<String, String> {
    let openssh_pem = private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|error| format!("failed to serialize OpenSSH private key: {error}"))?;

    let pub_key_filename = format!("id_{}_{}_tpm2.pub", username, algorithm.ssh_alg_name());
    let pub_key_path = paths.root_dir.join(pub_key_filename);
    let pub_key_exists = pub_key_path.exists();

    let public_key = private_key.public_key();
    let mut public_key_ssh = public_key
        .to_openssh()
        .map_err(|error| format!("failed to serialize OpenSSH public key: {error}"))?;
    if !public_key_ssh.ends_with('\n') {
        public_key_ssh.push('\n');
    }
    fs::write(&pub_key_path, public_key_ssh).map_err(|error| {
        format!(
            "failed to write public key '{}': {error}",
            pub_key_path.display()
        )
    })?;

    if show_priv {
        println!();
        println!("{}", openssh_pem.as_str());
    }

    let socket = ssh_agent_socket();
    let mut child = Command::new("ssh-add")
        .args(["-q", "-"])
        .env("SSH_AUTH_SOCK", &socket)
        .stdin(Stdio::piped())
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .spawn()
        .map_err(|error| format!("failed to spawn ssh-add: {error}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(openssh_pem.as_bytes())
            .map_err(|error| format!("failed to stream private key to ssh-add: {error}"))?;
    }

    let status = child
        .wait()
        .map_err(|error| format!("failed waiting for ssh-add: {error}"))?;
    if !status.success() {
        return Err("ssh-add failed".to_string());
    }

    if pub_key_exists {
        println!("Public key already exists at: {}", pub_key_path.display());
    } else {
        println!("Public key written to: {}", pub_key_path.display());
    }

    Ok(socket)
}

fn ssh_agent_socket() -> String {
    env::var("SSH_AUTH_SOCK")
        .unwrap_or_else(|_| format!("/run/user/{}/ssh-agent.socket", unsafe { libc::getuid() }))
}

fn run_tpm_command_with_auth(command: &mut Command, auth: &str) -> Result<Output, String> {
    let mut child = command
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to spawn TPM command: {error}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(auth.as_bytes())
            .map_err(|error| format!("failed to write TPM auth to stdin: {error}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed waiting for TPM command: {error}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            Err("command returned non-zero status".to_string())
        } else {
            Err(stderr)
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let verbose = args.iter().any(|arg| arg == "--verbose" || arg == "-v");

    let result = if args.contains(&"--setup".to_string()) {
        setup(verbose)
    } else if args.contains(&"--login".to_string()) {
        login(verbose)
    } else {
        println!("Usage: tpm2ssh [--setup | --login] [-v | --verbose]");
        Ok(())
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_profiles_config_tracks_profiles_per_algorithm() {
        let mut config = ManagedProfilesConfig::new(PathBuf::from("/tmp/tpm2ssh-state"));
        config.set_profile(LoginAlgorithm::Ed25519, "ssh-ed25519".to_string());
        config.set_profile(LoginAlgorithm::P256, "ssh-p256".to_string());

        assert_eq!(
            config.profile_for(LoginAlgorithm::Ed25519),
            Some("ssh-ed25519")
        );
        assert_eq!(config.profile_for(LoginAlgorithm::P256), Some("ssh-p256"));
    }

    #[test]
    fn decode_key_material_requires_exactly_thirty_two_bytes() {
        let error = decode_key_material("aa").expect_err("short material should be rejected");
        assert!(error.contains("expected 32 bytes"));
    }

    #[test]
    fn p256_secret_key_falls_back_for_zero_scalar_material() {
        let material = [0u8; DERIVED_KEY_BYTES];
        let secret_key = p256_secret_key_from_material(&material)
            .expect("fallback should produce a valid secret key");
        assert_ne!(secret_key.to_bytes().as_slice(), material.as_slice());
    }
}
