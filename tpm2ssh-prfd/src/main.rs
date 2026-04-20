use anyhow::Result;
use hkdf::Hkdf;
use rand::Rng;
use russh::keys::ssh_key::SshSig;
use russh::keys::ssh_key::rand_core::OsRng as SshOsRng;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::*;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

mod registry;
use registry::{Credential, CredentialRegistry};

const SERVICE_SECRET_ENV: &str = "TPM2SSH_PRFD_SECRET";
const REGISTRY_PATH_ENV: &str = "TPM2SSH_PRFD_REGISTRY";
const DEFAULT_PORT: u16 = 2222;

const SIGNATURE_NAMESPACE: &str = "tpm2ssh-prfd-";
const REGISTER_MESSAGE: &[u8] = b"register-v1";

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

#[derive(Clone)]
struct ClientAuth {
    user_id: String,
    pubkey: russh::keys::ssh_key::PublicKey,
}

#[derive(Clone)]
struct PrfServer {
    registry: Arc<Mutex<CredentialRegistry>>,
    service_secret: [u8; 32],
    auth: Option<ClientAuth>,
}

#[derive(Debug)]
struct ProtocolError {
    status: u32,
    message: String,
}

impl ProtocolError {
    fn new(status: u32, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(1, format!("FAILURE 400: {}", message.into()))
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(1, format!("FAILURE 403: {}", message.into()))
    }
}

type ProtocolResult<T> = std::result::Result<T, ProtocolError>;

impl PrfServer {
    fn new(service_secret: [u8; 32], registry_path: PathBuf) -> Self {
        let registry = CredentialRegistry::load(&registry_path).unwrap_or_else(|e| {
            warn!("Failed to load registry, starting fresh: {}", e);
            CredentialRegistry::new(registry_path)
        });
        Self {
            registry: Arc::new(Mutex::new(registry)),
            service_secret,
            auth: None,
        }
    }

    fn derive_pre_prf_seed(
        &self,
        user_id: &str,
        signature_sha_hex: &str,
    ) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(None, &self.service_secret);
        let mut pre_prf_seed = [0u8; 32];
        let info = format!(
            "tpm2ssh-prfd:{}:{}",
            user_id, signature_sha_hex
        );
        hkdf.expand(info.as_bytes(), &mut pre_prf_seed)
            .expect("HKDF expand should not fail with 32-byte output");
        pre_prf_seed
    }

    fn get_auth(&self) -> ProtocolResult<&ClientAuth> {
        self.auth
            .as_ref()
            .ok_or_else(|| ProtocolError::forbidden("pubkey auth required"))
    }

    async fn prepare_verification(
        &self,
        parts: &[&str],
        usage: &str,
    ) -> ProtocolResult<(&ClientAuth, SshSig, Vec<u8>)> {
        let auth = self.get_auth()?;
        let sig_hex = parts
            .get(1)
            .ok_or_else(|| ProtocolError::bad_request(usage))?;

        let sig_bytes =
            parse_hex(sig_hex).ok_or_else(|| ProtocolError::bad_request("invalid hex signature"))?;

        let sshsig = SshSig::from_pem(&sig_bytes)
            .map_err(|_| ProtocolError::bad_request("invalid sshsig pem inside hex"))?;

        Ok((auth, sshsig, sig_bytes))
    }

    async fn handle_register(&mut self) -> ProtocolResult<String> {
        let auth = self.get_auth()?.clone();
        let mut registry = self.registry.lock().await;

        if registry.get(&auth.user_id).is_some() {
            return Err(ProtocolError::bad_request("already registered"));
        }

        let credential = Credential {
            signature_sha: None,
            verified: false,
            created_at: chrono::Utc::now().to_rfc3339(),
            verified_at: None,
        };
        registry
            .register(auth.user_id.clone(), credential)
            .map_err(|e| ProtocolError::new(1, format!("FAILURE 500: registry error: {}", e)))?;

        info!("Registered unverified credential: {}", auth.user_id);
        Ok(format!("SUCCESS: {}\n", auth.user_id))
    }

    async fn handle_verify(&mut self, parts: &[&str]) -> ProtocolResult<String> {
        let (auth, sshsig, sig_bytes) = self
            .prepare_verification(parts, "usage: verify <sig_hex>")
            .await?;

        auth.pubkey
            .verify(SIGNATURE_NAMESPACE, REGISTER_MESSAGE, &sshsig)
            .map_err(|_| ProtocolError::bad_request("signature verification failed"))?;

        let signature_sha = sha256_hex(&sig_bytes);
        let user_id = auth.user_id.clone();
        let mut registry = self.registry.lock().await;
        let cred = registry
            .get_mut(&user_id)
            .ok_or_else(|| ProtocolError::bad_request("credential not found"))?;

        cred.signature_sha = Some(signature_sha);
        cred.verified = true;
        cred.verified_at = Some(chrono::Utc::now().to_rfc3339());
        registry
            .save()
            .map_err(|e| ProtocolError::new(1, format!("FAILURE 500: registry error: {}", e)))?;

        info!("Verified credential: {}", user_id);
        Ok("SUCCESS: true\n".to_string())
    }

    async fn handle_prf(&mut self, parts: &[&str]) -> ProtocolResult<String> {
        let (auth, sshsig, _) = self
            .prepare_verification(parts, "usage: prf <sig_hex>")
            .await?;

        let pubkey_bytes = auth.pubkey.to_bytes().map_err(|_| ProtocolError::new(1, "FAILURE 500: error encoding pubkey"))?;
        let pubkey_hex = hex::encode(&pubkey_bytes);
        let prf_message = format!("{}-{}", pubkey_hex, auth.user_id);

        auth.pubkey
            .verify(SIGNATURE_NAMESPACE, prf_message.as_bytes(), &sshsig)
            .map_err(|_| ProtocolError::bad_request("signature verification failed"))?;

        let user_id = auth.user_id.clone();
        let registry = self.registry.lock().await;
        let cred = registry
            .get(&user_id)
            .ok_or_else(|| ProtocolError::forbidden("credential not registered"))?;

        if !cred.verified {
            return Err(ProtocolError::forbidden("credential not verified"));
        }

        let sig_sha = cred
            .signature_sha
            .as_ref()
            .ok_or_else(|| ProtocolError::bad_request("no signature on record"))?;

        let pre_prf_seed = self.derive_pre_prf_seed(&user_id, sig_sha);
        let response = hex::encode(&pre_prf_seed);

        info!("Generated pre_prf_seed for {}", user_id);
        Ok(format!("SUCCESS: {}\n", response))
    }

    fn handle_help(&self) -> String {
        concat!(
            "SUCCESS: Commands:\n",
            "  register                     - Register your pubkey (auth-pubkey required)\n",
            "  verify <sig_hex>             - Verify registration (auth-pubkey required)\n",
            "  prf <sig_hex>                - Get pre_prf_seed (auth-pubkey required, verified only)\n",
            "  help                         - Show this help\n",
            "\n",
            "Responses: SUCCESS: <result> | FAILURE <code>: <message>\n",
            "Codes: 400=bad request, 403=forbidden\n",
            "\n",
            "Username must be your user_id (sha256 of pubkey as hex).\n",
            "All hex values are raw hex strings (no 0x).\n",
            "sig_hex is the hex-encoded SSH Signature PEM.\n",
            "Namespace: tpm2ssh-prfd-\n",
            "Signature for 'verify': SshSig over 'register-v1'\n",
            "Signature for 'prf': SshSig over '{pubkey_hex}-{user_id}'\n",
        )
        .to_string()
    }
}

impl server::Server for PrfServer {
    type Handler = Self;

    fn new_client(&mut self, addr: Option<SocketAddr>) -> Self {
        info!("New client connection from {:?}", addr);
        self.clone()
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        error!("Session error: {:?}", error);
    }
}

impl server::Handler for PrfServer {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        let mut methods = MethodSet::empty();
        methods.push(MethodKind::PublicKey);
        Ok(Auth::Reject {
            proceed_with_methods: Some(methods),
            partial_success: false,
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let pubkey_bytes = public_key.to_bytes()?;
        let user_id = sha256_hex(&pubkey_bytes);

        if user != user_id {
            warn!(
                "Auth failed: username '{}' does not match key's user_id '{}'",
                user, user_id
            );
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        self.auth = Some(ClientAuth {
            user_id,
            pubkey: public_key.clone(),
        });
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!("Channel open session: {}", channel.id());
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);
        info!("exec_request: {}", command);

        let parts: Vec<&str> = command.split_whitespace().collect();

        let result = if parts.is_empty() {
            Ok(self.handle_help())
        } else {
            match parts[0] {
                "register" => self.handle_register().await,
                "verify" => self.handle_verify(&parts).await,
                "prf" => self.handle_prf(&parts).await,
                "help" => Ok(self.handle_help()),
                _ => Err(ProtocolError::bad_request(format!(
                    "unknown command: {}",
                    parts[0]
                ))),
            }
        };

        let (exit_status, response) = match result {
            Ok(msg) => (0, msg),
            Err(err) => (err.status, format!("{}\n", err.message)),
        };

        session.data(channel, CryptoVec::from_slice(response.as_bytes()))?;
        session.exit_status_request(channel, exit_status)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let service_secret = std::env::var(SERVICE_SECRET_ENV)
        .map(|s| {
            let bytes = hex::decode(&s).expect("SERVICE_SECRET must be 64 hex chars");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .unwrap_or_else(|_| {
            info!("No service secret provided, generating random one");
            let mut secret = [0u8; 32];
            rand::rngs::OsRng.fill(&mut secret);
            info!("Generated service secret: {}", hex::encode(&secret));
            secret
        });

    let registry_path = std::env::var(REGISTRY_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("./registry.json")
        });

    let port = std::env::var("TPM2SSH_PRFD_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let mut server = PrfServer::new(service_secret, registry_path);

    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![
            russh::keys::PrivateKey::random(&mut SshOsRng, russh::keys::Algorithm::Ed25519)
                .unwrap(),
        ],
        ..Default::default()
    };
    let config = Arc::new(config);

    let socket = TcpListener::bind(("0.0.0.0", port)).await?;
    info!("tpm2ssh-prfd listening on port {}", port);

    server.run_on_socket(config, &socket).await?;

    Ok(())
}
