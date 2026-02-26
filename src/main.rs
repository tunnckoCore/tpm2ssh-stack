use anyhow::Result;
use hkdf::Hkdf;
use rand::Rng;
use russh::keys::ssh_key::SshSig;
use russh::keys::ssh_key::rand_core::OsRng as SshOsRng;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
    pubkey_hex: String,
}

#[derive(Clone)]
struct PrfServer {
    registry: Arc<Mutex<CredentialRegistry>>,
    service_secret: [u8; 32],
    clients: Arc<Mutex<HashMap<usize, Option<ClientAuth>>>>,
    id: usize,
}

impl PrfServer {
    fn new(service_secret: [u8; 32], registry_path: PathBuf) -> Self {
        let registry = CredentialRegistry::load(&registry_path).unwrap_or_else(|e| {
            warn!("Failed to load registry, starting fresh: {}", e);
            CredentialRegistry::new(registry_path)
        });
        Self {
            registry: Arc::new(Mutex::new(registry)),
            service_secret,
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        }
    }

    fn derive_pre_prf_seed(
        &self,
        user_id: &str,
        signature_sha_hex: &str,
        pubkey_hex: &str,
    ) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(None, &self.service_secret);
        let mut pre_prf_seed = [0u8; 32];
        let info = format!(
            "tpm2ssh-prfd:{}:{}:{}",
            user_id, signature_sha_hex, pubkey_hex
        );
        hkdf.expand(info.as_bytes(), &mut pre_prf_seed)
            .expect("HKDF expand should not fail with 32-byte output");
        pre_prf_seed
    }
}

impl server::Server for PrfServer {
    type Handler = Self;

    fn new_client(&mut self, addr: Option<SocketAddr>) -> Self {
        info!("New client connection from {:?}", addr);
        let mut s = self.clone();
        s.id = self.id;
        self.id += 1;
        s
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
        let pubkey_hex = hex::encode(&pubkey_bytes);

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

        let mut clients = self.clients.lock().await;
        clients.insert(
            self.id,
            Some(ClientAuth {
                user_id,
                pubkey_hex,
            }),
        );
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
        let mut exit_status: u32 = 0;

        if parts.is_empty() {
            session.data(
                channel,
                CryptoVec::from_slice(b"FAILURE 400: empty command\n"),
            )?;
            exit_status = 1;
        } else {
            match parts[0] {
                "register" => {
                    let clients = self.clients.lock().await;
                    let auth = clients.get(&self.id).cloned();
                    drop(clients);

                    if let Some(Some(ClientAuth {
                        user_id,
                        pubkey_hex,
                    })) = auth
                    {
                        let mut registry = self.registry.lock().await;
                        if registry.get(&user_id).is_some() {
                            session.data(
                                channel,
                                CryptoVec::from_slice(b"FAILURE 400: already registered\n"),
                            )?;
                            exit_status = 1;
                        } else {
                            let credential = Credential {
                                pubkey_hex,
                                signature_sha: None,
                                verified: false,
                                created_at: chrono::Utc::now().to_rfc3339(),
                                verified_at: None,
                            };
                            registry.register(user_id.clone(), credential)?;

                            info!("Registered unverified credential: {}", user_id);
                            session.data(
                                channel,
                                CryptoVec::from_slice(format!("SUCCESS: {}\n", user_id).as_bytes()),
                            )?;
                        }
                    } else {
                        session.data(
                            channel,
                            CryptoVec::from_slice(b"FAILURE 403: pubkey auth required\n"),
                        )?;
                        exit_status = 1;
                    }
                }
                "verify" => {
                    let clients = self.clients.lock().await;
                    let auth = clients.get(&self.id).cloned();
                    drop(clients);

                    if let Some(Some(ClientAuth {
                        user_id,
                        pubkey_hex,
                    })) = auth
                    {
                        if parts.len() < 2 {
                            session.data(
                                channel,
                                CryptoVec::from_slice(b"FAILURE 400: usage: verify <sig_hex>\n"),
                            )?;
                            exit_status = 1;
                        } else {
                            let sig_hex = parts[1];
                            if let Some(sig_bytes) = parse_hex(sig_hex) {
                                let pubkey_bytes = parse_hex(&pubkey_hex).unwrap_or_default();
                                let pubkey_res =
                                    russh::keys::ssh_key::PublicKey::from_bytes(&pubkey_bytes);

                                if let Ok(pubkey) = pubkey_res {
                                    if let Ok(sshsig) = SshSig::from_pem(&sig_bytes) {
                                        if pubkey
                                            .verify(SIGNATURE_NAMESPACE, REGISTER_MESSAGE, &sshsig)
                                            .is_ok()
                                        {
                                            let signature_sha = sha256_hex(&sig_bytes);
                                            let mut registry = self.registry.lock().await;
                                            if let Some(cred) = registry.get_mut(&user_id) {
                                                cred.signature_sha = Some(signature_sha);
                                                cred.verified = true;
                                                cred.verified_at =
                                                    Some(chrono::Utc::now().to_rfc3339());
                                                registry.save()?;

                                                info!("Verified credential: {}", user_id);
                                                session.data(
                                                    channel,
                                                    CryptoVec::from_slice(b"SUCCESS: true\n"),
                                                )?;
                                            } else {
                                                session.data(
                                                    channel,
                                                    CryptoVec::from_slice(
                                                        b"FAILURE 400: credential not found\n",
                                                    ),
                                                )?;
                                                exit_status = 1;
                                            }
                                        } else {
                                            session.data(
                                                channel,
                                                CryptoVec::from_slice(
                                                    b"FAILURE 400: signature verification failed\n",
                                                ),
                                            )?;
                                            exit_status = 1;
                                        }
                                    } else {
                                        session.data(
                                            channel,
                                            CryptoVec::from_slice(
                                                b"FAILURE 400: invalid sshsig pem inside hex\n",
                                            ),
                                        )?;
                                        exit_status = 1;
                                    }
                                } else {
                                    session.data(
                                        channel,
                                        CryptoVec::from_slice(
                                            b"FAILURE 400: server error - stored key corrupted\n",
                                        ),
                                    )?;
                                    exit_status = 1;
                                }
                            } else {
                                session.data(
                                    channel,
                                    CryptoVec::from_slice(b"FAILURE 400: invalid hex signature\n"),
                                )?;
                                exit_status = 1;
                            }
                        }
                    } else {
                        session.data(
                            channel,
                            CryptoVec::from_slice(b"FAILURE 403: pubkey auth required\n"),
                        )?;
                        exit_status = 1;
                    }
                }
                "prf" => {
                    let clients = self.clients.lock().await;
                    let auth = clients.get(&self.id).cloned();
                    drop(clients);

                    if let Some(Some(ClientAuth {
                        user_id,
                        pubkey_hex,
                    })) = auth
                    {
                        if parts.len() < 2 {
                            session.data(
                                channel,
                                CryptoVec::from_slice(b"FAILURE 400: usage: prf <sig_hex>\n"),
                            )?;
                            exit_status = 1;
                        } else {
                            let sig_hex = parts[1];
                            if let Some(sig_bytes) = parse_hex(sig_hex) {
                                let pubkey_bytes = parse_hex(&pubkey_hex).unwrap_or_default();
                                let pubkey_res =
                                    russh::keys::ssh_key::PublicKey::from_bytes(&pubkey_bytes);

                                if let Ok(pubkey) = pubkey_res {
                                    if let Ok(sshsig) = SshSig::from_pem(&sig_bytes) {
                                        let prf_message = format!("{}-{}", pubkey_hex, user_id);
                                        if pubkey
                                            .verify(
                                                SIGNATURE_NAMESPACE,
                                                prf_message.as_bytes(),
                                                &sshsig,
                                            )
                                            .is_ok()
                                        {
                                            let registry = self.registry.lock().await;
                                            match registry.get(&user_id) {
                                                Some(cred) if !cred.verified => {
                                                    session.data(
                                                        channel,
                                                        CryptoVec::from_slice(b"FAILURE 403: credential not verified\n"),
                                                    )?;
                                                    exit_status = 1;
                                                }
                                                Some(cred) => {
                                                    if let Some(sig_sha) = &cred.signature_sha {
                                                        let pre_prf_seed = self
                                                            .derive_pre_prf_seed(
                                                                &user_id,
                                                                sig_sha,
                                                                &pubkey_hex,
                                                            );
                                                        let response = hex::encode(&pre_prf_seed);

                                                        info!(
                                                            "Generated pre_prf_seed for {}",
                                                            user_id
                                                        );
                                                        session.data(
                                                            channel,
                                                            CryptoVec::from_slice(
                                                                format!("SUCCESS: {}\n", response)
                                                                    .as_bytes(),
                                                            ),
                                                        )?;
                                                    } else {
                                                        session.data(
                                                            channel,
                                                            CryptoVec::from_slice(b"FAILURE 400: no signature on record\n"),
                                                        )?;
                                                        exit_status = 1;
                                                    }
                                                }
                                                None => {
                                                    session.data(
                                                        channel,
                                                        CryptoVec::from_slice(b"FAILURE 403: credential not registered\n"),
                                                    )?;
                                                    exit_status = 1;
                                                }
                                            }
                                        } else {
                                            session.data(
                                                channel,
                                                CryptoVec::from_slice(
                                                    b"FAILURE 400: signature verification failed\n",
                                                ),
                                            )?;
                                            exit_status = 1;
                                        }
                                    } else {
                                        session.data(
                                            channel,
                                            CryptoVec::from_slice(
                                                b"FAILURE 400: invalid sshsig pem inside hex\n",
                                            ),
                                        )?;
                                        exit_status = 1;
                                    }
                                } else {
                                    session.data(
                                        channel,
                                        CryptoVec::from_slice(
                                            b"FAILURE 400: server error - stored key corrupted\n",
                                        ),
                                    )?;
                                    exit_status = 1;
                                }
                            } else {
                                session.data(
                                    channel,
                                    CryptoVec::from_slice(b"FAILURE 400: invalid hex signature\n"),
                                )?;
                                exit_status = 1;
                            }
                        }
                    } else {
                        session.data(
                            channel,
                            CryptoVec::from_slice(b"FAILURE 403: pubkey auth required\n"),
                        )?;
                        exit_status = 1;
                    }
                }
                "help" => {
                    let help = concat!(
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
                    );
                    session.data(channel, CryptoVec::from_slice(help.as_bytes()))?;
                }
                _ => {
                    session.data(
                        channel,
                        CryptoVec::from_slice(
                            format!("FAILURE 400: unknown command: {}\n", parts[0]).as_bytes(),
                        ),
                    )?;
                    exit_status = 1;
                }
            }
        }

        session.exit_status_request(channel, exit_status)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

impl Drop for PrfServer {
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
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
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".config/tpm2ssh-prfd/registry.json")
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
