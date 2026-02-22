use anyhow::Result;
use base64::Engine;
use hkdf::Hkdf;
use rand::Rng;
use russh::keys::ssh_key::rand_core::OsRng as SshOsRng;
use russh::keys::ssh_key::{HashAlg, SshSig};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::*;
use sha2::Sha256;
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

const SIGNATURE_NAMESPACE: &str = "tpm2ssh-prfd";
const SIGNATURE_MESSAGE: &[u8] = b"register-v1";

#[derive(Clone)]
struct PrfServer {
    registry: Arc<Mutex<CredentialRegistry>>,
    service_secret: [u8; 32],
    clients: Arc<Mutex<HashMap<usize, Option<String>>>>,
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
        fingerprint: &str,
        signature: &[u8],
        pubkey_bytes: &[u8],
    ) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(None, &self.service_secret);
        let mut pre_prf_seed = [0u8; 32];
        let info = format!(
            "tpm2ssh-prfd:{}:{}:{}",
            fingerprint,
            base64::engine::general_purpose::STANDARD.encode(signature),
            base64::engine::general_purpose::STANDARD.encode(pubkey_bytes)
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
        let mut clients = self.clients.lock().await;
        clients.insert(self.id, None);
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();

        let registry = self.registry.lock().await;
        if registry.get(&fingerprint).is_some() {
            let mut clients = self.clients.lock().await;
            clients.insert(self.id, Some(fingerprint));
            return Ok(Auth::Accept);
        }

        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
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

        if parts.is_empty() {
            let err = b"Error: empty command\n";
            session.data(channel, CryptoVec::from_slice(err))?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }

        match parts[0] {
            "register" => {
                if parts.len() < 2 {
                    session.data(
                        channel,
                        CryptoVec::from_slice(b"Usage: register <pubkey_b64>\n"),
                    )?;
                } else {
                    let pubkey_b64 = parts[1];
                    let pubkey_bytes =
                        match base64::engine::general_purpose::STANDARD.decode(pubkey_b64) {
                            Ok(b) => b,
                            Err(e) => {
                                session.data(
                                    channel,
                                    CryptoVec::from_slice(
                                        format!("Error: invalid base64 pubkey: {}\n", e).as_bytes(),
                                    ),
                                )?;
                                session.eof(channel)?;
                                session.close(channel)?;
                                return Ok(());
                            }
                        };

                    let pubkey = match russh::keys::ssh_key::PublicKey::from_bytes(&pubkey_bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            session.data(
                                channel,
                                CryptoVec::from_slice(
                                    format!("Error: invalid public key: {}\n", e).as_bytes(),
                                ),
                            )?;
                            session.eof(channel)?;
                            session.close(channel)?;
                            return Ok(());
                        }
                    };

                    let fingerprint = pubkey.fingerprint(HashAlg::Sha256);
                    let fingerprint_str = fingerprint.to_string();

                    let mut registry = self.registry.lock().await;
                    let credential = Credential {
                        pubkey_b64: pubkey_b64.to_string(),
                        signature_b64: None,
                        verified: false,
                        registered_at: chrono::Utc::now().to_rfc3339(),
                    };
                    registry.register(fingerprint_str.clone(), credential)?;

                    info!("Registered unverified credential: {}", fingerprint_str);
                    session.data(
                        channel,
                        CryptoVec::from_slice(
                            format!("Registered: {} (unverified)\n", fingerprint_str).as_bytes(),
                        ),
                    )?;
                }
            }
            "verify" => {
                let clients = self.clients.lock().await;
                let auth_fingerprint = clients.get(&self.id).cloned();
                drop(clients);

                let Some(Some(fingerprint)) = auth_fingerprint else {
                    session.data(
                        channel,
                        CryptoVec::from_slice(b"Error: pubkey auth required\n"),
                    )?;
                    session.eof(channel)?;
                    session.close(channel)?;
                    return Ok(());
                };

                if parts.len() < 2 {
                    session.data(
                        channel,
                        CryptoVec::from_slice(b"Usage: verify <sshsig_pem>\n"),
                    )?;
                    session.data(
                        channel,
                        CryptoVec::from_slice(
                            b"Signature must be SshSig PEM over message 'tpm2ssh-prfd-register-v1' with namespace 'tpm2ssh-prfd'\n",
                        ),
                    )?;
                } else {
                    let sshsig_pem = parts[1];

                    let mut registry = self.registry.lock().await;
                    let Some(cred) = registry.get_mut(&fingerprint) else {
                        session.data(
                            channel,
                            CryptoVec::from_slice(b"Error: credential not found\n"),
                        )?;
                        session.eof(channel)?;
                        session.close(channel)?;
                        return Ok(());
                    };

                    let pubkey = match russh::keys::ssh_key::PublicKey::from_bytes(
                        &base64::engine::general_purpose::STANDARD
                            .decode(&cred.pubkey_b64)
                            .unwrap_or_default(),
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            session.data(
                                channel,
                                CryptoVec::from_slice(
                                    format!("Error: stored pubkey invalid: {}\n", e).as_bytes(),
                                ),
                            )?;
                            session.eof(channel)?;
                            session.close(channel)?;
                            return Ok(());
                        }
                    };

                    let sshsig = match SshSig::from_pem(sshsig_pem.as_bytes()) {
                        Ok(s) => s,
                        Err(e) => {
                            session.data(
                                channel,
                                CryptoVec::from_slice(
                                    format!("Error: invalid SshSig PEM: {}\n", e).as_bytes(),
                                ),
                            )?;
                            session.eof(channel)?;
                            session.close(channel)?;
                            return Ok(());
                        }
                    };

                    if pubkey
                        .verify(SIGNATURE_NAMESPACE, SIGNATURE_MESSAGE, &sshsig)
                        .is_err()
                    {
                        session.data(
                            channel,
                            CryptoVec::from_slice(b"Error: signature verification failed\n"),
                        )?;
                        session.eof(channel)?;
                        session.close(channel)?;
                        return Ok(());
                    }

                    cred.signature_b64 = Some(sshsig_pem.to_string());
                    cred.verified = true;
                    registry.save()?;

                    info!("Verified credential: {}", fingerprint);
                    session.data(
                        channel,
                        CryptoVec::from_slice(format!("Verified: {}\n", fingerprint).as_bytes()),
                    )?;
                }
            }
            "prf" => {
                if parts.len() < 2 {
                    session.data(channel, CryptoVec::from_slice(b"Usage: prf <pubkey_b64>\n"))?;
                } else {
                    let pubkey_b64 = parts[1];
                    let pubkey_bytes =
                        match base64::engine::general_purpose::STANDARD.decode(pubkey_b64) {
                            Ok(b) => b,
                            Err(e) => {
                                session.data(
                                    channel,
                                    CryptoVec::from_slice(
                                        format!("Error: invalid base64 pubkey: {}\n", e).as_bytes(),
                                    ),
                                )?;
                                session.eof(channel)?;
                                session.close(channel)?;
                                return Ok(());
                            }
                        };

                    let pubkey = match russh::keys::ssh_key::PublicKey::from_bytes(&pubkey_bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            session.data(
                                channel,
                                CryptoVec::from_slice(
                                    format!("Error: invalid public key: {}\n", e).as_bytes(),
                                ),
                            )?;
                            session.eof(channel)?;
                            session.close(channel)?;
                            return Ok(());
                        }
                    };

                    let fingerprint = pubkey.fingerprint(HashAlg::Sha256);
                    let fingerprint_str = fingerprint.to_string();

                    let registry = self.registry.lock().await;
                    if let Some(cred) = registry.get(&fingerprint_str) {
                        if !cred.verified {
                            session.data(
                                channel,
                                CryptoVec::from_slice(b"Error: credential not verified\n"),
                            )?;
                        } else if let Some(sig_b64) = &cred.signature_b64 {
                            let pre_prf_seed = self.derive_pre_prf_seed(
                                &fingerprint_str,
                                sig_b64.as_bytes(),
                                &pubkey_bytes,
                            );
                            let response =
                                base64::engine::general_purpose::STANDARD.encode(&pre_prf_seed);

                            info!("Generated pre_prf_seed for {}", fingerprint_str);
                            session.data(channel, CryptoVec::from_slice(response.as_bytes()))?;
                        } else {
                            session.data(
                                channel,
                                CryptoVec::from_slice(b"Error: no signature on record\n"),
                            )?;
                        }
                    } else {
                        session.data(
                            channel,
                            CryptoVec::from_slice(b"Error: credential not registered\n"),
                        )?;
                    }
                }
            }
            "help" => {
                let help = concat!(
                    "Commands:\n",
                    "  register <pubkey_b64>     - Register pubkey (auth-none, unverified)\n",
                    "  verify <sshsig_pem>       - Verify registration (auth-pubkey required)\n",
                    "  prf <pubkey_b64>          - Get pre_prf_seed for verified pubkey\n",
                    "  help                      - Show this help\n",
                    "\n",
                    "Signature for verify: SshSig PEM over 'tpm2ssh-prfd-register-v1' with namespace 'tpm2ssh-prfd'\n",
                );
                session.data(channel, CryptoVec::from_slice(help.as_bytes()))?;
            }
            _ => {
                let err = format!("Unknown command: {}. Use 'help' for usage.\n", parts[0]);
                session.data(channel, CryptoVec::from_slice(err.as_bytes()))?;
            }
        }

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
