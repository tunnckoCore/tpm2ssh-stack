use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    pub signature_sha: Option<String>,
    pub verified: bool,
    pub created_at: String,
    pub verified_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CredentialRegistry {
    credentials: HashMap<String, Credential>,
    #[serde(skip)]
    path: PathBuf,
}

impl CredentialRegistry {
    pub fn new(path: PathBuf) -> Self {
        Self {
            credentials: HashMap::new(),
            path,
        }
    }

    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            let parent = path.parent().ok_or_else(|| {
                anyhow::anyhow!("Cannot determine parent directory for {:?}", path)
            })?;
            std::fs::create_dir_all(parent)?;
            return Ok(Self::new(path.clone()));
        }

        let contents = std::fs::read_to_string(path)?;
        let mut registry: Self = serde_json::from_str(&contents)?;
        registry.path = path.clone();
        Ok(registry)
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(&self)?;
        std::fs::write(&self.path, contents)?;
        Ok(())
    }

    pub fn register(&mut self, user_id: String, credential: Credential) -> Result<()> {
        self.credentials.insert(user_id, credential);
        self.save()
    }

    pub fn get(&self, user_id: &str) -> Option<&Credential> {
        self.credentials.get(user_id)
    }

    pub fn get_mut(&mut self, user_id: &str) -> Option<&mut Credential> {
        self.credentials.get_mut(user_id)
    }

    #[allow(dead_code)]
    pub fn remove(&mut self, user_id: &str) -> Option<Credential> {
        let cred = self.credentials.remove(user_id);
        if cred.is_some() {
            let _ = self.save();
        }
        cred
    }

    #[allow(dead_code)]
    pub fn list(&self) -> &HashMap<String, Credential> {
        &self.credentials
    }
}
