use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Config {
    pub base_url: Option<String>,
    pub session_token: Option<String>,
    pub api_key: Option<String>,
}

impl Config {
    pub fn config_path() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .context("could not determine config directory")?
            .join("kv");
        Ok(dir.join("config.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read config at {}", path.display()))?;
        let cfg: Self = toml::from_str(&contents).context("failed to parse config")?;
        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(&path, contents)
            .with_context(|| format!("failed to write config to {}", path.display()))?;
        Ok(())
    }

    pub fn base_url(&self) -> &str {
        self.base_url.as_deref().unwrap_or("https://kv.osmosis.page")
    }

    /// Return the stored api_key, prompting and saving if absent.
    pub fn require_api_key(&mut self) -> Result<String> {
        if let Some(k) = &self.api_key {
            return Ok(k.clone());
        }
        let key = rpassword::prompt_password("API key (X-Api-Key): ")
            .context("failed to read API key")?;
        self.api_key = Some(key.trim().to_string());
        self.save()?;
        Ok(self.api_key.clone().unwrap())
    }

    /// Return the stored session_token, prompting and saving if absent.
    pub fn require_session_token(&mut self) -> Result<String> {
        if let Some(t) = &self.session_token {
            return Ok(t.clone());
        }
        eprintln!("No session token found. Get one from the admin UI (Copy Session Token button).");
        let token = rpassword::prompt_password("Session token: ")
            .context("failed to read session token")?;
        self.session_token = Some(token.trim().to_string());
        self.save()?;
        Ok(self.session_token.clone().unwrap())
    }
}
