use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Config {
    pub base_url: Option<String>,
    pub session_token: Option<String>,
    pub api_key: Option<String>,
    pub device_id: Option<String>,
    /// A session-request awaiting human approval, saved so the NEXT `kv`
    /// invocation can claim the approved token (the token is delivered once, on
    /// the "approved" status poll) instead of blocking on a poll loop. Set when
    /// a command hits an expired/absent session and prints the approval link;
    /// cleared once claimed or found dead.
    #[serde(default)]
    pub pending_session_request: Option<PendingSessionRequest>,
}

/// Persisted handle to an in-flight session approval (see
/// [`Config::pending_session_request`]).
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct PendingSessionRequest {
    pub id: String,
    /// Proves the poller created the request (not just someone who saw the id).
    pub poll_secret: String,
    pub url: String,
    pub expires_at: String,
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }
        Ok(())
    }

    pub fn base_url(&self) -> &str {
        self.base_url
            .as_deref()
            .unwrap_or("https://kv.osmosis.page")
    }
}
