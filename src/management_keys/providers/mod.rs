pub mod openrouter;

use anyhow::{bail, Result};
use async_trait::async_trait;

pub struct ProviderKeyInfo {
    pub provider_key_id: String,
    pub label: String,
    pub disabled: bool,
    pub limit: Option<f64>,
    pub limit_reset: Option<String>,
}

pub struct ProviderKeyCreated {
    pub provider_key_id: String,
    pub label: String,
    pub plaintext_secret: String,
}

/// A provider's own management/provisioning API — calls run client-side, using
/// a management key decrypted locally, so kv_manager never sees the plaintext.
#[async_trait]
pub trait ManagementKeyProvider {
    fn id(&self) -> &'static str;
    async fn list_keys(&self, management_key: &str) -> Result<Vec<ProviderKeyInfo>>;
    async fn get_key(&self, management_key: &str, provider_key_id: &str) -> Result<ProviderKeyInfo>;
    async fn create_key(
        &self,
        management_key: &str,
        label: &str,
        limit: Option<f64>,
        limit_reset: Option<&str>,
    ) -> Result<ProviderKeyCreated>;
    async fn revoke_key(&self, management_key: &str, provider_key_id: &str) -> Result<()>;
}

pub fn provider_for(name: &str) -> Result<Box<dyn ManagementKeyProvider>> {
    match name {
        "openrouter" => Ok(Box::new(openrouter::OpenRouterProvider::new())),
        other => bail!("unsupported management key provider: {other}"),
    }
}
