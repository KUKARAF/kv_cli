use super::{ManagementKeyProvider, ProviderKeyCreated, ProviderKeyInfo};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

// priority-notify's management-key API (app/routes/tokens.py): a management key
// sent as Bearer may list/create/revoke that user's client tokens. Tokens have
// no spend limits, so limit/limit_reset are rejected rather than ignored.
const DEFAULT_BASE_URL: &str = "https://notifications.osmosis.page";

pub struct PriorityNotifyProvider {
    http: reqwest::Client,
    base_url: String,
}

impl PriorityNotifyProvider {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client")?;
        let base_url = std::env::var("PRIORITY_NOTIFY_BASE_URL")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        Ok(Self { http, base_url })
    }

    fn tokens_url(&self) -> String {
        format!("{}/api/tokens/", self.base_url)
    }
}

#[derive(Deserialize)]
struct TokenData {
    id: String,
    name: String,
}

impl TokenData {
    fn into_info(self) -> ProviderKeyInfo {
        ProviderKeyInfo {
            provider_key_id: self.id,
            label: self.name,
            disabled: false, // priority-notify tokens are deleted, never disabled
            limit: None,
            limit_reset: None,
        }
    }
}

#[derive(Deserialize)]
struct CreatedResponse {
    id: String,
    name: String,
    token: String, // plaintext, shown only once
}

async fn error_for_status(resp: reqwest::Response) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    bail!("priority-notify returned {status}: {body}");
}

#[async_trait]
impl ManagementKeyProvider for PriorityNotifyProvider {
    fn id(&self) -> &'static str {
        "priority-notify"
    }

    async fn list_keys(&self, management_key: &str) -> Result<Vec<ProviderKeyInfo>> {
        let resp = self
            .http
            .get(self.tokens_url())
            .bearer_auth(management_key)
            .send()
            .await
            .context("priority-notify list-tokens request failed")?;
        let resp = error_for_status(resp).await?;
        let parsed: Vec<TokenData> = resp
            .json()
            .await
            .context("failed to parse priority-notify list-tokens response")?;
        Ok(parsed.into_iter().map(TokenData::into_info).collect())
    }

    async fn get_key(
        &self,
        management_key: &str,
        provider_key_id: &str,
    ) -> Result<ProviderKeyInfo> {
        // No single-token GET endpoint; filter the list.
        let keys = self.list_keys(management_key).await?;
        keys.into_iter()
            .find(|k| k.provider_key_id == provider_key_id)
            .ok_or_else(|| anyhow::anyhow!("token {provider_key_id} not found on priority-notify"))
    }

    async fn create_key(
        &self,
        management_key: &str,
        label: &str,
        limit: Option<f64>,
        limit_reset: Option<&str>,
    ) -> Result<ProviderKeyCreated> {
        if limit.is_some() || limit_reset.is_some() {
            bail!("priority-notify tokens do not support limits");
        }
        let body = serde_json::json!({
            "name": label,
            "device_type": "other",
            "scope": "write",
        });
        let resp = self
            .http
            .post(self.tokens_url())
            .bearer_auth(management_key)
            .json(&body)
            .send()
            .await
            .context("priority-notify create-token request failed")?;
        let resp = error_for_status(resp).await?;
        let parsed: CreatedResponse = resp
            .json()
            .await
            .context("failed to parse priority-notify create-token response")?;
        Ok(ProviderKeyCreated {
            provider_key_id: parsed.id,
            label: parsed.name,
            plaintext_secret: parsed.token,
        })
    }

    async fn revoke_key(&self, management_key: &str, provider_key_id: &str) -> Result<()> {
        let url = format!(
            "{}{}",
            self.tokens_url(),
            crate::urlencode::urlencode(provider_key_id)
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(management_key)
            .send()
            .await
            .context("priority-notify revoke-token request failed")?;
        error_for_status(resp).await?;
        Ok(())
    }
}
