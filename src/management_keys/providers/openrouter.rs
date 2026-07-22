use super::{ManagementKeyProvider, ProviderKeyCreated, ProviderKeyInfo};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

// https://openrouter.ai/docs/features/provisioning-api-keys
const BASE_URL: &str = "https://openrouter.ai/api/v1/keys";

pub struct OpenRouterProvider {
    http: reqwest::Client,
}

impl OpenRouterProvider {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }
}

// The docs confirm the endpoints/methods below but not the exact response field
// names for `data` entries — `id` is accepted as an alias for `hash` in case the
// live API uses one or the other. Verify against a real account and adjust if
// OpenRouter's response shape differs.
#[derive(Deserialize)]
struct KeyData {
    #[serde(alias = "id")]
    hash: String,
    name: String,
    #[serde(default)]
    disabled: bool,
}

#[derive(Deserialize)]
struct ListResponse {
    data: Vec<KeyData>,
}

#[derive(Deserialize)]
struct CreateResponse {
    data: KeyData,
    key: String,
}

async fn error_for_status(resp: reqwest::Response) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    bail!("openrouter returned {status}: {body}");
}

#[async_trait]
impl ManagementKeyProvider for OpenRouterProvider {
    fn id(&self) -> &'static str {
        "openrouter"
    }

    async fn list_keys(&self, management_key: &str) -> Result<Vec<ProviderKeyInfo>> {
        let resp = self
            .http
            .get(BASE_URL)
            .bearer_auth(management_key)
            .send()
            .await
            .context("openrouter list-keys request failed")?;
        let resp = error_for_status(resp).await?;
        let parsed: ListResponse = resp
            .json()
            .await
            .context("failed to parse openrouter list-keys response")?;

        Ok(parsed
            .data
            .into_iter()
            .map(|k| ProviderKeyInfo {
                provider_key_id: k.hash,
                label: k.name,
                disabled: k.disabled,
            })
            .collect())
    }

    async fn create_key(
        &self,
        management_key: &str,
        label: &str,
        limit: Option<f64>,
        limit_reset: Option<&str>,
    ) -> Result<ProviderKeyCreated> {
        let url = format!("{BASE_URL}/");
        let body = serde_json::json!({ "name": label, "limit": limit });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(management_key)
            .json(&body)
            .send()
            .await
            .context("openrouter create-key request failed")?;
        let resp = error_for_status(resp).await?;
        let parsed: CreateResponse = resp
            .json()
            .await
            .context("failed to parse openrouter create-key response")?;

        // Per OpenRouter's docs, `limit_reset` is only documented on the update (PATCH)
        // endpoint, not on create — so applying a reset cadence takes a follow-up call.
        if let Some(reset) = limit_reset {
            let update_url = format!("{BASE_URL}/{}", parsed.data.hash);
            let resp = self
                .http
                .patch(&update_url)
                .bearer_auth(management_key)
                .json(&serde_json::json!({ "limit_reset": reset }))
                .send()
                .await
                .context("openrouter update-key (limit_reset) request failed")?;
            error_for_status(resp).await?;
        }

        Ok(ProviderKeyCreated {
            provider_key_id: parsed.data.hash,
            label: parsed.data.name,
            plaintext_secret: parsed.key,
        })
    }

    async fn revoke_key(&self, management_key: &str, provider_key_id: &str) -> Result<()> {
        let url = format!("{BASE_URL}/{provider_key_id}");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(management_key)
            .send()
            .await
            .context("openrouter revoke-key request failed")?;
        error_for_status(resp).await?;
        Ok(())
    }
}
