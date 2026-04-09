use anyhow::{bail, Context, Result};
use reqwest::{Method, Response, StatusCode};
use serde::Serialize;

use crate::config::Config;

pub struct Client {
    pub cfg: Config,
    pub base_url: String,
    http: reqwest::Client,
}

enum Auth {
    ApiKey,
    Bearer,
}

impl Client {
    pub fn new(cfg: Config, base_url_override: Option<String>) -> Self {
        let base_url = base_url_override
            .unwrap_or_else(|| cfg.base_url().to_string());
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            cfg,
            base_url,
            http: reqwest::Client::new(),
        }
    }

    async fn send_with_auth(
        &self,
        method: Method,
        path: &str,
        auth: &Auth,
        body: Option<&impl Serialize>,
    ) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, &url);

        match auth {
            Auth::ApiKey => {
                let key = self.cfg.api_key.as_deref().unwrap_or_default();
                req = req.header("X-Api-Key", key);
            }
            Auth::Bearer => {
                let token = self.cfg.session_token.as_deref().unwrap_or_default();
                req = req.header("Authorization", format!("Bearer {}", token));
            }
        }

        if let Some(b) = body {
            req = req.json(b);
        }

        Ok(req.send().await.with_context(|| format!("request to {url} failed"))?)
    }

    /// Execute a request, handling 401 with one interactive retry.
    pub async fn request_api_key(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<Response> {
        self.cfg.require_api_key()?;
        let resp = self
            .send_with_auth(method.clone(), path, &Auth::ApiKey, body)
            .await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            eprintln!("Token expired. Get a new one from the admin UI (Copy Session Token button).");
            let new_key = rpassword::prompt_password("New API key: ")
                .context("failed to read API key")?;
            self.cfg.api_key = Some(new_key.trim().to_string());
            self.cfg.save()?;
            let resp2 = self
                .send_with_auth(method, path, &Auth::ApiKey, body)
                .await?;
            if resp2.status() == StatusCode::UNAUTHORIZED {
                bail!("Authentication failed after retry");
            }
            return Ok(resp2);
        }
        Ok(resp)
    }

    pub async fn request_bearer(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<Response> {
        self.cfg.require_session_token()?;
        let resp = self
            .send_with_auth(method.clone(), path, &Auth::Bearer, body)
            .await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            eprintln!("Token expired. Get a new one from the admin UI (Copy Session Token button).");
            let new_token = rpassword::prompt_password("New session token: ")
                .context("failed to read session token")?;
            self.cfg.session_token = Some(new_token.trim().to_string());
            self.cfg.save()?;
            let resp2 = self
                .send_with_auth(method, path, &Auth::Bearer, body)
                .await?;
            if resp2.status() == StatusCode::UNAUTHORIZED {
                bail!("Authentication failed after retry");
            }
            return Ok(resp2);
        }
        Ok(resp)
    }

    pub async fn expect_success(resp: Response) -> Result<String> {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("server returned {status}: {body}");
        }
        Ok(body)
    }
}
