use anyhow::{bail, Context, Result};
use reqwest::{Method, Response, StatusCode};
use serde::Serialize;

use crate::config::Config;

pub struct Client {
    pub cfg: Config,
    pub base_url: String,
    pub silent: bool,
    http: reqwest::Client,
}

enum Auth {
    ApiKey,
    Bearer,
}

impl Client {
    pub fn new(cfg: Config, base_url_override: Option<String>, silent: bool) -> Self {
        let base_url = base_url_override
            .unwrap_or_else(|| cfg.base_url().to_string());
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            cfg,
            base_url,
            silent,
            http: reqwest::Client::new(),
        }
    }

    /// Check if the stored session token is valid without prompting.
    /// Returns true if the token exists and the server accepts it.
    pub async fn is_session_valid(&self) -> bool {
        if self.cfg.session_token.is_none() {
            return false;
        }
        match self.send_with_auth(Method::GET, "/kv", &Auth::Bearer, None::<&()>).await {
            Ok(resp) => resp.status() != StatusCode::UNAUTHORIZED,
            Err(_) => false,
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
                if let Some(key) = self.cfg.api_key.as_deref() {
                    req = req.header("X-Api-Key", key);
                }
            }
            Auth::Bearer => {
                if let Some(token) = self.cfg.session_token.as_deref() {
                    req = req.header("Authorization", format!("Bearer {}", token));
                }
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

     /// Try with session token without prompting.
     /// Returns Some(response) if the token exists and the server returns non-401.
     /// Returns None if no token is stored or the token is expired (401).
     /// Silently removes the token from config if it's invalid.
     pub async fn try_bearer_silent(
         &mut self,
         method: Method,
         path: &str,
         body: Option<&impl Serialize>,
     ) -> Result<Option<Response>> {
         if self.cfg.session_token.is_none() {
             return Ok(None);
         }
         let resp = self.send_with_auth(method, path, &Auth::Bearer, body).await?;
         if resp.status() == StatusCode::UNAUTHORIZED {
             // Token is invalid — remove it silently for next time
             self.cfg.session_token = None;
             let _ = self.cfg.save();
             Ok(None)
         } else {
             Ok(Some(resp))
         }
     }

     pub async fn request_bearer(
         &mut self,
         method: Method,
         path: &str,
         body: Option<&impl Serialize>,
     ) -> Result<Response> {
         if self.silent {
             if self.cfg.session_token.is_none() {
                 bail!("no session token configured (--silent mode)");
             }
             let resp = self.send_with_auth(method, path, &Auth::Bearer, body).await?;
             if resp.status() == StatusCode::UNAUTHORIZED {
                 bail!("session token expired (--silent mode)");
             }
             return Ok(resp);
         }
         self.cfg.require_session_token()?;
         let resp = self
             .send_with_auth(method.clone(), path, &Auth::Bearer, body)
             .await?;
         if resp.status() == StatusCode::UNAUTHORIZED {
             eprintln!("Session token invalid or expired. Removing old token.");
             // Clear the invalid token from config
             self.cfg.session_token = None;
             self.cfg.save()?;
             eprintln!("Get a new one from the admin UI (Copy Session Token button).");
             let new_token = rpassword::prompt_password("New session token: ")
                 .context("failed to read session token")?;
             self.cfg.session_token = Some(new_token.trim().to_string());
             self.cfg.save()?;
             let resp2 = self
                 .send_with_auth(method, path, &Auth::Bearer, body)
                 .await?;
             if resp2.status() == StatusCode::UNAUTHORIZED {
                 eprintln!("New session token also invalid. Removing it.");
                 self.cfg.session_token = None;
                 self.cfg.save()?;
                 bail!("Authentication failed with new token");
             }
             return Ok(resp2);
         }
         Ok(resp)
     }

    /// Make a request with an explicit API key token (not from config).
    pub async fn get_with_api_key(&self, path: &str, api_key: &str) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self.http.get(&url)
            .header("X-Api-Key", api_key)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?)
    }

    pub async fn post_with_api_key(&self, path: &str, api_key: &str) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self.http.post(&url)
            .header("X-Api-Key", api_key)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?)
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
