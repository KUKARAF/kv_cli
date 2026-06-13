use anyhow::{bail, Context, Result};
use qrcode::{render::unicode, QrCode};
use reqwest::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::interval;

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

#[derive(Serialize)]
struct SessionRequestBody {
    label: Option<String>,
}

#[derive(Deserialize)]
struct SessionRequestCreated {
    id: String,
    url: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct SessionRequestStatus {
    status: String,
    session_token: Option<String>,
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
    pub async fn is_session_valid(&mut self) -> bool {
        if self.cfg.session_token.is_none() {
            return false;
        }
        match self.send_with_auth(Method::GET, "/kv", &Auth::Bearer, None::<&()>).await {
            Ok(resp) => resp.status() != StatusCode::UNAUTHORIZED,
            Err(_) => false,
        }
    }

    /// Show the Tailscale-style approval flow: prints URL + QR code, polls until approved.
    /// Saves the resulting session token to config on success.
    pub async fn acquire_session_token(&mut self, label: Option<String>) -> Result<()> {
        let url = format!("{}/api/session-request", self.base_url);
        let resp = self
            .http_post_unauthenticated(&url, &SessionRequestBody { label })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("server returned {status}: {text}");
        }

        let created: SessionRequestCreated = resp.json().await?;

        eprintln!();
        eprintln!("  Approval URL:");
        eprintln!("  {}", created.url);
        eprintln!("  Expires: {}", created.expires_at);
        eprintln!();

        print_qr(&created.url);

        eprintln!("  Open the URL or scan the QR code to approve.");
        eprintln!("  Polling every 5s.  Press  q ↵  to cancel.");
        eprintln!();

        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<String>(4);
        tokio::task::spawn_blocking(move || {
            loop {
                let mut line = String::new();
                if std::io::stdin().read_line(&mut line).is_err() {
                    break;
                }
                if stdin_tx.blocking_send(line).is_err() {
                    break;
                }
            }
        });

        let status_path = format!("/api/session-request/{}/status", created.id);
        let mut ticker = interval(Duration::from_secs(5));
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let resp = self.send_unauthenticated(Method::GET, &status_path).await?;
                    let status_code = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();

                    if status_code == 404 {
                        bail!("request not found (expired?)");
                    }
                    if status_code != 200 {
                        eprint!(".");
                        continue;
                    }

                    let status: SessionRequestStatus = match serde_json::from_str(&body) {
                        Ok(s) => s,
                        Err(_) => { eprint!("."); continue; }
                    };

                    match status.status.as_str() {
                        "approved" => {
                            let token = status.session_token
                                .ok_or_else(|| anyhow::anyhow!("server approved but returned no token"))?;
                            self.cfg.session_token = Some(token);
                            self.cfg.save()?;
                            eprintln!();
                            eprintln!("  ✅  Session approved and saved to config.");
                            return Ok(());
                        }
                        "rejected" => {
                            eprintln!();
                            bail!("request was rejected");
                        }
                        "expired" => {
                            eprintln!();
                            bail!("request expired without approval");
                        }
                        _ => eprint!("."),
                    }
                }
                Some(line) = stdin_rx.recv() => {
                    match line.trim() {
                        "q" | "Q" => bail!("cancelled"),
                        _ => {}
                    }
                }
            }
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

        if self.cfg.session_token.is_none() {
            self.acquire_session_token(None).await?;
        }

        let resp = self
            .send_with_auth(method.clone(), path, &Auth::Bearer, body)
            .await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            // Clear from memory so send_with_auth doesn't retry with the stale token,
            // but don't save to disk yet — acquire_session_token will save on success.
            self.cfg.session_token = None;
            self.acquire_session_token(None).await?;
            let resp2 = self
                .send_with_auth(method, path, &Auth::Bearer, body)
                .await?;
            if resp2.status() == StatusCode::UNAUTHORIZED {
                bail!("authentication failed after re-approval");
            }
            return Ok(resp2);
        }

        Ok(resp)
    }

    /// Make a GET/etc request with no authentication headers.
    pub async fn send_unauthenticated(&self, method: Method, path: &str) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self
            .http
            .request(method, &url)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?)
    }

    /// POST JSON with no authentication headers.
    pub async fn http_post_unauthenticated(
        &self,
        url: &str,
        body: &impl Serialize,
    ) -> Result<Response> {
        Ok(self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?)
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

fn print_qr(url: &str) {
    match QrCode::new(url.as_bytes()) {
        Ok(code) => {
            let image = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Dark)
                .light_color(unicode::Dense1x2::Light)
                .build();
            eprintln!("{}", image);
        }
        Err(_) => eprintln!("  (QR generation failed, use the URL above)"),
    }
}
