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
    Bearer,
}

#[derive(Serialize)]
struct SessionRequestBody {
    label: Option<String>,
    requested_duration_hours: Option<i64>,
    /// Registered device the approved session token will be ECDH-wrapped to.
    /// Server returns 404 if it doesn't reference an existing device.
    device_id: String,
}

#[derive(Deserialize)]
struct SessionRequestCreated {
    id: String,
    url: String,
    expires_at: String,
    /// Required to poll for the session token — proves the poller is the same party
    /// that created the request, not just someone who saw the id in the URL/QR.
    poll_secret: String,
    /// Human-verifiable code to relay to whoever approves the request out-of-band —
    /// approval is bound to this code, not just to clicking the right row.
    confirm_code: String,
}

#[derive(Deserialize)]
struct SessionRequestStatus {
    status: String,
    /// Present exactly once, on the `approved` (one-time claim) poll. Subsequent
    /// polls return `status: "delivered"` with `envelope: null`.
    #[serde(default)]
    envelope: Option<Envelope>,
}

/// ECDH-wrapped session token — same envelope scheme as device-encrypted KV values
/// (`decrypt_device_kv`). All base64 fields are STANDARD (not url-safe).
#[derive(Deserialize)]
struct Envelope {
    nonce: String,
    ciphertext: String,
    aad: String,
    recipient: EnvelopeRecipient,
}

#[derive(Deserialize)]
struct EnvelopeRecipient {
    key_type: String,
    ephemeral_pub: String,
    dek_nonce: String,
    encrypted_dek: String,
}

impl Client {
    pub fn new(cfg: Config, base_url_override: Option<String>, silent: bool) -> Result<Self> {
        let base_url = base_url_override.unwrap_or_else(|| cfg.base_url().to_string());
        let base_url = base_url.trim_end_matches('/').to_string();

        if !base_url.starts_with("https://")
            && !base_url.starts_with("http://localhost")
            && !base_url.starts_with("http://127.0.0.1")
        {
            eprintln!(
                "warning: base URL '{base_url}' is not https — session tokens and API keys \
                 will be sent in cleartext"
            );
        }

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self {
            cfg,
            base_url,
            silent,
            http,
        })
    }

    /// Check if the stored session token is valid without prompting.
    /// Returns true if the token exists and the server accepts it.
    pub async fn is_session_valid(&mut self) -> bool {
        if self.cfg.session_token.is_none() {
            return false;
        }
        match self
            .send_with_auth(Method::GET, "/kv", &Auth::Bearer, None::<&()>)
            .await
        {
            Ok(resp) => resp.status() != StatusCode::UNAUTHORIZED,
            Err(_) => false,
        }
    }

    /// Show the Tailscale-style approval flow: prints URL + QR code, polls until approved.
    /// Saves the resulting session token to config on success.
    pub async fn acquire_session_token(
        &mut self,
        label: Option<String>,
        duration_hours: Option<i64>,
        device_override: Option<String>,
    ) -> Result<()> {
        // The approved token is delivered ECDH-wrapped to a registered device's
        // public key — so we must tell the server which device to wrap it for, and
        // we need that device's private key locally to unwrap it later.
        let device_id = device_override
            .or_else(|| self.cfg.device_id.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no device registered — run `kv device register <name>`, enrol its public \
                     key via the web admin panel or Android app (WebAuthn-gated), then \
                     `kv device set-id <device-id>`, before requesting a session"
                )
            })?;

        let url = format!("{}/api/session-request", self.base_url);
        let resp = self
            .http_post_unauthenticated(
                &url,
                &SessionRequestBody {
                    label,
                    requested_duration_hours: duration_hours,
                    device_id: device_id.clone(),
                },
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status.as_u16() == 404 {
                bail!(
                    "server returned 404 for device_id {device_id}: no such registered device. \
                     Enrol this CLI's device key first (see `kv device register`), then \
                     `kv device set-id <device-id>`."
                );
            }
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
        eprintln!("  Tell whoever approves this request the confirm code:");
        eprintln!("  {}", created.confirm_code);
        eprintln!("  (approval will fail without it — this proves the approval is for you)");
        eprintln!("  Polling every 5s.  Press  Ctrl+C  to cancel.");
        eprintln!();

        let status_path = format!(
            "/api/session-request/{}/status?secret={}",
            crate::urlencode::urlencode(&created.id),
            crate::urlencode::urlencode(&created.poll_secret)
        );
        let mut ticker = interval(Duration::from_secs(5));
        ticker.tick().await;

        loop {
            ticker.tick().await;
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
                Err(_) => {
                    eprint!(".");
                    continue;
                }
            };

            match status.status.as_str() {
                "approved" => {
                    let envelope = status.envelope.ok_or_else(|| {
                        anyhow::anyhow!("server approved but returned no envelope")
                    })?;
                    // The CLI only ever registers an x25519 device key, so the envelope
                    // wrapped for our device must be x25519. `decrypt_device_kv` is
                    // x25519-only; guard against anything else rather than mis-decrypt.
                    if envelope.recipient.key_type != "x25519" {
                        bail!(
                            "session token was wrapped for key type '{}', but this CLI's device \
                             key is x25519 — cannot decrypt",
                            envelope.recipient.key_type
                        );
                    }
                    let priv_key_b64 = crate::commands::device::load_private_key_b64()?;
                    let plaintext = crate::crypto::decrypt_device_kv(
                        &priv_key_b64,
                        &envelope.recipient.ephemeral_pub,
                        &envelope.recipient.dek_nonce,
                        &envelope.recipient.encrypted_dek,
                        &envelope.nonce,
                        &envelope.ciphertext,
                        &envelope.aad,
                    )?;
                    let token = String::from_utf8(plaintext)
                        .context("decrypted session token is not valid UTF-8")?;
                    self.cfg.session_token = Some(token);
                    self.cfg.save()?;
                    eprintln!();
                    eprintln!("  ✅  Session approved, token decrypted and saved to config.");
                    return Ok(());
                }
                "delivered" => {
                    eprintln!();
                    bail!(
                        "session token was already delivered (the one-time envelope is consumed) \
                         — request a new session"
                    );
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
            Auth::Bearer => {
                if let Some(token) = self.cfg.session_token.as_deref() {
                    req = req.header("Authorization", format!("Bearer {}", token));
                }
            }
        }

        if let Some(b) = body {
            req = req.json(b);
        }

        req.send()
            .await
            .with_context(|| format!("request to {url} failed"))
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
        let resp = self
            .send_with_auth(method, path, &Auth::Bearer, body)
            .await?;
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
            let resp = self
                .send_with_auth(method, path, &Auth::Bearer, body)
                .await?;
            if resp.status() == StatusCode::UNAUTHORIZED {
                bail!("session token expired (--silent mode)");
            }
            return Ok(resp);
        }

        if self.cfg.session_token.is_none() {
            self.acquire_session_token(None, None, None).await?;
        }

        let resp = self
            .send_with_auth(method.clone(), path, &Auth::Bearer, body)
            .await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            // Clear from memory so send_with_auth doesn't retry with the stale token,
            // but don't save to disk yet — acquire_session_token will save on success.
            self.cfg.session_token = None;
            self.acquire_session_token(None, None, None).await?;
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
        self.http
            .request(method, &url)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))
    }

    /// POST JSON with no authentication headers.
    pub async fn http_post_unauthenticated(
        &self,
        url: &str,
        body: &impl Serialize,
    ) -> Result<Response> {
        self.http
            .post(url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))
    }

    /// Make a request with an explicit API key token (not from config).
    pub async fn get_with_api_key(&self, path: &str, api_key: &str) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .get(&url)
            .header("X-Api-Key", api_key)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))
    }

    pub async fn post_with_api_key(&self, path: &str, api_key: &str) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .post(&url)
            .header("X-Api-Key", api_key)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))
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
