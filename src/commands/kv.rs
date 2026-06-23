use anyhow::{bail, Context, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};
use tokio::time::{interval, Duration};

use crate::client::Client;

// ── Request bodies ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct DeviceKvWriteRequest {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    nonce: String,
    ciphertext: String,
    aad: String,
    recipients: Vec<DeviceKvWriteRecipient>,
}

#[derive(Serialize)]
struct DeviceKvWriteRecipient {
    device_id: String,
    key_type: String,
    ephemeral_pub: String,
    dek_nonce: String,
    encrypted_dek: String,
}

#[derive(Deserialize)]
struct DeviceListEntry {
    id: String,
    name: String,
    key_type: String,
    public_key: String,
}

#[derive(Serialize)]
struct KvUpsertRequest {
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_hours: Option<f64>,
    ttl_sliding: bool,
    open_access: bool,
}

#[derive(Serialize)]
struct AdminKvWriteRequest {
    key: String,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_hours: Option<f64>,
    ttl_sliding: bool,
    open_access: bool,
}

// ── Device-encrypted KV response ─────────────────────────────────────────────

#[derive(Deserialize)]
struct DeviceKvResponse {
    nonce: String,
    ciphertext: String,
    aad: String,
    recipient: DeviceKvRecipient,
}

#[derive(Deserialize)]
struct DeviceKvRecipient {
    ephemeral_pub: String,
    dek_nonce: String,
    encrypted_dek: String,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Deserialize, Tabled)]
struct KvEntry {
    key: String,
    #[tabled(display_with = "opt_str")]
    scope: Option<String>,
    #[tabled(display_with = "opt_f64", rename = "ttl_hours")]
    ttl_hours: Option<f64>,
    #[tabled(display_with = "opt_str", rename = "expires_at")]
    expires_at: Option<String>,
    open_access: bool,
}

#[derive(Deserialize)]
struct RequestAccessResponse {
    confirm: String,
}

fn opt_str(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("-").to_string()
}

fn opt_f64(v: &Option<f64>) -> String {
    v.map(|f| f.to_string()).unwrap_or_else(|| "-".to_string())
}

// ── Commands ──────────────────────────────────────────────────────────────────

pub async fn get(client: &mut Client, key: &str, token: Option<String>) -> Result<()> {
    let path = format!("/kv/{}", urlencoding(key));

    if let Some(api_key) = token {
        // Explicit --token: approval-required / one-time flow
        return get_with_token(client, key, &api_key).await;
    }

    if let Some(api_key) = client.cfg.api_key.clone() {
        // Config API key: try it first; fall back to session token on scope error
        let resp = client.get_with_api_key(&path, &api_key).await?;
        match resp.status().as_u16() {
            200 => {
                print!("{}", resp.text().await.unwrap_or_default());
                return Ok(());
            }
            401 | 403 => {
                let status = resp.status().as_u16();
                let body: serde_json::Value =
                    serde_json::from_str(&resp.text().await.unwrap_or_default())
                        .unwrap_or_default();
                let err = body["error"].as_str().unwrap_or("");
                if err == "pending approval" {
                    return get_with_token(client, key, &api_key).await;
                }
                if err.starts_with("device-encrypted") {
                    return fetch_and_decrypt(client, key).await;
                }
                // Key expired/invalid or insufficient scope — escalate to session token
                if status == 401 {
                    eprintln!("API key invalid or expired. Removing old key.");
                    client.cfg.api_key = None;
                    let _ = client.cfg.save();
                }
                if client.silent {
                    if status == 401 {
                        bail!("API key expired or invalid (run `kv add-api-token` to update it)");
                    } else {
                        bail!("API key has insufficient scope (--silent prevents session token fallback)");
                    }
                }
                let had_session_token = client.cfg.session_token.is_some();
                // Try existing session token silently first
                if let Some(resp) = client.try_bearer_silent(Method::GET, &path, None::<&()>).await? {
                    let status = resp.status();
                    let body_text = resp.text().await.unwrap_or_default();
                    if status.as_u16() == 403 {
                        let b: serde_json::Value =
                            serde_json::from_str(&body_text).unwrap_or_default();
                        if b["error"].as_str().unwrap_or("").starts_with("device-encrypted") {
                            return fetch_and_decrypt(client, key).await;
                        }
                    }
                    if !status.is_success() {
                        bail!("server returned {status}: {body_text}");
                    }
                    print!("{body_text}");
                    return Ok(());
                }
                if had_session_token && status == 403 {
                    // Session token expired AND key is valid (scope error) — use approval flow
                    return get_with_token(client, key, &api_key).await;
                }
                // No usable session token: prompt for one
                let resp = client.request_bearer(Method::GET, &path, None::<&()>).await?;
                let body = Client::expect_success(resp).await?;
                print!("{body}");
                return Ok(());
            }
            s => bail!("unexpected status {s}"),
        }
    }

    // No API key in config: use session token directly
    let resp = client.request_bearer(Method::GET, &path, None::<&()>).await?;
    if resp.status().as_u16() == 403 {
        let body: serde_json::Value =
            serde_json::from_str(&resp.text().await.unwrap_or_default())
                .unwrap_or_default();
        if body["error"].as_str().unwrap_or("").starts_with("device-encrypted") {
            return fetch_and_decrypt(client, key).await;
        }
        bail!("{}", body["error"].as_str().unwrap_or("forbidden"));
    }
    let body = Client::expect_success(resp).await?;
    print!("{body}");
    Ok(())
}

async fn fetch_and_decrypt(client: &mut Client, key: &str) -> Result<()> {
    let device_id = client
        .cfg
        .device_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("key is device-encrypted; run `kv device register` first"))?;

    let priv_key_b64 = crate::commands::device::load_private_key_b64()?;

    let path = format!("/api/admin/devices/{}/kv/{}", device_id, urlencoding(key));
    let resp = client.request_bearer(Method::GET, &path, None::<&()>).await?;
    let text = Client::expect_success(resp).await?;

    let payload: DeviceKvResponse =
        serde_json::from_str(&text).context("failed to parse device KV response")?;

    let plaintext = crate::crypto::decrypt_device_kv(
        &priv_key_b64,
        &payload.recipient.ephemeral_pub,
        &payload.recipient.dek_nonce,
        &payload.recipient.encrypted_dek,
        &payload.nonce,
        &payload.ciphertext,
        &payload.aad,
    )?;

    print!("{}", String::from_utf8_lossy(&plaintext));
    Ok(())
}

async fn call_request_access(client: &Client, api_key: &str) -> Result<String> {
    let resp = client.post_with_api_key("/kv/request-access", api_key).await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("server returned {status}: {body}");
    }
    let parsed: RequestAccessResponse = serde_json::from_str(&body)
        .map_err(|_| anyhow::anyhow!("unexpected response: {body}"))?;
    Ok(parsed.confirm)
}

fn print_emojis(emojis: &str) {
    eprintln!();
    eprintln!("  ┌─────────────────────────────────┐");
    eprintln!("  │  Tell the key owner these emojis │");
    eprintln!("  │                                  │");
    eprintln!("  │    {}                       │", emojis);
    eprintln!("  │                                  │");
    eprintln!("  └─────────────────────────────────┘");
    eprintln!();
    eprintln!("  Polling for approval every 5s.  Press  Ctrl+C  to quit.");
    eprintln!();
}

async fn get_with_token(client: &Client, key: &str, api_key: &str) -> Result<()> {
    let path = format!("/kv/{}", urlencoding(key));

    // First try: maybe already approved or open
    let resp = client.get_with_api_key(&path, api_key).await?;
    match resp.status().as_u16() {
        200 => {
            print!("{}", resp.text().await.unwrap_or_default());
            return Ok(());
        }
        401 => bail!("link expired or already used"),
        403 => {
            let body: serde_json::Value =
                serde_json::from_str(&resp.text().await.unwrap_or_default())
                    .unwrap_or_default();
            if body["error"].as_str() != Some("pending approval") {
                bail!("{}", body["error"].as_str().unwrap_or("access denied"));
            }
            // Fall through to approval flow
        }
        s => bail!("unexpected status {s}"),
    }

    let emojis = call_request_access(client, api_key).await?;
    print_emojis(&emojis);

    let mut ticker = interval(Duration::from_secs(5));
    ticker.tick().await; // discard immediate first tick

    loop {
        ticker.tick().await;
        let resp = client.get_with_api_key(&path, api_key).await?;
        match resp.status().as_u16() {
            200 => {
                eprintln!("✅  Approved!");
                print!("{}", resp.text().await.unwrap_or_default());
                return Ok(());
            }
            401 => bail!("link expired"),
            _ => eprint!("."),
        }
    }
}

pub async fn set(
    client: &mut Client,
    key: &str,
    value: String,
    scope: Option<String>,
    ttl_hours: Option<f64>,
    sliding: bool,
    open: bool,
    device: bool,
) -> Result<()> {
    if device {
        return set_device_encrypted(client, key, value.as_bytes(), scope).await;
    }
    if let Some(ref sc) = scope {
        let body = AdminKvWriteRequest {
            key: key.to_string(),
            value,
            scope: Some(sc.clone()),
            ttl_hours,
            ttl_sliding: sliding,
            open_access: open,
        };
        let resp = client
            .request_bearer(Method::PUT, "/api/admin/kv", Some(&body))
            .await?;
        Client::expect_success(resp).await?;
    } else {
        let path = format!("/kv/{}", urlencoding(key));
        let body = KvUpsertRequest {
            value,
            ttl_hours,
            ttl_sliding: sliding,
            open_access: open,
        };
        let resp = client
            .request_bearer(Method::PUT, &path, Some(&body))
            .await?;
        Client::expect_success(resp).await?;
    }
    Ok(())
}

async fn set_device_encrypted(
    client: &mut Client,
    key: &str,
    plaintext: &[u8],
    scope: Option<String>,
) -> Result<()> {
    let resp = client
        .request_bearer(Method::GET, "/api/admin/devices", None::<&()>)
        .await?;
    let body = Client::expect_success(resp).await?;
    let devices: Vec<DeviceListEntry> =
        serde_json::from_str(&body).context("failed to parse devices list")?;

    if devices.is_empty() {
        anyhow::bail!("no registered devices — register at least one device first");
    }

    let lines: Vec<String> = devices
        .iter()
        .map(|d| format!("{:<30}  [{}]", d.name, d.key_type))
        .collect();
    let selected = crate::fzf::select(&lines, true, "Encrypt for devices (TAB to toggle) > ")?;

    let device_tuples: Vec<(String, String, String)> = selected
        .iter()
        .map(|&i| (devices[i].id.clone(), devices[i].key_type.clone(), devices[i].public_key.clone()))
        .collect();

    let payload = crate::crypto::encrypt_for_devices(key, plaintext, &device_tuples)?;

    let body = DeviceKvWriteRequest {
        key: key.to_string(),
        scope,
        nonce: payload.nonce,
        ciphertext: payload.ciphertext,
        aad: payload.aad,
        recipients: payload
            .recipients
            .into_iter()
            .map(|r| DeviceKvWriteRecipient {
                device_id: r.device_id,
                key_type: r.key_type,
                ephemeral_pub: r.ephemeral_pub,
                dek_nonce: r.dek_nonce,
                encrypted_dek: r.encrypted_dek,
            })
            .collect(),
    };

    let resp = client
        .request_bearer(Method::POST, "/api/admin/kv/device", Some(&body))
        .await?;
    Client::expect_success(resp).await?;
    let n = device_tuples.len();
    eprintln!("set {key} (device-encrypted, {n} recipient(s))");
    Ok(())
}

pub async fn list(client: &mut Client, prefix: Option<String>) -> Result<()> {
    let path = match &prefix {
        Some(p) => format!("/kv?prefix={}", urlencoding(p)),
        None => "/kv".to_string(),
    };
    let resp = client.request_bearer(Method::GET, &path, None::<&()>).await?;
    let body = Client::expect_success(resp).await?;
    let entries: Vec<KvEntry> = serde_json::from_str(&body).unwrap_or_else(|_| vec![]);
    if entries.is_empty() {
        eprintln!("(no entries)");
    } else {
        println!("{}", Table::new(&entries));
    }
    Ok(())
}

pub async fn delete(client: &mut Client, key: &str) -> Result<()> {
    let path = format!("/kv/{}", urlencoding(key));
    let resp = client
        .request_bearer(Method::DELETE, &path, None::<&()>)
        .await?;
    Client::expect_success(resp).await?;
    eprintln!("deleted {key}");
    Ok(())
}

pub async fn pick_key(client: &mut Client) -> Result<String> {
    let resp = client.request_bearer(Method::GET, "/kv", None::<&()>).await?;
    let body = Client::expect_success(resp).await?;
    let entries: Vec<KvEntry> = serde_json::from_str(&body).unwrap_or_else(|_| vec![]);
    if entries.is_empty() {
        anyhow::bail!("no KV entries found");
    }
    let lines: Vec<String> = entries
        .iter()
        .map(|e| match &e.scope {
            Some(s) => format!("{} [scope:{}]", e.key, s),
            None => e.key.clone(),
        })
        .collect();
    let selected = crate::fzf::select(&lines, false, "Select key > ")?;
    Ok(entries[selected[0]].key.clone())
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect()
            }
        })
        .collect()
}
