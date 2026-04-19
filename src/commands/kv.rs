use anyhow::{bail, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};
use tokio::time::{interval, Duration};

use crate::client::Client;

// ── Request bodies ────────────────────────────────────────────────────────────

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
                let body: serde_json::Value =
                    serde_json::from_str(&resp.text().await.unwrap_or_default())
                        .unwrap_or_default();
                if body["error"].as_str() == Some("pending approval") {
                    return get_with_token(client, key, &api_key).await;
                }
                // Key expired/invalid or insufficient scope — escalate to session token
                if client.silent {
                    bail!("API key expired, invalid, or has insufficient scope (--silent prevents session token fallback)");
                }
                let had_session_token = client.cfg.session_token.is_some();
                eprintln!("API key unavailable, trying session token…");
                if let Some(resp) = client.try_bearer_silent(Method::GET, &path, None::<&()>).await? {
                    let body = Client::expect_success(resp).await?;
                    print!("{body}");
                    return Ok(());
                }
                if had_session_token {
                    // Session token was present but expired: fall back to API key
                    eprintln!("Session token expired, falling back to API key…");
                    return get_with_token(client, key, &api_key).await;
                }
                // No session token yet: prompt for one then use it
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
    let body = Client::expect_success(resp).await?;
    print!("{body}");
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
    eprintln!("  Polling for approval every 5s.");
    eprintln!("  Press  r ↵  to regenerate emojis");
    eprintln!("  Press  q ↵  to quit");
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

    // Spawn a background task that forwards stdin lines on a channel
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

    // Outer loop — re-enters when user regenerates
    loop {
        let emojis = call_request_access(client, api_key).await?;
        print_emojis(&emojis);

        let mut ticker = interval(Duration::from_secs(5));
        ticker.tick().await; // discard immediate first tick

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let resp = client.get_with_api_key(&path, api_key).await?;
                    match resp.status().as_u16() {
                        200 => {
                            eprintln!("✅  Approved!");
                            print!("{}", resp.text().await.unwrap_or_default());
                            return Ok(());
                        }
                        401 => bail!("link expired"),
                        _ => eprint!("."), // still pending
                    }
                }
                Some(line) = stdin_rx.recv() => {
                    match line.trim() {
                        "r" | "R" => {
                            eprintln!("Regenerating…");
                            break; // break inner → outer loop regenerates
                        }
                        "q" | "Q" => bail!("cancelled"),
                        _ => {}
                    }
                }
            }
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
) -> Result<()> {
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
