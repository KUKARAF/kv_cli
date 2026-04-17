use anyhow::{Context, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};

use crate::client::Client;

// ── Request bodies ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ScopeRule {
    scope: String,
    ops: Vec<String>,
}

#[derive(Serialize)]
struct CreateKeyRequest {
    label: String,
    key_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    scopes: Vec<ScopeRule>,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Deserialize, Tabled)]
struct ApiKeyEntry {
    id: String,
    label: String,
    #[tabled(rename = "type")]
    key_type: String,
    status: String,
    #[tabled(display_with = "opt_str")]
    expires_at: Option<String>,
    #[tabled(display_with = "opt_str")]
    last_used_at: Option<String>,
}

fn opt_str(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("-").to_string()
}

// ── Commands ──────────────────────────────────────────────────────────────────

pub async fn list(client: &mut Client) -> Result<()> {
    let resp = client
        .request_bearer(Method::GET, "/api/admin/keys", None::<&()>)
        .await?;
    let body = Client::expect_success(resp).await?;
    let entries: Vec<ApiKeyEntry> = serde_json::from_str(&body)
        .context("failed to parse keys response")?;
    if entries.is_empty() {
        eprintln!("(no keys)");
    } else {
        println!("{}", Table::new(&entries));
    }
    Ok(())
}

pub async fn create(
    client: &mut Client,
    label: String,
    key_type: String,
    scopes_raw: Vec<String>,
) -> Result<()> {
    let scopes = parse_scopes(&scopes_raw)?;
    let body = CreateKeyRequest {
        label,
        key_type,
        expires_at: None,
        scopes,
    };
    let resp = client
        .request_bearer(Method::POST, "/api/admin/keys", Some(&body))
        .await?;
    let body_str = Client::expect_success(resp).await?;
    // Server returns JSON with `key` field or just the raw key string
    let key = extract_key_from_response(&body_str);
    println!("{key}");
    eprintln!("⚠  Copy this key now — it will not be shown again.");
    Ok(())
}

pub async fn revoke(client: &mut Client, id: &str) -> Result<()> {
    let path = format!("/api/admin/keys/{id}");
    let resp = client
        .request_bearer(Method::DELETE, &path, None::<&()>)
        .await?;
    Client::expect_success(resp).await?;
    eprintln!("revoked {id}");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_scopes(raw: &[String]) -> Result<Vec<ScopeRule>> {
    raw.iter()
        .map(|s| {
            let (pattern, ops_str) = s
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("invalid scope format {s:?} — expected pattern:ops"))?;
            let ops = ops_str.split(',').map(|o| o.trim().to_string()).collect();
            Ok(ScopeRule {
                scope: pattern.trim().to_string(),
                ops,
            })
        })
        .collect()
}

fn extract_key_from_response(body: &str) -> String {
    // Try to parse as JSON object with a `key` field
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(k) = v.get("key").and_then(|k| k.as_str()) {
            return k.to_string();
        }
        if let Some(k) = v.get("api_key").and_then(|k| k.as_str()) {
            return k.to_string();
        }
    }
    body.trim().to_string()
}
