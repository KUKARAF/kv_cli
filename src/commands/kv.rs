use anyhow::Result;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};

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

fn opt_str(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("-").to_string()
}

fn opt_f64(v: &Option<f64>) -> String {
    v.map(|f| f.to_string()).unwrap_or_else(|| "-".to_string())
}

// ── Commands ──────────────────────────────────────────────────────────────────

pub async fn get(client: &mut Client, key: &str) -> Result<()> {
    let path = format!("/kv/{key}");
    let resp = client.request_api_key(Method::GET, &path, None::<&()>).await?;
    let body = Client::expect_success(resp).await?;
    // Parse JSON string value if the server wraps it
    let value: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body.clone()));
    match value {
        serde_json::Value::String(s) => print!("{s}"),
        other => print!("{other}"),
    }
    Ok(())
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
        // Admin endpoint
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
        let path = format!("/kv/{key}");
        let body = KvUpsertRequest {
            value,
            ttl_hours,
            ttl_sliding: sliding,
            open_access: open,
        };
        let resp = client
            .request_api_key(Method::PUT, &path, Some(&body))
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
    let resp = client.request_api_key(Method::GET, &path, None::<&()>).await?;
    let body = Client::expect_success(resp).await?;
    let entries: Vec<KvEntry> = serde_json::from_str(&body)
        .unwrap_or_else(|_| vec![]);
    if entries.is_empty() {
        eprintln!("(no entries)");
    } else {
        println!("{}", Table::new(&entries));
    }
    Ok(())
}

pub async fn delete(client: &mut Client, key: &str) -> Result<()> {
    let path = format!("/kv/{key}");
    let resp = client
        .request_api_key(Method::DELETE, &path, None::<&()>)
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
