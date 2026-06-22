use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand_core::OsRng;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tabled::{Table, Tabled};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::client::Client;

// ── Keypair management ────────────────────────────────────────────────────────

fn key_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("kv");
    Ok(dir.join("device.key"))
}

fn load_or_create_key() -> Result<StaticSecret> {
    let path = key_path()?;
    if path.exists() {
        let b64 = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read key from {}", path.display()))?;
        let bytes: [u8; 32] = B64
            .decode(b64.trim())
            .context("device.key is not valid base64 — delete it and re-register")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("device.key has wrong length — delete it and re-register"))?;
        return Ok(StaticSecret::from(bytes));
    }
    let secret = StaticSecret::random_from_rng(OsRng);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, B64.encode(secret.as_bytes()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    eprintln!("Generated new device key at {}", path.display());
    Ok(secret)
}

pub fn load_private_key_b64() -> Result<String> {
    let path = key_path()?;
    std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read device key from {}", path.display()))
        .map(|s| s.trim().to_string())
}

// ── API types ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RegisterRequest {
    name: String,
    public_key: String,
    key_type: &'static str,
}

#[derive(Deserialize)]
struct RegisterResponse {
    id: String,
}

#[derive(Deserialize, Tabled)]
struct DeviceRow {
    id: String,
    name: String,
    created_at: String,
    #[tabled(display_with = "opt_str")]
    last_seen_at: Option<String>,
}

fn opt_str(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("-").to_string()
}

// ── Commands ──────────────────────────────────────────────────────────────────

pub async fn register(client: &mut Client, name: String) -> Result<()> {
    let secret = load_or_create_key()?;
    let public_key = B64.encode(PublicKey::from(&secret).as_bytes());

    let body = RegisterRequest { name: name.clone(), public_key, key_type: "x25519" };
    let resp = client
        .request_bearer(Method::POST, "/api/devices", Some(&body))
        .await?;
    let text = Client::expect_success(resp).await?;
    let created: RegisterResponse =
        serde_json::from_str(&text).context("failed to parse registration response")?;

    client.cfg.device_id = Some(created.id.clone());
    client.cfg.save()?;

    eprintln!("Registered device '{}' (id: {})", name, created.id);
    Ok(())
}

pub async fn list(client: &mut Client) -> Result<()> {
    let resp = client
        .request_bearer(Method::GET, "/api/admin/devices", None::<&()>)
        .await?;
    let body = Client::expect_success(resp).await?;
    let devices: Vec<DeviceRow> =
        serde_json::from_str(&body).context("failed to parse devices response")?;
    if devices.is_empty() {
        eprintln!("(no devices)");
    } else {
        println!("{}", Table::new(&devices));
    }
    Ok(())
}

pub async fn unregister(client: &mut Client, id: String) -> Result<()> {
    let path = format!("/api/admin/devices/{id}");
    let resp = client
        .request_bearer(Method::DELETE, &path, None::<&()>)
        .await?;
    Client::expect_success(resp).await?;
    if client.cfg.device_id.as_deref() == Some(&id) {
        client.cfg.device_id = None;
        client.cfg.save()?;
    }
    eprintln!("Unregistered device {id}");
    Ok(())
}
