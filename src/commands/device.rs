use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tabled::{Table, Tabled};

use crate::client::Client;

// ── Keypair management ────────────────────────────────────────────────────────

fn key_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("kv");
    Ok(dir.join("device.key"))
}

fn load_or_create_key() -> Result<SigningKey> {
    let path = key_path()?;
    if path.exists() {
        let pem = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read key from {}", path.display()))?;
        return SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| anyhow::anyhow!("failed to parse device key: {e}"));
    }
    let key = SigningKey::random(&mut OsRng);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    key.write_pkcs8_pem_file(&path, LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to write device key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    eprintln!("Generated new device key at {}", path.display());
    Ok(key)
}

fn public_key_b64(key: &SigningKey) -> Result<String> {
    let der = key
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| anyhow::anyhow!("failed to encode public key: {e}"))?;
    Ok(B64.encode(der.as_bytes()))
}

// ── API types ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RegisterRequest {
    name: String,
    public_key: String,
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
    let key = load_or_create_key()?;
    let public_key = public_key_b64(&key)?;

    let body = RegisterRequest { name: name.clone(), public_key };
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
