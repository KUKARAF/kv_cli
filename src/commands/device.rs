use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tabled::{Table, Tabled};

use crate::client::Client;

const KEYRING_SERVICE: &str = "kv";
const KEYRING_ACCOUNT: &str = "device-key";

// ── Keypair management ────────────────────────────────────────────────────────

/// Load (or generate) the device signing key.
///
/// `key_file = Some(path)` → plaintext file fallback (headless/CI, prints warning).
/// `key_file = None`       → OS keyring (GNOME Keyring / macOS Keychain / DPAPI).
fn load_or_create_key(key_file: Option<&Path>) -> Result<SigningKey> {
    if let Some(path) = key_file {
        eprintln!("warning: using unencrypted key file at {}", path.display());
        return load_or_create_key_file(path);
    }

    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| anyhow::anyhow!("keyring unavailable: {e}\nHint: pass --key-file for headless environments"))?;

    match entry.get_password() {
        Ok(b64) => {
            let der = B64.decode(b64.trim()).context("failed to decode key from keyring")?;
            SigningKey::from_pkcs8_der(&der)
                .map_err(|e| anyhow::anyhow!("failed to parse key from keyring: {e}"))
        }
        Err(keyring::Error::NoEntry) => {
            let key = SigningKey::random(&mut OsRng);
            let der = key
                .to_pkcs8_der()
                .map_err(|e| anyhow::anyhow!("failed to encode key: {e}"))?;
            entry
                .set_password(&B64.encode(der.as_bytes()))
                .map_err(|e| anyhow::anyhow!("failed to save key to keyring: {e}"))?;
            eprintln!("Device key saved to OS keyring.");
            Ok(key)
        }
        Err(e) => Err(anyhow::anyhow!(
            "keyring error: {e}\nHint: pass --key-file for headless environments"
        )),
    }
}

fn load_or_create_key_file(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read key from {}", path.display()))?;
        return SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| anyhow::anyhow!("failed to parse device key: {e}"));
    }
    let key = SigningKey::random(&mut OsRng);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    key.write_pkcs8_pem_file(path, LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to write device key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    eprintln!("Device key written to {}", path.display());
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

pub async fn register(client: &mut Client, name: String, key_file: Option<PathBuf>) -> Result<()> {
    let key_file_ref = key_file.as_deref();
    let key = tokio::task::block_in_place(|| load_or_create_key(key_file_ref))?;
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

/// Print this device's public key (base64 SPKI DER).
pub fn pubkey(key_file: Option<PathBuf>) -> Result<()> {
    let key_file_ref = key_file.as_deref();
    let key = load_or_create_key(key_file_ref)?;
    println!("{}", public_key_b64(&key)?);
    Ok(())
}

