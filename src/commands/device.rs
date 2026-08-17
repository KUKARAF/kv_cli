use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand_core::OsRng;
use reqwest::Method;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;
use tabled::{Table, Tabled};
use tokio::time::interval;
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
            .map_err(|_| {
                anyhow::anyhow!("device.key has wrong length — delete it and re-register")
            })?;
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

// Device registration is WebAuthn-gated and two-step on the server:
//   POST /api/devices/register/begin  {name, public_key, key_type}
//        -> {challenge_id, options}   (a WebAuthn assertion challenge)
//   POST /api/devices/register/finish {challenge_id, assertion}
//        -> {id}
// A headless CLI cannot produce the signed WebAuthn assertion the `finish` step
// requires, so we deliberately do NOT drive this flow (and never fabricate an
// assertion). `register` (legacy, manual) generates + stores the keypair locally
// and prints the public key for a human to enrol via a WebAuthn-capable surface
// (web admin panel or Android app); `set-id` then records the server-assigned
// device id.
//
// `propose` (recommended) automates the same enrolment without any copy-pasting:
//   POST /api/devices/propose {name, public_key, key_type} -> {id, url, expires_at, poll_secret}
//   GET  /api/devices/propose/{id}/status?secret=...       -> {status, device_id?}
// The security gate is unchanged (an admin must confirm via WebAuthn on the
// dashboard) — this just replaces manual copy/paste with polling.

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

pub fn register(name: String) -> Result<()> {
    eprintln!(
        "  note: `kv device propose <name>` automates this whole flow (no manual \
         set-id step) — prefer it unless you have a reason not to."
    );
    let secret = load_or_create_key()?;
    let public_key = B64.encode(PublicKey::from(&secret).as_bytes());

    // The server's device-registration endpoint is WebAuthn-gated (see the
    // note above the API types). We cannot complete a WebAuthn assertion headlessly,
    // so registration is a manual, out-of-band enrolment: print the public key and
    // let the user enrol it via a WebAuthn-capable surface.
    eprintln!();
    eprintln!("  Device keypair ready. To register '{name}', enrol this PUBLIC KEY on the server");
    eprintln!("  via a WebAuthn-capable surface (web admin panel or the Android app):");
    eprintln!();
    eprintln!("    name:       {name}");
    eprintln!("    key_type:   x25519");
    eprintln!("    public_key: {public_key}");
    eprintln!();
    eprintln!("  The private key stays local; only the public key above leaves this machine.");
    eprintln!("  Registration is WebAuthn-gated and requires a signed assertion, which a headless");
    eprintln!("  CLI cannot produce — so this command does NOT contact the server.");
    eprintln!();
    eprintln!("  After the server assigns a device id, save it with:");
    eprintln!("    kv device set-id <device-id>");
    eprintln!();
    Ok(())
}

/// Recommended enrolment path: generate/reuse the local device keypair, propose
/// it to the server, and poll until an admin confirms it via a WebAuthn passkey
/// touch on the web dashboard — then save the assigned `device_id` to config
/// automatically. No manual `device set-id` step needed.
pub async fn propose(client: &mut Client, name: String) -> Result<()> {
    let secret = load_or_create_key()?;
    let public_key = B64.encode(PublicKey::from(&secret).as_bytes());

    let created = client.propose_device(&name, &public_key).await?;

    eprintln!();
    eprintln!("  Device proposal created for '{name}'.");
    eprintln!("  Open this link and confirm with a passkey touch:");
    eprintln!();
    eprintln!("  {}", created.url);
    eprintln!();
    eprintln!("  Expires: {}", created.expires_at);
    eprintln!("  Polling every 5s until confirmed.  Press  Ctrl+C  to cancel.");
    eprintln!();

    // Proposals expire in 30 minutes server-side; give up around the same time
    // rather than polling forever.
    let timeout = Duration::from_secs(30 * 60);
    let start = std::time::Instant::now();
    let mut ticker = interval(Duration::from_secs(5));
    ticker.tick().await; // first tick fires immediately

    loop {
        if start.elapsed() > timeout {
            bail!("timed out waiting for device proposal confirmation (30 min)");
        }
        ticker.tick().await;

        let (status, device_id) = match client
            .poll_propose_status(&created.id, &created.poll_secret)
            .await
        {
            Ok(v) => v,
            Err(_) => {
                eprint!(".");
                continue;
            }
        };

        match status.as_str() {
            "confirmed" => {
                let device_id = device_id.ok_or_else(|| {
                    anyhow::anyhow!("server confirmed the proposal but returned no device_id")
                })?;
                client.cfg.device_id = Some(device_id.clone());
                client.cfg.save()?;
                eprintln!();
                eprintln!("  ✅  Device confirmed and saved: {device_id}");
                return Ok(());
            }
            "rejected" => {
                eprintln!();
                bail!("device proposal was rejected by the admin");
            }
            "expired" => {
                eprintln!();
                bail!("device proposal expired without confirmation");
            }
            // "pending"
            _ => {
                eprint!(".");
            }
        }
    }
}

pub fn set_id(client: &mut Client, id: String) -> Result<()> {
    client.cfg.device_id = Some(id.clone());
    client.cfg.save()?;
    eprintln!("Saved device id {id} to config.");
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

pub async fn unregister(client: &mut Client, id: Option<String>) -> Result<()> {
    let id = match id {
        Some(id) => id,
        None => {
            let resp = client
                .request_bearer(Method::GET, "/api/admin/devices", None::<&()>)
                .await?;
            let body = Client::expect_success(resp).await?;
            let devices: Vec<DeviceRow> =
                serde_json::from_str(&body).context("failed to parse devices list")?;
            if devices.is_empty() {
                anyhow::bail!("no registered devices");
            }
            let lines: Vec<String> = devices
                .iter()
                .map(|d| format!("{:<30}  registered: {}", d.name, d.created_at))
                .collect();
            let selected = crate::fzf::select(&lines, false, "Select device to unregister > ")?;
            let idx = *selected.first().context("fzf returned no selection")?;
            devices
                .get(idx)
                .context("fzf selection index out of range")?
                .id
                .clone()
        }
    };

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
