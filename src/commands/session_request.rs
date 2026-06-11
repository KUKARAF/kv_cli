use anyhow::{bail, Result};
use qrcode::{render::unicode, QrCode};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::interval;

use crate::client::Client;

#[derive(Serialize)]
struct CreateBody {
    label: Option<String>,
}

#[derive(Deserialize)]
struct CreateResponse {
    id: String,
    url: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct StatusResponse {
    status: String,
    session_token: Option<String>,
}

pub async fn request(client: &mut Client, label: Option<String>) -> Result<()> {
    let body = CreateBody { label };
    let url = format!("{}/api/session-request/", client.base_url);
    let resp = client
        .http_post_unauthenticated(&url, &body)
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        bail!("server returned {status}: {text}");
    }

    let created: CreateResponse = resp.json().await?;

    eprintln!();
    eprintln!("  Approval URL:");
    eprintln!("  {}", created.url);
    eprintln!("  Expires: {}", created.expires_at);
    eprintln!();

    print_qr(&created.url);

    eprintln!("  Open the URL or scan the QR code to approve.");
    eprintln!("  Polling every 5s.  Press  q ↵  to cancel.");
    eprintln!();

    // Spawn stdin reader
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
    ticker.tick().await; // discard immediate first tick

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let resp = client
                    .send_unauthenticated(Method::GET, &status_path)
                    .await?;
                let status_code = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();

                if status_code == 404 {
                    bail!("request not found (expired?)");
                }
                if status_code != 200 {
                    eprint!(".");
                    continue;
                }

                let status: StatusResponse = match serde_json::from_str(&body) {
                    Ok(s) => s,
                    Err(_) => { eprint!("."); continue; }
                };

                match status.status.as_str() {
                    "approved" => {
                        let token = status.session_token
                            .ok_or_else(|| anyhow::anyhow!("server approved but returned no token"))?;
                        client.cfg.session_token = Some(token);
                        client.cfg.save()?;
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
