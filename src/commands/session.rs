use crate::client::Client;
use anyhow::{bail, Result};

/// Returns true if the current session token is valid, false otherwise.
/// Never prompts interactively — safe to call from scripts.
pub async fn check(client: &mut Client) -> bool {
    client.is_session_valid().await
}

/// `kv status` — print whether the current session token is valid and, if so,
/// which device (if any) it's bound to.
pub async fn status(client: &mut Client) -> Result<()> {
    if !client.is_session_valid().await {
        println!("session: invalid or missing");
        bail!("no valid session token — run `kv session request`");
    }
    println!("session: valid");

    let who = client.whoami().await?;
    match (who.device_id, who.device_name) {
        (Some(id), Some(name)) => println!("device: {name} ({id})"),
        _ => println!("device: no device bound"),
    }
    Ok(())
}
