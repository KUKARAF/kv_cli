use anyhow::{bail, Result};
use crate::client::Client;

pub async fn request(client: &mut Client, label: Option<String>, duration: Option<String>) -> Result<()> {
    let hours = duration.as_deref().map(parse_duration_hours).transpose()?;
    client.acquire_session_token(label, hours).await
}

fn parse_duration_hours(s: &str) -> Result<i64> {
    if let Some(d) = s.strip_suffix('d') {
        return Ok(d.parse::<i64>()? * 24);
    }
    if let Some(h) = s.strip_suffix('h') {
        return Ok(h.parse()?);
    }
    bail!("duration must be like 24h or 7d (e.g. 7d, 30d, 90d, 365d)")
}
