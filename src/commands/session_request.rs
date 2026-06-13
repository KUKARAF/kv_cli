use anyhow::Result;
use crate::client::Client;

pub async fn request(client: &mut Client, label: Option<String>) -> Result<()> {
    client.acquire_session_token(label).await
}
