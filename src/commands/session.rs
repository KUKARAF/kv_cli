use crate::client::Client;

/// Returns true if the current session token is valid, false otherwise.
/// Never prompts interactively — safe to call from scripts.
pub async fn check(client: &Client) -> bool {
    client.is_session_valid().await
}
