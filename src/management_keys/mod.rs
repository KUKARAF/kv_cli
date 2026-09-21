pub mod providers;

use anyhow::{bail, Context, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};

use crate::client::Client;
use crate::secret_display::{emit_secret, SecretDisplay};

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DeviceListEntry {
    id: String,
    name: String,
    key_type: String,
    public_key: String,
}

#[derive(Serialize)]
struct DeviceRecipient {
    device_id: String,
    key_type: String,
    ephemeral_pub: String,
    dek_nonce: String,
    encrypted_dek: String,
}

impl From<crate::crypto::DeviceWrap> for DeviceRecipient {
    fn from(w: crate::crypto::DeviceWrap) -> Self {
        Self {
            device_id: w.device_id,
            key_type: w.key_type,
            ephemeral_pub: w.ephemeral_pub,
            dek_nonce: w.dek_nonce,
            encrypted_dek: w.encrypted_dek,
        }
    }
}

#[derive(Serialize)]
struct CreateManagementKeyRequest {
    provider: String,
    label: String,
    nonce: String,
    ciphertext: String,
    aad: String,
    recipients: Vec<DeviceRecipient>,
    default_limit: Option<f64>,
    default_limit_reset: Option<String>,
}

#[derive(Deserialize)]
struct CreateManagementKeyResponse {
    id: String,
}

#[derive(Serialize)]
struct UpdateManagementKeyDefaultsRequest {
    default_limit: Option<f64>,
    default_limit_reset: Option<String>,
}

#[derive(Deserialize, Tabled)]
struct ManagementKeyRow {
    id: String,
    provider: String,
    label: String,
    status: String,
    created_at: String,
    #[tabled(display_with = "opt_str")]
    last_used_at: Option<String>,
    #[tabled(display_with = "opt_f64")]
    default_limit: Option<f64>,
    #[tabled(display_with = "opt_str")]
    default_limit_reset: Option<String>,
}

#[derive(Deserialize)]
struct EnvelopeResponse {
    nonce: String,
    ciphertext: String,
    aad: String,
    recipient: EnvelopeRecipient,
}

#[derive(Deserialize)]
struct EnvelopeRecipient {
    ephemeral_pub: String,
    dek_nonce: String,
    encrypted_dek: String,
}

#[derive(Serialize)]
struct CreateProvisionedKeyRequest {
    provider_key_id: String,
    label: String,
    nonce: String,
    ciphertext: String,
    aad: String,
    recipients: Vec<DeviceRecipient>,
}

#[derive(Deserialize)]
struct CreateProvisionedKeyResponse {
    id: String,
}

#[derive(Deserialize, Tabled)]
struct ProvisionedKeyRow {
    id: String,
    provider_key_id: String,
    label: String,
    status: String,
    created_at: String,
    #[tabled(display_with = "opt_str")]
    revoked_at: Option<String>,
}

fn opt_str(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("-").to_string()
}

fn opt_f64(v: &Option<f64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "-".to_string())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolve devices to encrypt for. `preselected` entries (device name or id) skip the
/// interactive fzf picker — needed for non-TTY / automated invocations (e.g. a scheduled
/// `provider-key rotate`).
async fn select_devices(
    client: &mut Client,
    preselected: &[String],
) -> Result<Vec<(String, String, String)>> {
    let resp = client
        .request_bearer(Method::GET, "/api/admin/devices", None::<&()>)
        .await?;
    let body = Client::expect_success(resp).await?;
    let devices: Vec<DeviceListEntry> =
        serde_json::from_str(&body).context("failed to parse devices response")?;
    if devices.is_empty() {
        bail!("no registered devices — register at least one device first");
    }
    if !preselected.is_empty() {
        return preselected
            .iter()
            .map(|wanted| {
                let d = devices
                    .iter()
                    .find(|d| d.id == *wanted || d.name == *wanted)
                    .ok_or_else(|| anyhow::anyhow!("no registered device named '{wanted}'"))?;
                Ok((d.id.clone(), d.key_type.clone(), d.public_key.clone()))
            })
            .collect::<Result<Vec<_>>>();
    }
    let lines: Vec<String> = devices
        .iter()
        .map(|d| format!("{:<30}  [{}]", d.name, d.key_type))
        .collect();
    let selected = crate::fzf::select(&lines, true, "Encrypt for devices (TAB to toggle) > ")?;
    selected
        .into_iter()
        .map(|i| {
            let d = devices
                .get(i)
                .ok_or_else(|| anyhow::anyhow!("fzf selection index out of range"))?;
            Ok((d.id.clone(), d.key_type.clone(), d.public_key.clone()))
        })
        .collect::<Result<Vec<_>>>()
}

fn local_device_id(client: &Client) -> Result<String> {
    client.cfg.device_id.clone().ok_or_else(|| {
        anyhow::anyhow!("no local device registered; run `kv device register` first")
    })
}

async fn management_key_row(client: &mut Client, mgmt_key_id: &str) -> Result<ManagementKeyRow> {
    let rows = list_management_keys(client).await?;
    rows.into_iter()
        .find(|r| r.id == mgmt_key_id)
        .ok_or_else(|| anyhow::anyhow!("management key {mgmt_key_id} not found"))
}

async fn list_management_keys(client: &mut Client) -> Result<Vec<ManagementKeyRow>> {
    let resp = client
        .request_bearer(Method::GET, "/api/admin/management-keys", None::<&()>)
        .await?;
    let body = Client::expect_success(resp).await?;
    serde_json::from_str(&body).context("failed to parse management keys response")
}

async fn decrypt_management_key(client: &mut Client, mgmt_key_id: &str) -> Result<String> {
    let device_id = local_device_id(client)?;
    let priv_key_b64 = crate::commands::device::load_private_key_b64()?;

    let path = format!("/api/admin/management-keys/{mgmt_key_id}/devices/{device_id}");
    let resp = client
        .request_bearer(Method::GET, &path, None::<&()>)
        .await?;
    let text = Client::expect_success(resp).await?;
    let payload: EnvelopeResponse =
        serde_json::from_str(&text).context("failed to parse envelope response")?;

    let plaintext = crate::crypto::decrypt_device_kv(
        &priv_key_b64,
        &payload.recipient.ephemeral_pub,
        &payload.recipient.dek_nonce,
        &payload.recipient.encrypted_dek,
        &payload.nonce,
        &payload.ciphertext,
        &payload.aad,
    )?;
    String::from_utf8(plaintext).context("management key plaintext was not valid UTF-8")
}

// ── Management key commands ──────────────────────────────────────────────────

pub async fn add(
    client: &mut Client,
    label: String,
    provider: String,
    default_limit: Option<f64>,
    default_limit_reset: Option<String>,
) -> Result<()> {
    providers::provider_for(&provider)?; // validates the provider name early
    validate_limit_reset(&default_limit_reset)?;

    let secret = rpassword::prompt_password(format!("{provider} management key: "))
        .context("failed to read management key")?;
    let secret = secret.trim();
    if secret.is_empty() {
        bail!("management key must not be empty");
    }

    let device_tuples = select_devices(client, &[]).await?;
    let aad = format!("mgmt-key:{label}");
    let payload = crate::crypto::encrypt_for_devices(&aad, secret.as_bytes(), &device_tuples)?;

    let body = CreateManagementKeyRequest {
        provider: provider.clone(),
        label: label.clone(),
        nonce: payload.nonce,
        ciphertext: payload.ciphertext,
        aad: payload.aad,
        recipients: payload.recipients.into_iter().map(Into::into).collect(),
        default_limit,
        default_limit_reset,
    };

    let resp = client
        .request_bearer(Method::POST, "/api/admin/management-keys", Some(&body))
        .await?;
    let text = Client::expect_success(resp).await?;
    let created: CreateManagementKeyResponse =
        serde_json::from_str(&text).context("failed to parse response")?;
    eprintln!("Stored management key '{label}' (id: {})", created.id);
    Ok(())
}

fn validate_limit_reset(value: &Option<String>) -> Result<()> {
    match value.as_deref() {
        None | Some("daily") | Some("weekly") | Some("monthly") => Ok(()),
        Some(other) => bail!("invalid limit-reset '{other}': expected daily, weekly, or monthly"),
    }
}

/// Sets default_limit/default_limit_reset for a management key. Each `Some` overrides that
/// field; `None` leaves it as currently stored (fetches the existing row first, since the
/// server PATCH endpoint replaces both fields unconditionally).
pub async fn set_defaults(
    client: &mut Client,
    id: &str,
    default_limit: Option<f64>,
    clear_limit: bool,
    default_limit_reset: Option<String>,
    clear_limit_reset: bool,
) -> Result<()> {
    validate_limit_reset(&default_limit_reset)?;
    let current = management_key_row(client, id).await?;

    let body = UpdateManagementKeyDefaultsRequest {
        default_limit: if clear_limit {
            None
        } else {
            default_limit.or(current.default_limit)
        },
        default_limit_reset: if clear_limit_reset {
            None
        } else {
            default_limit_reset.or(current.default_limit_reset)
        },
    };

    let path = format!("/api/admin/management-keys/{id}");
    let resp = client
        .request_bearer(Method::PATCH, &path, Some(&body))
        .await?;
    Client::expect_success(resp).await?;
    eprintln!("Updated defaults for management key {id}");
    Ok(())
}

pub async fn list(client: &mut Client) -> Result<()> {
    let rows = list_management_keys(client).await?;
    if rows.is_empty() {
        eprintln!("(no management keys)");
    } else {
        println!("{}", Table::new(&rows));
    }
    Ok(())
}

pub async fn revoke(client: &mut Client, id: &str) -> Result<()> {
    let path = format!("/api/admin/management-keys/{id}/revoke");
    let resp = client
        .request_bearer(Method::POST, &path, None::<&()>)
        .await?;
    Client::expect_success(resp).await?;
    eprintln!("Revoked management key {id}");
    Ok(())
}

// ── Provisioned key commands ─────────────────────────────────────────────────

pub async fn keys_list(client: &mut Client, mgmt_key_id: &str) -> Result<()> {
    let mgmt_key = decrypt_management_key(client, mgmt_key_id).await?;
    let row = management_key_row(client, mgmt_key_id).await?;
    let provider = providers::provider_for(&row.provider)?;
    let live = provider.list_keys(&mgmt_key).await?;

    if live.is_empty() {
        eprintln!("(no keys on {})", provider.id());
        return Ok(());
    }
    for k in live {
        let flag = if k.disabled { "  [disabled]" } else { "" };
        println!("{:<24}  {}{}", k.provider_key_id, k.label, flag);
    }
    Ok(())
}

pub async fn keys_create(
    client: &mut Client,
    mgmt_key_id: &str,
    label: &str,
    limit: Option<f64>,
    limit_reset: Option<String>,
    mode: SecretDisplay,
) -> Result<()> {
    validate_limit_reset(&limit_reset)?;
    let mgmt_key = decrypt_management_key(client, mgmt_key_id).await?;
    let row = management_key_row(client, mgmt_key_id).await?;
    let provider = providers::provider_for(&row.provider)?;
    // CLI flags override the management key's stored defaults when given.
    let limit = limit.or(row.default_limit);
    let limit_reset = limit_reset.or(row.default_limit_reset);
    let created = provider
        .create_key(&mgmt_key, label, limit, limit_reset.as_deref())
        .await?;

    let stored_id = store_provisioned_key(client, mgmt_key_id, &created, &[]).await?;

    eprintln!();
    eprintln!(
        "Created {} key '{}' (provider id: {})",
        provider.id(),
        created.label,
        created.provider_key_id
    );
    eprintln!(
        "Stored encrypted as {stored_id} — retrievable later with \
         `kv mgmt-key keys show {mgmt_key_id} {stored_id}`."
    );
    emit_secret(
        "a newly provisioned provider key (shown once)",
        &created.plaintext_secret,
        mode,
    )?;
    Ok(())
}

/// Encrypts a newly-created provider key for a freshly-selected set of devices and stores
/// it. Shared by `keys_create` and `keys_rotate`. Returns our local record id.
async fn store_provisioned_key(
    client: &mut Client,
    mgmt_key_id: &str,
    created: &providers::ProviderKeyCreated,
    devices: &[String],
) -> Result<String> {
    let device_tuples = select_devices(client, devices).await?;
    let aad = format!("provisioned-key:{}", created.provider_key_id);
    let payload = crate::crypto::encrypt_for_devices(
        &aad,
        created.plaintext_secret.as_bytes(),
        &device_tuples,
    )?;

    let body = CreateProvisionedKeyRequest {
        provider_key_id: created.provider_key_id.clone(),
        label: created.label.clone(),
        nonce: payload.nonce,
        ciphertext: payload.ciphertext,
        aad: payload.aad,
        recipients: payload.recipients.into_iter().map(Into::into).collect(),
    };

    let path = format!("/api/admin/management-keys/{mgmt_key_id}/provisioned-keys");
    let resp = client
        .request_bearer(Method::POST, &path, Some(&body))
        .await?;
    let text = Client::expect_success(resp).await?;
    let created_row: CreateProvisionedKeyResponse =
        serde_json::from_str(&text).context("failed to parse response")?;
    Ok(created_row.id)
}

/// Best-effort: delete our local record for `provider_key_id` if one exists. Returns whether
/// a matching record was found (and its deletion attempted) — callers decide how to report
/// a deletion failure since the severity differs (revoke: non-fatal; rotate: also non-fatal,
/// but the caller may want different wording).
async fn delete_local_provisioned_key(
    client: &mut Client,
    mgmt_key_id: &str,
    provider_key_id: &str,
) -> Result<bool> {
    let path = format!("/api/admin/management-keys/{mgmt_key_id}/provisioned-keys");
    let resp = client
        .request_bearer(Method::GET, &path, None::<&()>)
        .await?;
    let body = Client::expect_success(resp).await?;
    let rows: Vec<ProvisionedKeyRow> =
        serde_json::from_str(&body).context("failed to parse response")?;
    let Some(row) = rows.iter().find(|r| r.provider_key_id == provider_key_id) else {
        return Ok(false);
    };
    let delete_path = format!(
        "/api/admin/management-keys/{mgmt_key_id}/provisioned-keys/{}",
        row.id
    );
    let del_resp = client
        .request_bearer(Method::DELETE, &delete_path, None::<&()>)
        .await?;
    Client::expect_success(del_resp).await?;
    Ok(true)
}

pub async fn keys_revoke(
    client: &mut Client,
    mgmt_key_id: &str,
    provider_key_id: &str,
) -> Result<()> {
    let mgmt_key = decrypt_management_key(client, mgmt_key_id).await?;
    let row = management_key_row(client, mgmt_key_id).await?;
    let provider = providers::provider_for(&row.provider)?;
    provider.revoke_key(&mgmt_key, provider_key_id).await?;

    // Provider-side delete succeeded — clean up our local record if we have one. Must not
    // fail silently: if we DO have a stored copy but can't delete it, that's a real
    // inconsistency (a now-invalid secret left recoverable via SHOW) the user needs to know.
    delete_local_provisioned_key(client, mgmt_key_id, provider_key_id)
        .await
        .context("revoked on provider but failed to delete local record")?;

    eprintln!("Revoked {provider_key_id} on {}", provider.id());
    Ok(())
}

pub async fn keys_rotate(
    client: &mut Client,
    mgmt_key_id: &str,
    provider_key_id: &str,
    mode: SecretDisplay,
) -> Result<()> {
    let mgmt_key = decrypt_management_key(client, mgmt_key_id).await?;
    let row = management_key_row(client, mgmt_key_id).await?;
    let provider = providers::provider_for(&row.provider)?;

    // Read the key's *current* limit/limit_reset from the provider itself — not our stored
    // defaults, which may be stale or never matched this specific key.
    let info = provider.get_key(&mgmt_key, provider_key_id).await.context(
        "failed to fetch current key info from provider — aborting rotation, nothing was changed",
    )?;

    // Delete old, then create new (in that order): there's a brief window with zero active
    // keys. If create-new then fails, that's the accepted risk of this ordering, so it must
    // fail loudly (see below) rather than leaving the user thinking nothing happened.
    provider
        .revoke_key(&mgmt_key, provider_key_id)
        .await
        .context("failed to delete old key on provider — aborting rotation, nothing was changed")?;

    // Best-effort: local cleanup of the old record is non-fatal here — the user still needs
    // the replacement key regardless of whether our bookkeeping for the old one succeeds.
    if let Err(e) = delete_local_provisioned_key(client, mgmt_key_id, provider_key_id).await {
        eprintln!("warning: deleted old key on provider, but failed to remove local record: {e:#}");
    }

    let created = provider
        .create_key(
            &mgmt_key,
            &info.label,
            info.limit,
            info.limit_reset.as_deref(),
        )
        .await
        .context(
            "CRITICAL: the old key was already deleted on the provider, but creating its \
             replacement failed — you now have NO active key for this identity. Retry manually.",
        )?;

    let stored_id = store_provisioned_key(client, mgmt_key_id, &created, &[]).await?;

    eprintln!();
    eprintln!(
        "Rotated {} key '{}' (new provider id: {})",
        provider.id(),
        created.label,
        created.provider_key_id
    );
    eprintln!(
        "Stored encrypted as {stored_id} — retrievable later with \
         `kv mgmt-key keys show {mgmt_key_id} {stored_id}`."
    );
    emit_secret(
        "the rotated provider key (shown once)",
        &created.plaintext_secret,
        mode,
    )?;
    Ok(())
}

/// Rotate a provisioned provider key AND republish it into the KV entry `kv_entry` that
/// consumer apps source (e.g. `SOLO_FORGE_API_KEY`), with no serving gap.
///
/// Ordering is deliberately **create → store → publish → revoke-old** (not the
/// delete-then-create of `keys_rotate`): the old key stays valid until the new value has
/// been written to the KV entry, so a consumer that reads at any instant always gets a
/// working key. The old key is revoked only *after* the new one is stored and published.
///
/// The raw new key is never written to stdout by default — it is written into the KV entry
/// (server-side) and stored device-encrypted. `mode` only controls an optional
/// non-sensitive confirmation (md5 / last-3), matching the no-print-sink direction in
/// SECURITY.md.
pub async fn rotate_into_kv(
    client: &mut Client,
    mgmt_key_id: &str,
    provider_key_id: &str,
    kv_entry: &str,
    devices: &[String],
    mode: SecretDisplay,
) -> Result<()> {
    let mgmt_key = decrypt_management_key(client, mgmt_key_id).await?;
    let row = management_key_row(client, mgmt_key_id).await?;
    let provider = providers::provider_for(&row.provider)?;

    // Read the key's *current* limit/limit_reset from the provider so the replacement keeps
    // the same identity/label/limit — not our stored defaults, which may be stale.
    let info = provider.get_key(&mgmt_key, provider_key_id).await.context(
        "failed to fetch current key info from provider — aborting rotation, nothing was changed",
    )?;

    // 1. Create the replacement FIRST. If this fails the old key is untouched and still
    //    serving, so it's safe to abort loudly.
    let created = provider
        .create_key(
            &mgmt_key,
            &info.label,
            info.limit,
            info.limit_reset.as_deref(),
        )
        .await
        .context(
            "failed to create the replacement key on the provider — aborting rotation, \
             nothing was changed (the old key is still active)",
        )?;

    // 2. Store the new key device-encrypted BEFORE publishing, so it is recoverable via
    //    `kv mgmt-key keys show` even if a later step fails.
    let stored_id = store_provisioned_key(client, mgmt_key_id, &created, devices)
        .await
        .context(
            "created the replacement key on the provider but failed to store it encrypted — \
             the old key is still active; if you are not keeping the new key, revoke it \
             manually on the provider",
        )?;

    // 3. Publish the new value into the KV entry. Consumers re-reading this entry now pick up
    //    the new key. The old key is still valid, so an in-flight consumer is never stranded.
    crate::commands::kv::set(
        client,
        kv_entry,
        created.plaintext_secret.clone(),
        None,
        false,
        false,
        false,
    )
    .await
    .context(
        "stored the new key but failed to write it to the KV entry — the old key was NOT \
         revoked and consumers still use it. Retry, or publish manually.",
    )?;

    // 4. Only now revoke the OLD key on the provider — the new value is already published.
    //    A failure here is non-fatal (the new key is live and in the KV entry); we just warn
    //    so the operator can clean up the lingering old key.
    match provider.revoke_key(&mgmt_key, provider_key_id).await {
        Ok(()) => {
            if let Err(e) = delete_local_provisioned_key(client, mgmt_key_id, provider_key_id).await
            {
                eprintln!(
                    "warning: revoked the old key on the provider but failed to remove its \
                     local record: {e:#}"
                );
            }
        }
        Err(e) => {
            eprintln!(
                "warning: published the new key to '{kv_entry}' but failed to revoke the old \
                 provider key {provider_key_id}: {e:#}"
            );
            eprintln!(
                "         it is still valid on the provider — revoke it manually with \
                 `kv mgmt-key keys revoke {mgmt_key_id} {provider_key_id}`"
            );
        }
    }

    eprintln!();
    eprintln!(
        "Rotated {} key '{}' into KV entry '{}' (new provider id: {}, stored as {})",
        provider.id(),
        created.label,
        kv_entry,
        created.provider_key_id,
        stored_id
    );
    confirm_published_key(&created.plaintext_secret, mode);
    Ok(())
}

/// Prints an optional, non-sensitive confirmation for a key that was just written into a KV
/// entry. The raw value is *never* printed here — it already lives in the KV entry, so stdout
/// is not the delivery channel — only a derived, non-reversible fingerprint (md5 / last-3) on
/// request. Never fails the command.
fn confirm_published_key(secret: &str, mode: SecretDisplay) {
    if mode.md5 {
        use md5::{Digest, Md5};
        println!("{:x}", Md5::digest(secret.as_bytes()));
    } else if mode.last3 {
        let tail: String = {
            let mut chars: Vec<char> = secret.chars().rev().take(3).collect();
            chars.reverse();
            chars.into_iter().collect()
        };
        println!("...{tail}");
    } else {
        eprintln!("The new key value was written to the KV entry; it is not printed here.");
    }
}

pub async fn keys_show(
    client: &mut Client,
    mgmt_key_id: &str,
    provisioned_key_id: &str,
    mode: SecretDisplay,
) -> Result<()> {
    let device_id = local_device_id(client)?;
    let priv_key_b64 = crate::commands::device::load_private_key_b64()?;

    let path = format!(
        "/api/admin/management-keys/{}/provisioned-keys/{}/devices/{}",
        crate::urlencode::urlencode(mgmt_key_id),
        crate::urlencode::urlencode(provisioned_key_id),
        crate::urlencode::urlencode(&device_id),
    );
    let resp = client
        .request_bearer(Method::GET, &path, None::<&()>)
        .await?;
    let text = Client::expect_success(resp).await?;
    let payload: EnvelopeResponse =
        serde_json::from_str(&text).context("failed to parse envelope response")?;

    let plaintext = crate::crypto::decrypt_device_kv(
        &priv_key_b64,
        &payload.recipient.ephemeral_pub,
        &payload.recipient.dek_nonce,
        &payload.recipient.encrypted_dek,
        &payload.nonce,
        &payload.ciphertext,
        &payload.aad,
    )?;
    emit_secret(
        &format!("provisioned provider key {provisioned_key_id}"),
        &String::from_utf8_lossy(&plaintext),
        mode,
    )?;
    Ok(())
}
