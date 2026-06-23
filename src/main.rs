mod client;
mod commands;
mod config;
mod crypto;
mod fzf;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use client::Client;
use config::Config;

#[derive(Parser)]
#[command(name = "kv", about = "CLI for kv_manager", version = env!("APP_VERSION"))]
struct Cli {
    /// Override base URL (or set KV_BASE_URL env var)
    #[arg(long, global = true, env = "KV_BASE_URL")]
    base_url: Option<String>,

    /// Do not prompt for a session token (fail instead of escalating)
    #[arg(long, global = true)]
    silent: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Get a value by key (launches fzf picker if no key given)
    Get {
        key: Option<String>,
        /// API key token for approval-required or one-time share links
        #[arg(long)]
        token: Option<String>,
    },
    /// Set a value
    Set {
        key: String,
        value: String,
        /// Restrict to this scope (uses admin endpoint)
        #[arg(long)]
        scope: Option<String>,
        /// TTL in hours
        #[arg(long)]
        ttl: Option<f64>,
        /// Use sliding TTL
        #[arg(long)]
        sliding: bool,
        /// Allow open (unauthenticated) read access
        #[arg(long)]
        open: bool,
        /// Encrypt for selected registered devices (fzf multi-select)
        #[arg(long)]
        device: bool,
    },
    /// List KV entries
    List {
        /// Filter by prefix
        #[arg(long)]
        prefix: Option<String>,
    },
    /// Delete a key (launches fzf picker if no key given)
    Delete {
        key: Option<String>,
    },
    /// Store an API key in local config
    AddApiToken {
        /// The API key to store (prompted securely if omitted)
        token: Option<String>,
    },
    /// Manage API keys
    #[command(subcommand)]
    Keys(KeysCmd),
    /// Session management
    #[command(subcommand)]
    Session(SessionCmd),
    /// Manage device registration
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Write the man page to stdout
    #[command(hide = true)]
    GenerateManPage,
}

#[derive(Subcommand)]
enum KeysCmd {
    /// List all API keys
    #[command(name = "list")]
    List,
    /// Create a new API key
    Create {
        label: String,
        /// Key type: standard, one_time, approval_required
        #[arg(long, default_value = "standard")]
        r#type: String,
        /// Scope rules, repeatable: "pattern:read,write"
        #[arg(long = "scope", value_name = "SCOPE")]
        scopes: Vec<String>,
    },
    /// Revoke an API key by ID
    Revoke {
        id: String,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Register this CLI as a device (generates key pair if needed)
    Register {
        /// Device name (e.g. "work-laptop")
        name: String,
    },
    /// List all registered devices
    List,
    /// Unregister a device (launches fzf picker if no ID given)
    Unregister {
        id: Option<String>,
    },
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Check if the current session token is valid.
    /// Exits 0 if valid, 1 if expired or missing. No output — safe for scripting.
    Check,
    /// Request a session token via admin approval (shows URL + QR code, polls until approved)
    Request {
        /// Optional label shown to the approving admin
        #[arg(long)]
        label: Option<String>,
        /// Requested session duration, e.g. 24h, 7d, 30d, 90d, 365d. Admin can override.
        #[arg(long)]
        duration: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    if matches!(cli.command, Cmd::GenerateManPage) {
        let cmd = Cli::command();
        let man = clap_mangen::Man::new(cmd);
        man.render(&mut std::io::stdout())?;
        return Ok(());
    }

    let cfg = Config::load()?;
    let mut client = Client::new(cfg, cli.base_url, cli.silent);

    match cli.command {
        Cmd::Get { key, token } => {
            let key = match key {
                Some(k) => k,
                None => commands::kv::pick_key(&mut client).await?,
            };
            commands::kv::get(&mut client, &key, token).await?;
        }
        Cmd::Set { key, value, scope, ttl, sliding, open, device } => {
            commands::kv::set(&mut client, &key, value, scope, ttl, sliding, open, device).await?;
        }
        Cmd::List { prefix } => {
            commands::kv::list(&mut client, prefix).await?;
        }
        Cmd::Delete { key } => {
            let key = match key {
                Some(k) => k,
                None => commands::kv::pick_key(&mut client).await?,
            };
            commands::kv::delete(&mut client, &key).await?;
        }
        Cmd::AddApiToken { token } => {
            let key = match token {
                Some(t) => t,
                None => rpassword::prompt_password("API key: ")
                    .context("failed to read API key")?,
            };
            client.cfg.api_key = Some(key.trim().to_string());
            client.cfg.save()?;
            eprintln!("API key saved to config.");
        }
        Cmd::Keys(keys_cmd) => match keys_cmd {
            KeysCmd::List => {
                commands::keys::list(&mut client).await?;
            }
            KeysCmd::Create { label, r#type, scopes } => {
                commands::keys::create(&mut client, label, r#type, scopes).await?;
            }
            KeysCmd::Revoke { id } => {
                commands::keys::revoke(&mut client, &id).await?;
            }
        },
        Cmd::Session(session_cmd) => match session_cmd {
            SessionCmd::Check => {
                if !commands::session::check(&mut client).await {
                    std::process::exit(1);
                }
            }
            SessionCmd::Request { label, duration } => {
                commands::session_request::request(&mut client, label, duration).await?;
            }
        },
        Cmd::Device(device_cmd) => match device_cmd {
            DeviceCmd::Register { name } => {
                commands::device::register(&mut client, name).await?;
            }
            DeviceCmd::List => {
                commands::device::list(&mut client).await?;
            }
            DeviceCmd::Unregister { id } => {
                commands::device::unregister(&mut client, id).await?;
            }
        },
        Cmd::GenerateManPage => unreachable!(),
    }

    Ok(())
}
