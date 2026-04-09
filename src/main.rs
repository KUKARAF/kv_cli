mod client;
mod commands;
mod config;

use anyhow::Result;
use clap::{Parser, Subcommand};

use client::Client;
use config::Config;

#[derive(Parser)]
#[command(name = "kv", about = "CLI for kv_manager", version = env!("APP_VERSION"))]
struct Cli {
    /// Override base URL (or set KV_BASE_URL env var)
    #[arg(long, global = true, env = "KV_BASE_URL")]
    base_url: Option<String>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Get a value by key
    Get {
        key: String,
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
    },
    /// List KV entries
    List {
        /// Filter by prefix
        #[arg(long)]
        prefix: Option<String>,
    },
    /// Delete a key
    Delete {
        key: String,
    },
    /// Manage API keys
    #[command(subcommand)]
    Keys(KeysCmd),
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

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load()?;
    let mut client = Client::new(cfg, cli.base_url);

    match cli.command {
        Cmd::Get { key } => {
            commands::kv::get(&mut client, &key).await?;
        }
        Cmd::Set { key, value, scope, ttl, sliding, open } => {
            commands::kv::set(&mut client, &key, value, scope, ttl, sliding, open).await?;
        }
        Cmd::List { prefix } => {
            commands::kv::list(&mut client, prefix).await?;
        }
        Cmd::Delete { key } => {
            commands::kv::delete(&mut client, &key).await?;
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
    }

    Ok(())
}
