# kv

CLI for [kv.osmosis.page](https://kv.osmosis.page).

## Prerequisites

- [`fzf`](https://github.com/junegunn/fzf) — required for interactive key/device selection

## Global options

| Flag | Env | Description |
|------|-----|-------------|
| `--base-url <URL>` | `KV_BASE_URL` | Override the server base URL |
| `--silent` | | Fail instead of prompting for a session token |

## Commands

```
kv get [key]               # omit key to pick interactively with fzf
    --token <TOKEN>        # API key for approval-required / one-time links

kv set <key> <value>
    --scope <scope>        # restrict to scope (uses admin endpoint)
    --ttl <hours>          # expiry in hours
    --sliding              # reset TTL on each read
    --open                 # allow unauthenticated read access
    --device               # encrypt for devices (fzf multi-select)

kv list [--prefix <prefix>]

kv delete [key]            # omit key to pick interactively with fzf

kv add-api-token [token]   # store an API key (prompted securely if omitted)

kv keys list
kv keys create <label> [--type standard|one_time|approval_required] [--scope <pattern:perms>]
kv keys revoke <id>

kv device register <name>
kv device list
kv device unregister [id]  # omit id to pick interactively with fzf

kv session check           # exits 0 if valid, 1 if missing/expired (no output)
kv session request [--label <label>] [--duration 7d|30d|90d|365d]
```
