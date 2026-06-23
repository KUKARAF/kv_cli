# kv

CLI for [kv.osmosis.page](https://kv.osmosis.page).

## Prerequisites

- [`fzf`](https://github.com/junegunn/fzf) — required for interactive device selection (`kv set --device`, `kv device unregister`)

## Usage

```
kv get <key>
kv set <key> <value> [--device] [--scope <scope>] [--ttl <hours>] [--open]
kv list [--prefix <prefix>]
kv delete <key>

kv device register <name>
kv device list
kv device unregister [id]   # omit id to pick interactively with fzf

kv keys list
kv keys create <label> [--type standard|one_time|approval_required] [--scope <pattern:perms>]
kv keys revoke <id>

kv session check
kv session request [--label <label>] [--duration <e.g. 7d>]
kv add-api-token [token]
```
