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

kv device propose <name>   # recommended: generates a keypair, then polls until
                            # an admin confirms it via WebAuthn — no manual copy/paste
kv device register <name>  # legacy: prints the public key for manual out-of-band
                            # enrolment; follow up with `device set-id`
kv device set-id <id>      # (legacy) record the server-assigned device id after
                            # manually enrolling a `device register` public key
kv device list
kv device unregister [id]  # omit id to pick interactively with fzf

kv session check           # exits 0 if valid, 1 if missing/expired (no output)
kv session request [--label <label>] [--duration 7d|30d|90d|365d]

kv status                  # session validity + which device it's bound to

kv provider-key get <entry>            # source an app's provider key from its KV entry
kv provider-key rotate <mgmt_key_id> <provider_key_id> --kv-entry <entry> [--device <name|id>]
                                        # rotate the provisioned key AND republish it into
                                        # its KV entry with no serving gap
```

## Sourcing & rotating an app's OpenRouter key

An application (e.g. SoloForge) does not hold a long-lived OpenRouter key of its
own. Instead an OpenRouter key is *provisioned* from a device-encrypted
management key (`kv mgmt-key keys create …`) and *published* into a named KV
entry that the app reads at runtime. This decouples the app from the provider:
the key can be rotated underneath it without redeploying or re-configuring the
app.

### Naming convention

Publish each app's key under an entry named `<APP>_API_KEY`, upper-snake-case —
for example `SOLO_FORGE_API_KEY`. One entry per app so keys can be rotated and
revoked independently.

### Sourcing (how an app reads its key)

```
kv provider-key get SOLO_FORGE_API_KEY      # or the equivalent: kv get SOLO_FORGE_API_KEY
```

`provider-key get` is a thin, documented wrapper over `kv get`: same access
model (a scoped API key via `kv add-api-token`, or a session token) and the same
secret-display gating. The consuming app should hold a **read-only API key
scoped to just its own entry**.

Note the raw-secret gate (see `SECURITY.md`): `kv get` / `provider-key get`
print a raw value only to an interactive terminal, after a typed confirmation —
a pipe, a redirect, or any captured stdout (e.g. `VAR=$(kv get …)`) is refused.
This is intentional, so there are two sourcing channels:

- **A service / non-interactive consumer** reads the KV HTTP endpoint directly
  with its scoped API key — no CLI, no TTY gate:

  ```
  curl -fsS -H "X-Api-Key: $KV_API_KEY" https://kv.osmosis.page/kv/SOLO_FORGE_API_KEY
  ```

- **A human at a terminal** uses `kv provider-key get SOLO_FORGE_API_KEY` (raw,
  after confirmation) or `--show-3-last-digits-on-agent-true` /
  `--return-md5-on-agent-true` for a non-secret fingerprint that works
  non-interactively.

### Refresh model (how consumers pick up a rotation)

Rotation republishes the new key **in place** under the same entry name, so
consumers pick it up simply by re-reading. Two supported patterns:

- **Re-read on auth failure (recommended):** when the provider returns 401/403,
  re-read the entry (via the HTTP endpoint or `kv provider-key get <entry>`) to
  fetch the freshly-published key and retry once. Because rotation revokes the
  old key only *after* the new one is published, a consumer that re-reads always
  finds a working key.
- **Periodic re-read:** long-running services can re-read the entry on an
  interval (optionally give the entry a sliding TTL via `kv set … --ttl --sliding`).

### Rotation

```
kv provider-key rotate <mgmt_key_id> <provider_key_id> --kv-entry SOLO_FORGE_API_KEY
```

Ordering is deliberately **create → store → publish → revoke-old** so there is
no window in which no valid key exists:

1. Create the replacement key on the provider (old key untouched).
2. Store the new key device-encrypted (recoverable later via `kv mgmt-key keys show`).
3. Write the new value into the KV entry — consumers re-reading now get it.
4. Revoke the old key on the provider, **only after** the new one is published.

The raw key is written into the KV entry and stored encrypted; it is **never
printed to stdout** (there is no reveal flag — the value's delivery channel is
the KV entry). Pass `--show-3-last-digits-on-agent-true` or
`--return-md5-on-agent-true` for a non-secret fingerprint as confirmation. Pass `--device`
one or more times to encrypt the stored copy for specific devices without the
interactive picker — this is what makes rotation runnable non-interactively
(e.g. from a scheduler).

> **Why rotation is a CLI command and not a server-side scheduled task.** The
> management key is device-encrypted and is only ever decrypted **client-side**
> using the local device's private key; `kv_manager` only stores opaque
> envelopes and never sees the plaintext management key. A server-side task
> therefore *cannot* call the OpenRouter provisioning API, so rotation has to
> run where the device key lives — the CLI. Schedule `kv provider-key rotate`
> from cron/systemd on an authorized device to automate it.
