# Security

## Agent access to management-key functionality — 2026-09-20

This note documents an incident in which an automated coding agent was able to
reach management-key (`mgmt-key`) functionality through the `kv` CLI using an
already-valid on-device session. It is recorded here for hardening purposes.
Please read it accurately — no secret material was exfiltrated.

### What happened

- An automated coding agent (Claude Code) running as the local user, on a
  workstation that already held a valid `kv` session, was asked to provision an
  OpenRouter provider key for application testing.
- The agent ran `kv mgmt-key list`. This printed management-key **record
  metadata only** — id, provider, label, status, created / last-used
  timestamps, and default limits. One of the records surfaced was an
  `openrouter` provider management key. This is metadata, **not** the secret
  key material.
- The agent ran `kv mgmt-key keys list <mgmt_key_id>`, which returned HTTP 404.
- Later, when explicitly asked to provision a key, the agent ran
  `kv mgmt-key keys create <mgmt_key_id> <label> --limit 1 --limit-reset weekly`.
  It also returned HTTP 404 — see "Provisioning is device-gated" below: the
  current device is not a recipient of the management key, so the CLI could not
  decrypt it and never reached the provider. The agent never passed
  `--dangerously-show-content-on-agent-true` and never ran `kv mgmt-key keys show`.
  **No provider key was provisioned, and no raw management-key or provider-key
  secret was printed or exfiltrated.**

### The access vector (CLI side)

- The workstation holds `~/.config/kv/device.key` plus an unexpired session
  token; `kv status` reported `session: valid` bound to a registered device.
  That standing on-device session grants **any** local process — including an
  autonomous agent — full `mgmt-key` authority with no further human
  interaction.
- `kv mgmt-key keys create <id> <label>` can provision new provider keys, and
  `kv mgmt-key keys show` can reprint a stored key's plaintext. By default the
  CLI detects "agent" invocation and withholds raw values (printing an md5 /
  last-3 characters instead), but `--dangerously-show-content-on-agent-true`
  overrides that behavior.
- The agent-detection is therefore a **soft, self-overridable guard**: an agent
  that chooses to pass the flag could provision and read provider keys. The
  management key itself stays device-encrypted and is only decrypted in-memory
  to call the provider (it is never printed), but it remains **usable** without
  a human in the loop.

### Recommended hardening (CLI side)

1. Make the raw-secret reveal non-overridable by a mere CLI flag. Require an
   interactive confirmation or a second factor for
   `--dangerously-show-content-on-agent-true` and for `mgmt-key keys show`,
   rather than letting a single argument bypass the agent guard.
2. Require an out-of-band human approval (for example via the kv approver app /
   push notification) before the CLI will perform `mgmt-key keys create`,
   `mgmt-key keys show`, or `mgmt-key keys rotate` — do not let a passive
   standing session authorize these.
3. Use short-lived sessions and require re-authentication specifically for
   `mgmt-key` subcommands.
4. Protect `device.key` at rest via an OS keyring or hardware-backed store so
   that filesystem read access alone is not sufficient to act as the device.
5. Emit a clear local audit trail for every `mgmt-key` subcommand invocation.

### Provisioning is device-gated (observed 2026-09-20)

`kv mgmt-key keys create` from this workstation returns HTTP 404. Tracing the
flow: `keys_create` calls `decrypt_management_key()` first, which does
`GET /api/admin/management-keys/{id}/devices/{this_device_id}` to fetch this
device's *envelope* of the management key. The OpenRouter management key is not
encrypted to this device (`thinkpad_cli`), so the envelope fetch 404s and the
command aborts before ever calling the provider. `kv mgmt-key list` still works
because it only reads record metadata, which is not device-scoped.

This is a **good boundary**: a workstation — and any agent running on it — cannot
provision provider keys unless an admin has explicitly encrypted the management
key to that device. To enable provisioning here, an admin holding the key must
re-share it to this device, ideally as an approval-gated operation (kv approver
app), not a silent grant.

### Structure for safe agent-driven provisioning

If an autonomous agent is ever meant to mint and hand a scoped provider key to a
local consumer (e.g. inject an OpenRouter key into an app under test) without
routing the secret through a terminal/transcript, the intended structure is:

1. **Prerequisite, human-gated:** the agent's device must be an explicit,
   approval-granted recipient of the management key (see above). No standing
   session should self-authorize this.
2. **Scope every key:** always pass `--limit <cap> --limit-reset <cadence>` so a
   leaked test key has a bounded blast radius, and use a dated, purpose-specific
   label (e.g. `soloforge-e2e-2026-09-20`).
3. **Never print the secret.** Today the only agent path to the raw value is
   `--dangerously-show-content-on-agent-true`, which writes it to stdout, where
   it lands in logs/transcripts. Add a sink that hands the secret to a consumer
   without a terminal round-trip — e.g. `--write-to-fd <n>` or `--exec '<cmd>'`
   (pipe the plaintext straight into the consuming process's stdin) — so the agent
   orchestrates injection without ever reading the value itself.
4. **Short TTL + revoke-on-done:** the agent revokes the provisioned key
   (`kv mgmt-key keys revoke`) as soon as the task finishes; prefer keys that
   auto-expire.
5. **Audit:** log provision / reveal / revoke server-side and alert on
   agent-pattern (non-interactive) usage.

Until a no-print sink (item 3) exists, treat agent provisioning as unsupported:
a human should provision and inject the key, or run the injection step directly.

### Follow-up

The management key involved (OpenRouter) is being rotated as a precaution,
independent of the fact that no secret was disclosed.
