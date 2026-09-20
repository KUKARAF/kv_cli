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
- The agent did **not** run `kv mgmt-key keys create`, `kv mgmt-key keys show`,
  nor did it pass `--dangerously-show-content-on-agent-true`. **No provider key
  was provisioned, and no raw management-key or provider-key secret was printed
  or exfiltrated.**

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

### Follow-up

The management key involved (OpenRouter) is being rotated as a precaution,
independent of the fact that no secret was disclosed.
