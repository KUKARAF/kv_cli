# Security

## Revealing plaintext secrets is interactive-only (enforced)

The `kv` CLI can print plaintext secret material in a few places:

- `kv get <key>` — a stored KV value
- `kv keys create` — a freshly minted service API key (shown once)
- `kv mgmt-key keys create` / `kv mgmt-key keys rotate` — a newly provisioned
  provider key (shown once)
- `kv mgmt-key keys show` — a previously provisioned provider key, decrypted

Management keys themselves are **never** printed by any command path — they are
decrypted in memory only to call a provider and are never written to stdout.

### The guard

Revealing the raw value of any of the secrets above requires a **genuine
interactive human confirmation that a non-interactive or agent invocation
cannot satisfy**:

1. **Both stdin and stdout must be a real terminal** (`std::io::IsTerminal`).
   If either is a pipe, a redirect, or otherwise captured — the exact shape of
   an automated agent's shell tool, whose stdout is collected into the model's
   context — the CLI refuses and exits with an error. The raw secret is never
   written.
2. **A typed confirmation** (`yes`) must then be entered at the terminal before
   the value is printed.

There is **no flag that overrides this**. The previous
`--dangerously-show-content-on-agent-true` flag has been removed: a secret
reveal can no longer be forced by passing an argument.

### Why not agent-detection?

Earlier versions gated secret output on a best-effort "is this an AI agent
running me?" heuristic (environment-variable markers plus parent-process
inspection). That approach is fundamentally unreliable and **failed exactly when
it mattered**: a bash-tool-driven, non-interactive invocation was routinely
misclassified as a human, so the `*-on-agent-true` guards silently no-op'd and
the raw value went to stdout by default. Genuine terminal interactivity is the
only signal a non-interactive caller cannot forge, so the gate now depends on
that alone. The `agent_detect` heuristic has been deleted.

### Safe, non-secret fingerprints (allowed non-interactively)

Two flags remain and are safe to use from scripts/agents because they never
emit the secret itself, only a non-reversible fingerprint of it:

- `--return-md5-on-agent-true` — prints an md5 digest of the value
- `--show-3-last-digits-on-agent-true` — prints only the last 3 characters

These let an automated caller confirm *which* value is present (e.g. that a
rotation changed it) without exposing the plaintext.

### Notes for `create` / `rotate`

`mgmt-key keys create` and `mgmt-key keys rotate` provision the key server-side
before attempting the one-time reveal, and store it encrypted first. If the
reveal is refused (non-interactive session), the operation still succeeded and
the key is recoverable later from an interactive terminal via
`kv mgmt-key keys show <mgmt_key_id> <provisioned_key_id>`. Nothing is lost, and
nothing leaks.

### Residual risk / further hardening

A standing on-device session still grants any local process `mgmt-key`
authority to *provision* and *revoke* keys (the reveal of plaintext is what is
now gated). Defence-in-depth beyond this CLI change — out-of-band approval for
provisioning, short-lived sessions requiring re-auth for `mgmt-key`, protecting
`device.key` in an OS keyring, and server-side audit logging — remains
worthwhile and is tracked separately.
