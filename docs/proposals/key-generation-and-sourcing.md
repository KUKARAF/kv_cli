# Key Generation & Sourcing — Design Proposal

**Status:** Draft / proposal
**Scope:** How a provider API key (e.g. an OpenRouter key) — and more generally any
KV-stored app secret — is generated/obtained and made available to an app or an
automated agent in the `kv.osmosis.page` system.
**Audience:** `kv_manager` (server), `kv_cli` (CLI), `kv_apk` (approver) maintainers.

This is a design proposal, not an implementation. It builds on what already exists in
the four repos and calls out precisely what must be *built* vs. what already *works*.

---

## 0. Background & threat model

The system already implements a strong core primitive: **management keys are
device-encrypted**. A management key (the long-lived provider credential that can mint
scoped sub-keys, e.g. an OpenRouter *provisioning* key) is stored server-side only as
ciphertext plus a set of per-device DEK wraps. The server never holds the plaintext.

Concretely, the mint flow today is:

1. CLI fetches this device's *envelope*:
   `GET /api/admin/management-keys/{id}/devices/{device_id}`
   (`kv_manager` `management_keys/handlers.rs::get_management_key_envelope`).
2. CLI decrypts it locally with `~/.config/kv/device.key`
   (`kv_cli` `management_keys/mod.rs::decrypt_management_key` →
   `crypto::decrypt_device_kv`).
3. CLI calls the provider directly — `POST https://openrouter.ai/api/v1/keys` — with the
   decrypted management key as a bearer token
   (`management_keys/providers/openrouter.rs::create_key`). **The plaintext management
   key never leaves the workstation and never transits `kv_manager`.**
4. CLI re-encrypts the freshly minted provider key to a chosen set of device recipients
   and stores the ciphertext server-side:
   `POST /api/admin/management-keys/{id}/provisioned-keys`
   (`store_provisioned_key`).

The critical existing boundary: **provisioning from a device 404s unless that device is
an authorized recipient of the management key.** `get_management_key_envelope` only
returns a recipient row for a `(management_key_id, device_id)` pair that exists in
`management_key_recipients`; a non-recipient device gets `AppError::NotFound`, so
`decrypt_management_key` aborts before the provider is ever contacted. This is documented
and confirmed in both `SECURITY.md` files (the 2026-09-20 incident: `mgmt-key keys create`
from `thinkpad_cli` returned 404 because that device was not a recipient).

**The gap this proposal addresses.** Two `SECURITY.md` notes record that a *standing
on-device session* currently authorizes the entire `mgmt-key` surface with no
human-in-the-loop, and that the only agent path to a raw secret today —
`--dangerously-show-content-on-agent-true` — writes plaintext to stdout, i.e. straight
into a terminal/transcript/model context. The agent-detection guard
(`agent_detect.rs`) is explicitly "a UX nudge, not a security control" and is
self-overridable. So the two things missing for *safe* generation-and-sourcing are:

- **(A) a proper authorization step** for privileged `mgmt-key` operations (device must
  be a recipient — good — *plus* a fresh human approval, not just a passive session), and
- **(B) a no-print sink** so a secret can be delivered to a consumer without ever being
  rendered to a terminal.

Everything below is organized around closing those two gaps while reusing the machinery
that already exists (device encryption, the approver app, the session-request approval
flow).

---

## 1. Device authorization flow

*How a new device/workstation (or an agent's device) becomes an approved recipient of a
management key — and why standing sessions must not self-authorize.*

### 1.1 Registering the device identity (exists)

Every workstation or agent host has an X25519 device keypair at
`~/.config/kv/device.key` (0600), generated locally; only the public key leaves the
machine (`kv_cli` `commands/device.rs`). Enrolment is **WebAuthn-gated on the server** and
two-step (`devices/handlers.rs::register_begin` / `register_finish`) — a headless CLI
cannot forge the assertion, so a human confirms the enrolment on a WebAuthn-capable
surface (web admin or `kv_apk`). The ergonomic path is `kv device propose <name>`:

```
POST /api/devices/propose               -> {id, url, expires_at, poll_secret}
GET  /api/devices/propose/{id}/status   -> {status, device_id?}
```

The device polls while a human confirms the proposal via WebAuthn on the dashboard/app
(`devices/handlers.rs::propose` / `poll_proposal_status` / `link_proposal`). This gives us
a *registered device identity*, but **registration alone grants nothing** — a registered
device still 404s on every management key it is not an explicit recipient of.

### 1.2 Authorizing the device as a management-key recipient (the real gate)

Being a recipient of a specific management key is a **separate, deliberate act** by an
admin who already holds that key on one of their devices. Mechanically it is a *re-share*:
the admin's device decrypts the management key locally, then re-encrypts the DEK to the
new device's public key and appends a recipient row.

Today the recipient set is chosen once, at `kv mgmt-key add` time, via the interactive
device picker (`select_devices` → fzf), and there is **no CLI command to add a recipient
to an existing management key**. That is the first thing to build.

**Proposed: `kv mgmt-key grant <mgmt_key_id> <device>` (approval-gated).**

1. Admin's device decrypts the management key locally (it is already a recipient).
2. CLI fetches the target device's public key from `GET /api/admin/devices`.
3. CLI wraps the management key's DEK to that public key
   (`crypto::encrypt_for_devices`, reusing the exact `DeviceRecipient` shape already
   used by `mgmt-key add`).
4. CLI submits the new recipient row to a **new** server endpoint,
   `POST /api/admin/management-keys/{id}/recipients`, which **must require an out-of-band
   human approval** (see 1.3) before it is persisted into `management_key_recipients`.

**Why standing sessions must not self-authorize.** The 2026-09-20 incident is the whole
argument: a valid session + `device.key` on disk is *ambient authority* — any local
process, including an autonomous agent, inherits it. If becoming/among a management key's
recipients (or minting from it) required nothing beyond that ambient session, then
compromising one workstation, or an over-eager agent on it, silently escalates to
"can provision provider credentials." Recipient-grant is exactly the escalation step, so
it is the one that must demand a fresh, explicit, human decision — not a passive token
that happens to still be valid. Device-key possession is treated as *necessary but not
sufficient* for the most privileged operations (per `kv_manager/SECURITY.md` rec. #5).

### 1.3 The approval channel (reuse `session_request`)

The server already has a human-in-the-loop approval primitive built for exactly this
shape of problem: the **session-request** flow (`session_request/handlers.rs`), used by
`kv_apk`. Its properties are the ones we want:

- The requester generates an `approve_token` that is **never exposed to the admin UI** —
  the approver must possess the token (from the QR/emoji channel), so "click notification,
  click approve" alone is insufficient (`session_request/handlers.rs::approve`, the
  `hash_key(&body.token) != approve_token_hash` check).
- Only the device's *owner* may approve (`owner_id` match).
- Requests are short-lived (`expires_at`) and atomically consumed.

**Proposal:** generalize this into an **approval grant** the server can require for
privileged `mgmt-key` operations. A grant request carries: `{operation, mgmt_key_id,
target_device_id?, requesting_device_id, label}`; the admin approves it on `kv_apk`
(the operation, the target device name, and the scope are shown on the approval screen);
approval yields a **short-lived, single-operation elevation token** bound to
`(operation, mgmt_key_id, target/requesting device)`. The privileged endpoints
(`grant`, `keys create`, `keys show`, `keys rotate`) require a valid, unspent elevation
token in addition to `AdminAuth`. This directly implements rec. #1/#2 of both
`SECURITY.md` files: an out-of-band human approval, server-enforced, not a client-side
nudge.

---

## 2. Generation flow (minting a scoped provider key)

*How a scoped provider key is minted, labeled, stored, and encrypted to the right
recipients.*

The mechanics already exist in `keys_create` / `store_provisioned_key` /
`OpenRouterProvider::create_key`. The proposal keeps them and tightens the policy around
them.

### 2.1 Always mint scoped

Every provisioned key MUST carry a spend cap and a reset cadence. The plumbing exists —
`--limit <cap> --limit-reset <daily|weekly|monthly>` flow through to OpenRouter's
`limit` on create and a follow-up `PATCH {limit_reset}` (create doesn't accept
`limit_reset`; see the openrouter provider comment). A management key can also carry
`default_limit` / `default_limit_reset` so a bare `keys create` still gets a bounded key
(`row.default_limit` fallback in `keys_create`).

**Policy proposal:** make an unbounded provisioned key impossible to mint through the
happy path. If neither a CLI flag nor a management-key default supplies a limit, refuse
rather than mint an uncapped key. A leaked scoped key then has a bounded blast radius.

### 2.2 Dated, purpose-specific labels

Labels are the audit surface (they show up in `mgmt-key keys list` and on the provider
dashboard). Require a descriptive, dated label, e.g. `soloforge-e2e-2026-09-21`. This
makes stray keys attributable and easy to reap. (Matches `kv_cli/SECURITY.md` "Structure
for safe agent-driven provisioning" item 2.)

### 2.3 Encrypt to the right recipients

`store_provisioned_key` re-runs device selection for the *provisioned* key independently
of the management key's recipients — so a key can be minted by an admin device and
encrypted for a *different*, least-privilege consumer device (e.g. the app host), which
never needs the management key at all. Recommended default: encrypt the provisioned key
**only** to the consuming device(s), not to the full admin set — narrow the blast radius
of the sub-key the same way the management key is narrowed.

### 2.4 Where the plaintext lives

At creation the provider returns the plaintext exactly once (`CreateResponse.key`). Today
it flows into `emit_secret`. Under this proposal (see §4) the create path's *default* for
an agent invocation is a no-print sink; the encrypted copy stored server-side remains the
canonical retrievable form via `keys show` for authorized devices.

---

## 3. Sourcing flow (how an app obtains its key at runtime)

There are two distinct models. They are complementary; pick per consumer.

### 3.1 KV-entry model — `kv get SOLO_FORGE_API_KEY` (exists)

An app's key is stored as a normal (optionally **device-encrypted**) KV entry and fetched
at runtime with `kv get <NAME>`. Device-encrypted entries follow the same envelope
pattern as management keys: `GET /api/admin/devices/{device_id}/kv/{key}` returns
ciphertext + this device's DEK wrap, decrypted locally
(`kv_cli/commands/kv.rs::get` → `get_device_encrypted`; server
`devices/handlers.rs::get_device_kv`, which enforces `device owned by owner`).

**Use this when:** the consumer is a long-running app/service with a stable identity, the
key rotates on a schedule (not per-run), and multiple processes on the host read the same
value. It decouples the consumer from provider-specific provisioning: the app only knows
"read `SOLO_FORGE_API_KEY`", and rotation (see §5) swaps the value underneath it.

### 3.2 Direct-provisioning model (exists for the mint half)

The consumer (or an agent acting for it) mints a *fresh* scoped key at point of use via
`kv mgmt-key keys create`, uses it, and revokes it when done.

**Use this when:** the work is ephemeral and self-contained (an e2e test run, a one-off
job), you want per-run isolation and a bounded TTL, and you can revoke-on-done. Each run
gets its own attributable, independently-revocable key.

### 3.3 Recommended split

- **Standing apps → KV-entry model.** One durable, named entry; rotate on schedule.
- **Ephemeral/agent jobs → direct provisioning** with a scoped, dated key + revoke-on-done.
- **Bridge:** an agent may *provision* a scoped key (§4) and *write it into* the KV entry
  the app reads (§5 rotation), so the app keeps using the stable KV-entry contract while
  the actual credential behind it is short-lived and freshly minted.

---

## 4. Agent-safe handling (the no-print sink)

*So a secret never transits a terminal/transcript, plus scope + TTL + revoke-on-done.*

### 4.1 The problem with today's agent path

The only way an agent gets a raw value today is
`--dangerously-show-content-on-agent-true`, which makes `emit_secret` `print!` the
plaintext to stdout — where it lands in the tool transcript and thus the model's context
(and potentially the model provider). `agent_detect::should_nudge()` is best-effort and
self-overridable by design. So "agent reads the secret to inject it" is inherently
leaky.

### 4.2 Proposed: a no-print sink (`--write-to-fd` / `--exec`)

Add secret-delivery modes to `emit_secret` (and the `keys create` / `keys rotate` /
`keys show` / `kv get` call sites) that hand the plaintext to a *consumer* without ever
rendering it to stdout/stderr:

- `--write-to-fd <N>`: write the raw bytes to inherited file descriptor `N` (e.g. a pipe
  the orchestrator opened), never to stdout. The agent wires fd `N` to the consumer and
  never sees the bytes.
- `--exec '<cmd>'`: spawn `<cmd>` and pipe the plaintext straight into its **stdin**; the
  agent orchestrates injection but the value only ever exists in the child's stdin. (E.g.
  `--exec 'kv set SOLO_FORGE_API_KEY --device --stdin'` to land it directly into the KV
  entry, or feeding a container/env-file writer.)

Both are additive `SecretDisplay`/sink variants; when a sink is specified, `emit_secret`
routes to it and prints nothing. Crucially, this is the *supported* agent path — it lets
us stop treating `--dangerously-show-content-on-agent-true` as the escape hatch and
instead make raw stdout reveal interactive-only.

### 4.3 Interactive-only reveal + non-overridable dangerous flag

Per `kv_cli/SECURITY.md` rec. #1: a raw reveal to stdout in a detected-agent context
should require an interactive confirmation or a second factor, **not** a single
self-passable flag. Concretely: `--dangerously-show-content-on-agent-true` should only
short-circuit when a TTY is present (interactive human), and for `keys show` the server
should additionally require the elevation token from §1.3. The no-print sink is what makes
this restriction acceptable — agents that legitimately need the value use a sink, not a
print.

### 4.4 Scope + TTL + revoke-on-done

The agent's contract for a provisioned key (from `kv_cli/SECURITY.md`):

1. **Prerequisite (human-gated):** the agent's device is an approval-granted recipient of
   the management key (§1). No standing session self-authorizes.
2. **Scope:** always `--limit <cap> --limit-reset <cadence>` + a dated label.
3. **No print:** deliver via `--write-to-fd`/`--exec`; never `--dangerously-show...`.
4. **Short TTL + revoke-on-done:** the agent runs `kv mgmt-key keys revoke <mgmt_key_id>
   <provider_key_id>` as soon as the task finishes (this deletes on the provider *and*
   the stored local ciphertext — `keys_revoke` → `delete_local_provisioned_key`). Prefer
   keys that also auto-expire provider-side.
5. **Audit:** server logs provision/reveal/revoke (rec. #4/#5, both SECURITY notes) and
   alerts on agent-pattern bursts.

---

## 5. Rotation

*How keys are rotated and how consumers pick up the new value.*

### 5.1 Provisioned-key rotation (exists)

`kv mgmt-key keys rotate <mgmt_key_id> <provider_key_id>` already: reads the current
`limit`/`limit_reset` from the provider (not stale local defaults), **deletes the old key,
then creates the replacement** with the same label/limits, and stores the new ciphertext
(`keys_rotate`). The ordering (delete-then-create) has a brief zero-active-key window and
fails *loudly* with a CRITICAL message if the create leg fails — an accepted, documented
tradeoff. For a make-before-break variant, invert to create-new → update-consumer →
revoke-old (see 5.3).

### 5.2 Consumer pickup for the KV-entry model

For apps sourcing via `kv get SOLO_FORGE_API_KEY`, rotation must **atomically update the
KV entry** so the next read returns the new value:

1. Provision the replacement scoped key (§2), delivered via a no-print sink (§4).
2. Sink writes it straight into the KV entry:
   `--exec 'kv set SOLO_FORGE_API_KEY --device --stdin'` (encrypting to the consumer
   device set). The server upsert replaces the entry's body/recipients in place.
3. The app re-reads `kv get SOLO_FORGE_API_KEY` on its own cadence (next request, or a
   refresh interval) and transparently gets the new value — it never learns a key rotated.
4. Revoke the old provider key once the new value is confirmed live.

The KV-entry contract is what makes rotation invisible to consumers: the *name* is stable;
the *value* behind it is swapped atomically. This is the "bridge" from §3.3 — short-lived
minted credentials behind a durable named entry.

### 5.3 Recommended ordering for zero-downtime

For a standing app, prefer **make-before-break**: create new → write KV entry → verify →
revoke old. This avoids the zero-active-key window that `keys rotate` accepts, at the cost
of two live keys for a short overlap (both scoped, so bounded).

### 5.4 Management-key rotation

A management (provisioning) key itself rotates out-of-band with the provider, then is
re-added with `kv mgmt-key add` and re-granted to recipient devices (§1.2). The
2026-09-20 follow-up (rotating the OpenRouter management key as a precaution) is exactly
this path.

---

## 6. Recommended path forward (the reasonable path)

A concrete, minimal sequence that is secure today and gets safer as the two gaps close.

### 6.1 For a standing app (e.g. SoloForge) — KV-entry model

Human admin, on a device that is already a recipient of the OpenRouter management key:

```bash
# 1. Mint a scoped, dated key (bounded blast radius), deliver via no-print sink
#    straight into the app's KV entry (proposed --exec sink):
kv mgmt-key keys create <mgmt_key_id> soloforge-prod-2026-09-21 \
    --limit 20 --limit-reset monthly \
    --exec 'kv set SOLO_FORGE_API_KEY --device --stdin'   # [needs build: --exec]

# 2. App reads it at runtime, unchanged:
kv get SOLO_FORGE_API_KEY            # device-encrypted; decrypts locally

# 3. Rotate on schedule (make-before-break):
kv mgmt-key keys create <mgmt_key_id> soloforge-prod-2026-10-21 \
    --limit 20 --limit-reset monthly \
    --exec 'kv set SOLO_FORGE_API_KEY --device --stdin'
#    verify app healthy, then:
kv mgmt-key keys revoke <mgmt_key_id> <old_provider_key_id>
```

Until `--exec`/`--write-to-fd` exist, a **human** performs step 1's inject interactively
(reveal on a TTY, paste into `kv set`) — do not use an agent for the reveal.

### 6.2 For an agent-driven ephemeral job — direct provisioning

Prerequisite (one-time, human-gated): the agent's device is an approval-granted recipient
of the management key:

```bash
kv mgmt-key grant <mgmt_key_id> <agent_device>   # [needs build] approval-gated re-share
```

Then, per run:

```bash
# provision → deliver into the consumer via a pipe, agent never sees the value
kv mgmt-key keys create <mgmt_key_id> agentjob-e2e-2026-09-21 \
    --limit 1 --limit-reset weekly \
    --write-to-fd 3   3>/run/secrets/or.key         # [needs build: --write-to-fd]
# ... run the job using the injected key ...
kv mgmt-key keys revoke <mgmt_key_id> <provider_key_id>   # revoke-on-done
```

The agent orchestrates provision and revoke but never reads the plaintext.

### 6.3 What already exists vs. what needs building

**Already works (no code change):**

- Device-encrypted management keys; local decrypt via per-device envelope
  (`get_management_key_envelope`, `decrypt_management_key`).
- Provisioning is device-gated: non-recipient devices 404 (the core boundary).
- Scoped minting with `--limit` / `--limit-reset` + management-key defaults; dated labels.
- Store/list/show/revoke/rotate of provisioned keys, encrypted to a chosen device set.
- Revoke deletes both provider-side and the stored local ciphertext.
- KV-entry sourcing, including device-encrypted entries (`kv get` / `kv set --device`).
- WebAuthn-gated device registration (`kv device propose`) and the human approval channel
  (`session_request` + `kv_apk`) to build on.

**Needs building (in rough priority):**

1. **No-print sink** — `--write-to-fd <N>` / `--exec '<cmd>'` on `keys create`,
   `keys rotate`, `keys show`, and `kv get`; route `emit_secret` to the sink and print
   nothing. *This is the unblock:* until it exists, agent provisioning stays unsupported
   (per `kv_cli/SECURITY.md`). Client-only change.
2. **Interactive-only raw reveal** — make `--dangerously-show-content-on-agent-true`
   effective only with a TTY; require server-side elevation for `keys show`. Client +
   server.
3. **Recipient grant command + endpoint** — `kv mgmt-key grant <id> <device>` and
   `POST /api/admin/management-keys/{id}/recipients`, so an existing management key can be
   re-shared to a new device. Client + server.
4. **Approval-gated privileged ops** — extend `session_request` into a single-operation
   elevation token required by `grant`, `keys create`, `keys show`, `keys rotate` on the
   server; approve on `kv_apk`. Server + `kv_apk` (+ CLI to request/poll). This is the
   direct implementation of both `SECURITY.md` files' rec. #1–#2.
5. **Refuse uncapped mint** — reject `keys create` when neither a flag nor a management-key
   default supplies a limit. Small client (ideally also server) guard.
6. **Server-side audit log + agent-pattern alerting** — log every `mgmt-key` endpoint call
   with device/session/outcome (rec. #4). Server.
7. **Device-key at rest** — back `~/.config/kv/device.key` with an OS keyring / hardware
   store so filesystem read alone can't impersonate the device (rec. #4, CLI SECURITY).
   Client.

Items 1–2 are the smallest changes that make agent-driven sourcing *safe today*; items 3–4
close the standing-session escalation gap the 2026-09-20 incident exposed; 5–7 are
defense-in-depth.

---

## Appendix: endpoint & code map

| Purpose | Endpoint / entry point | Repo · file |
| --- | --- | --- |
| Fetch this device's mgmt-key envelope | `GET /api/admin/management-keys/{id}/devices/{device_id}` | `kv_manager` `management_keys/handlers.rs::get_management_key_envelope` |
| Local decrypt of mgmt key | `decrypt_management_key` → `crypto::decrypt_device_kv` | `kv_cli` `management_keys/mod.rs` |
| Mint scoped provider key | `POST https://openrouter.ai/api/v1/keys` (+`PATCH` for `limit_reset`) | `kv_cli` `management_keys/providers/openrouter.rs::create_key` |
| Store provisioned-key ciphertext | `POST /api/admin/management-keys/{id}/provisioned-keys` | `kv_manager` `::create_provisioned_key` |
| Fetch/decrypt stored provisioned key | `GET /api/admin/management-keys/{id}/provisioned-keys/{pid}/devices/{device_id}` | `kv_manager` `::get_provisioned_key_envelope` / `kv_cli` `::keys_show` |
| Revoke (provider + local) | provider `DELETE` + `DELETE /api/admin/management-keys/{id}/provisioned-keys/{pid}` | `kv_cli` `::keys_revoke` / `kv_manager` `::delete_provisioned_key` |
| KV-entry sourcing (device-encrypted) | `GET /api/admin/devices/{device_id}/kv/{key}` | `kv_manager` `devices/handlers.rs::get_device_kv` / `kv_cli` `commands/kv.rs::get` |
| Human approval primitive to reuse | `session_request` create/approve/poll | `kv_manager` `session_request/handlers.rs` / `kv_apk` |
| Device enrolment (WebAuthn-gated) | `POST /api/devices/propose` + poll | `kv_manager` `devices/handlers.rs::propose` / `kv_cli` `commands/device.rs` |
| Agent-detection nudge (not a control) | `agent_detect::should_nudge` / `secret_display::emit_secret` | `kv_cli` |
