# Security

## Printing secrets

`kv get <key>` (and the other commands that print a secret: `kv keys create`,
`kv mgmt-key keys create|rotate|show`, `kv provider-key get`) writes the raw
value to stdout with no prompt and no terminal check, so it can be used
directly in scripts and command substitution:

```
curl -s -H "Authorization: Bearer $(kv get TORBOX_API_KEY)" https://api.torbox.app/v1/api/user/me
```

CI (`ci-required.yml`) checks exactly this, non-interactively, on every push and
pull request.

Access control is the server's job: a scoped API key (`kv add-api-token`) or a
device-bound session decides which entries a caller can read. Management keys
themselves are never printed — they are decrypted in memory only to call a
provider.

### Non-secret fingerprints

- `--return-md5-on-agent-true` — prints an md5 digest of the value
- `--show-3-last-digits-on-agent-true` — prints only the last 3 characters

These confirm *which* value is present (e.g. that a rotation changed it) without
printing it.

### Residual risk / further hardening

A standing on-device session still grants any local process `mgmt-key`
authority to *provision* and *revoke* keys . Defence-in-depth beyond this CLI change — out-of-band approval for
provisioning, short-lived sessions requiring re-auth for `mgmt-key`, protecting
`device.key` in an OS keyring, and server-side audit logging — remains
worthwhile and is tracked separately.
