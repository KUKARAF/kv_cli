# kv_cli todos

## Approval-required key support

When a key has `approval_required` type, the CLI should handle the full flow:

1. User runs `kv get <key> --token <token>`
2. CLI calls `POST /kv/request-access` with `X-Api-Key: <token>`
3. Server returns `{ "confirm": "🦩🦁🎠" }` — 3 emojis
4. CLI prints the emojis prominently and waits:
   ```
   Waiting for approval. Tell the key owner these emojis:

     🦩  🦁  🎠

   Press Ctrl+C to cancel. Polling every 5s...
   ```
5. CLI polls `GET /kv/<key>` with the token every 5s
6. On 200: print the value (or write to stdout/file)
7. On 403 pending: keep polling
8. On 401: print "link expired or already used"

## Regenerate option

Add `--regenerate` flag or prompt the user:
```
[r] Regenerate emojis   [q] Quit
```
Regenerate calls `POST /kv/request-access` again (server cancels old request).
