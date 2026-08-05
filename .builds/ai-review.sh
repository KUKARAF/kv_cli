#!/bin/bash
# Runs on every push (via .build.yml). Reviews the diff since the last
# reviewed commit with `pi` (read-only, no bash/write/network tools — it can
# only inspect files and emit findings) and files each finding as a ticket on
# TRACKER via `hut`, the only thing in this script with write access to
# anything. State (the last-reviewed SHA) lives as a comment thread on a
# pinned ticket in the same tracker — see #STATE_TICKET.
set -euo pipefail

TRACKER="kv_cli-ai-review"
STATE_TICKET=2
MODEL="minimax/minimax-m3"

HUT_CONFIG="$HOME/.hut-ai-review-config"
cat > "$HUT_CONFIG" <<EOF
instance "sourcehut" {
	origin "sr.ht"
	access-token-cmd cat $HOME/.secrets/todo_ticket_token
}
EOF
hut() { command hut --config "$HUT_CONFIG" "$@"; }

LAST_SHA=$(hut todo ticket show -t "$TRACKER" "$STATE_TICKET" \
  | grep -o 'last-reviewed-sha=[0-9a-f]*' | tail -1 | cut -d= -f2 || true)

if [ -z "$LAST_SHA" ]; then
  echo "no last-reviewed-sha found on state ticket #$STATE_TICKET — aborting" >&2
  exit 1
fi

CURRENT_SHA=$(git rev-parse HEAD)

if [ "$LAST_SHA" = "$CURRENT_SHA" ]; then
  echo "nothing new since last review ($CURRENT_SHA)"
  exit 0
fi

if ! git cat-file -e "$LAST_SHA" 2>/dev/null; then
  echo "last-reviewed-sha $LAST_SHA not found in this checkout — reviewing only the tip commit instead" >&2
  LAST_SHA=$(git rev-parse "$CURRENT_SHA^")
fi

DIFF=$(git diff "$LAST_SHA".."$CURRENT_SHA" -- . ':(exclude).builds')

if [ -z "$DIFF" ]; then
  echo "empty diff between $LAST_SHA and $CURRENT_SHA — nothing to review"
else
  export OPENROUTER_API_KEY
  OPENROUTER_API_KEY="$(cat "$HOME/.secrets/openrouter_api_key")"

  PROMPT_FILE=$(mktemp)
  {
    echo 'Review the following git diff for correctness bugs, security issues, and risky'
    echo 'changes. Respond with ONLY a JSON array (no prose, no markdown fences) of'
    echo 'objects: [{"title": string, "severity": "low"|"medium"|"high", "file": string,'
    echo '"explanation": string}]. If nothing is worth flagging, respond with []. Diff:'
    echo
    echo "$DIFF"
  } > "$PROMPT_FILE"

  RAW=$(timeout 300 pi --mode json --approve --tools read,grep,find,ls --provider openrouter --model "$MODEL" \
    "$(cat "$PROMPT_FILE")" </dev/null 2>/tmp/pi-stderr.log || true)
  rm -f "$PROMPT_FILE"

  FINAL_TEXT=$(echo "$RAW" \
    | jq -c 'select(.type == "message_end" and .message.role == "assistant")' 2>/dev/null \
    | tail -1 \
    | jq -r '[.message.content[] | select(.type=="text") | .text] | join("\n")' 2>/dev/null || echo "")

  FINDINGS_JSON=$(echo "$FINAL_TEXT" | grep -o '\[.*\]' | head -1 || true)
  [ -z "$FINDINGS_JSON" ] && FINDINGS_JSON="[]"

  if ! echo "$FINDINGS_JSON" | jq -e 'type == "array"' >/dev/null 2>&1; then
    echo "pi output wasn't parseable JSON, skipping ticket filing this run. Raw stderr:" >&2
    cat /tmp/pi-stderr.log >&2
    FINDINGS_JSON="[]"
  fi

  echo "$FINDINGS_JSON" | jq -c '.[]' | while IFS= read -r finding; do
    TITLE=$(echo "$finding" | jq -r '.title // "untitled finding"')
    SEVERITY=$(echo "$finding" | jq -r '.severity // "unknown"')
    FILE=$(echo "$finding" | jq -r '.file // "?"')
    EXPLANATION=$(echo "$finding" | jq -r '.explanation // ""')
    printf '[%s] %s (%s)\n\n%s\n\nCommit range: %s..%s\n' \
      "$SEVERITY" "$TITLE" "$FILE" "$EXPLANATION" "$LAST_SHA" "$CURRENT_SHA" \
      | hut todo ticket create -t "$TRACKER"
  done
fi

echo "state: last-reviewed-sha=$CURRENT_SHA" | hut todo ticket comment -t "$TRACKER" "$STATE_TICKET"
