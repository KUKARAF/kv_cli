#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

BASE=$(cat VERSION | tr -d '[:space:]')
MAJOR=$(echo "$BASE" | cut -d. -f1)
NEW_MAJOR=$((MAJOR + 1))
echo "$NEW_MAJOR.0" > VERSION
echo "Bumped to $NEW_MAJOR.0"
