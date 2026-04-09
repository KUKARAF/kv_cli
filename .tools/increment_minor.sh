#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

BASE=$(cat VERSION | tr -d '[:space:]')
MAJOR=$(echo "$BASE" | cut -d. -f1)
MINOR=$(echo "$BASE" | cut -d. -f2)
NEW_MINOR=$((MINOR + 1))
echo "$MAJOR.$NEW_MINOR" > VERSION
echo "Bumped to $MAJOR.$NEW_MINOR"
