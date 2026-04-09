#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

BASE=$(cat VERSION | tr -d '[:space:]')
SHORT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")
echo "$BASE.$SHORT_SHA"
