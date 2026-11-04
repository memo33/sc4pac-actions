#!/usr/bin/env bash
# This wrapper script installs mono only on demand when needed.
set -euo pipefail

if ! command -v mono >/dev/null 2>&1; then
  if [[ "$(uname -s)" == "Linux" ]]; then
    sudo apt-get update
    sudo apt-get install -y mono-runtime
  else
    echo "Cannot install Mono automatically on $(uname -s)." >&2
    exit 1
  fi
fi

exec mono "$@"
