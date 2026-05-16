#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 /path/to/cli-target [target args...]" >&2
  exit 2
fi

exec "$@"
