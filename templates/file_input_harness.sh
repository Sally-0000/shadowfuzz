#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 /path/to/file-target @@ [target args...]" >&2
  exit 2
fi

exec "$@"
