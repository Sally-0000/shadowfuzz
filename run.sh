#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -d "${SCRIPT_DIR}/third_party" ]]; then
  ROOT_DIR="${SCRIPT_DIR}"
else
  ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi

DR_DIR="${ROOT_DIR}/third_party/DynamoRIO-Linux-11.3.0-1"
DRRUN="${DR_DIR}/bin64/drrun"
CLIENT="${ROOT_DIR}/build/libshadowcov.so"

usage() {
  cat <<'EOF'
Usage:
  ./run.sh /path/to/target [target args...]

Environment:
  SHADOWCOV_BITMAP_OUT   Output bitmap path (default: ./coverage.map)
  SHADOWCOV_MAP_SIZE     Bitmap size, must be power of two (default: 65536)
  AFL_SHM_ID             If set, write coverage directly to AFL shared memory

Examples:
  ./run.sh ./target
  SHADOWCOV_BITMAP_OUT=/tmp/foo.map ./run.sh ./target arg1 arg2
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

TARGET="$1"
shift

if [[ ! -x "${DRRUN}" ]]; then
  echo "shadowcov-run: missing drrun at ${DRRUN}" >&2
  exit 1
fi

if [[ ! -f "${CLIENT}" ]]; then
  echo "shadowcov-run: missing client ${CLIENT}" >&2
  echo "shadowcov-run: build it first with: cmake -S . -B build && cmake --build build" >&2
  exit 1
fi

if [[ ! -f "${TARGET}" ]]; then
  echo "shadowcov-run: target not found: ${TARGET}" >&2
  exit 1
fi

if [[ -z "${AFL_SHM_ID:-}" ]]; then
  export SHADOWCOV_BITMAP_OUT="${SHADOWCOV_BITMAP_OUT:-${PWD}/coverage.map}"
  echo "shadowcov-run: bitmap output -> ${SHADOWCOV_BITMAP_OUT}"
else
  echo "shadowcov-run: using AFL shared memory AFL_SHM_ID=${AFL_SHM_ID}"
fi

echo "shadowcov-run: target -> ${TARGET}"
"${DRRUN}" -c "${CLIENT}" -- "${TARGET}" "$@"
