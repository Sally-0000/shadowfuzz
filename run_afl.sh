#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}"

INPUT_DIR="${ROOT_DIR}/seeds"
OUTPUT_DIR="${ROOT_DIR}/afl-out"
TIME_LIMIT=""
EXECS_LIMIT=""
USE_FILE_INPUT=0
FORCE_RESUME=0

usage() {
  cat <<'EOF'
Usage:
  ./run_afl.sh [options] /path/to/target [target args...]

Options:
  --stdin              Feed testcases via stdin (default)
  --file               Feed testcases via a temporary file path using @@
  -i, --input DIR      AFL++ input seed directory (default: ./seeds)
  -o, --output DIR     AFL++ output directory (default: ./afl-out)
  -V, --seconds SEC    Stop after SEC seconds
  -E, --execs NUM      Stop after approximately NUM executions
  --resume             Resume an existing AFL++ output directory
  -h, --help           Show this help

Examples:
  ./run_afl.sh ./b
  ./run_afl.sh -V 30 ./b
  ./run_afl.sh --file ./target @@
  ./run_afl.sh --file ./target
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stdin)
      USE_FILE_INPUT=0
      shift
      ;;
    --file)
      USE_FILE_INPUT=1
      shift
      ;;
    -i|--input)
      INPUT_DIR="$2"
      shift 2
      ;;
    -o|--output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -V|--seconds)
      TIME_LIMIT="$2"
      shift 2
      ;;
    -E|--execs)
      EXECS_LIMIT="$2"
      shift 2
      ;;
    --resume)
      FORCE_RESUME=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "run_afl: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

if ! command -v afl-fuzz >/dev/null 2>&1; then
  echo "run_afl: afl-fuzz not found in PATH" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/afl-shadow-trace" ]]; then
  echo "run_afl: missing executable ${ROOT_DIR}/afl-shadow-trace" >&2
  exit 1
fi

TARGET="$1"
shift

if [[ ! -f "${TARGET}" ]]; then
  echo "run_afl: target not found: ${TARGET}" >&2
  exit 1
fi

if [[ "${FORCE_RESUME}" -eq 1 ]]; then
  export AFL_AUTORESUME="${AFL_AUTORESUME:-1}"
  AFL_INPUT_ARG="${INPUT_DIR}"
else
  if [[ -d "${OUTPUT_DIR}" ]]; then
    base_output="${OUTPUT_DIR}"
    idx=1
    while [[ -d "${base_output}-${idx}" ]]; do
      idx=$((idx + 1))
    done
    OUTPUT_DIR="${base_output}-${idx}"
  fi
  AFL_INPUT_ARG="${INPUT_DIR}"
fi

AFL_ARGS=(-i "${AFL_INPUT_ARG}" -o "${OUTPUT_DIR}")
if [[ -n "${TIME_LIMIT}" ]]; then
  AFL_ARGS=(-V "${TIME_LIMIT}" "${AFL_ARGS[@]}")
fi
if [[ -n "${EXECS_LIMIT}" ]]; then
  AFL_ARGS=(-E "${EXECS_LIMIT}" "${AFL_ARGS[@]}")
fi

TARGET_CMD=("${ROOT_DIR}/afl-shadow-trace" "${TARGET}" "$@")
if [[ "${USE_FILE_INPUT}" -eq 1 ]]; then
  has_placeholder=0
  for arg in "${TARGET_CMD[@]}"; do
    if [[ "${arg}" == "@@" ]]; then
      has_placeholder=1
      break
    fi
  done
  if [[ "${has_placeholder}" -eq 0 ]]; then
    TARGET_CMD+=("@@")
  fi
fi

export AFL_NO_FORKSRV="${AFL_NO_FORKSRV:-1}"
export AFL_SKIP_BIN_CHECK="${AFL_SKIP_BIN_CHECK:-1}"
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES:-1}"

if [[ -n "${AFL_AUTORESUME:-}" && -d "${OUTPUT_DIR}" ]]; then
  echo "run_afl: input  -> resuming existing session in ${OUTPUT_DIR}"
else
  echo "run_afl: input  -> ${AFL_INPUT_ARG}"
fi
echo "run_afl: output -> ${OUTPUT_DIR}"
echo "run_afl: target -> ${TARGET_CMD[*]}"

exec afl-fuzz "${AFL_ARGS[@]}" -- "${TARGET_CMD[@]}"
