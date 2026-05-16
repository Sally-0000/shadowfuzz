#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}"

INPUT_DIR="${ROOT_DIR}/seeds"
OUTPUT_DIR="${ROOT_DIR}/afl-out"
TIME_LIMIT=""
EXECS_LIMIT=""
DICT_PATH=""
POLICY_FILE=""
EXEC_ALLOWLIST=""
ENV_ALLOWLIST=""
NETWORK_ALLOWLIST=""
PATH_ALLOWLIST=""
NGRAM_SIZE=""
USE_FILE_INPUT=0
FORCE_RESUME=0
HITCOUNT_BUCKETS=0
INLINE_COVERAGE=0
PERSISTENT=0
ABORT_ON_DANGEROUS_API=0
ABORT_ON_CREDENTIAL_FILE=0
ABORT_ON_EXEC=0
ABORT_ON_ENV_ACCESS=0
ABORT_ON_FILE_MUTATION=0
ABORT_ON_NETWORK=0
ABORT_ON_PATH_TRAVERSAL=0
TRACE_CMP=0

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
  -x, --dict FILE      AFL++ dictionary file
  --policy-file FILE   Load target-specific shadowfuzz oracle policy defaults
  --ngram N            Enable shadowcov n-gram coverage with N=1,2,4,8
  --hitcount-buckets   Enable AFL-style bucketed coverage counters
  --inline-coverage    Enable inline edge counter updates when supported
  --persistent         Use the experimental shadowfuzz persistent harness protocol
  --abort-on-dangerous-api
                        Enable shadowcov dangerous API hook oracle
  --abort-on-credential-file
                        Enable shadowcov credential file path oracle
  --abort-on-exec       Enable shadowcov exec* whitelist oracle
  --abort-on-env-access Enable shadowcov sensitive getenv oracle
  --abort-on-file-mutation
                        Enable shadowcov destructive file mutation oracle
  --abort-on-network    Enable shadowcov connect/send network oracle
  --exec-allowlist LIST Allow comma/colon-separated exec basenames
  --env-allowlist LIST  Allow comma/colon-separated env var names
  --network-allowlist LIST
                        Allow comma/colon-separated IPs or payload tokens
  --path-allowlist LIST Allow comma/colon-separated path prefixes
  --abort-on-path-traversal
                        Enable shadowcov path traversal oracle
  --trace-cmp           Enable shadowcov comparison tracing
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
    -x|--dict)
      DICT_PATH="$2"
      shift 2
      ;;
    --policy-file)
      POLICY_FILE="$2"
      shift 2
      ;;
    --ngram)
      NGRAM_SIZE="$2"
      shift 2
      ;;
    --hitcount-buckets)
      HITCOUNT_BUCKETS=1
      shift
      ;;
    --inline-coverage)
      INLINE_COVERAGE=1
      shift
      ;;
    --persistent)
      PERSISTENT=1
      shift
      ;;
    --resume)
      FORCE_RESUME=1
      shift
      ;;
    --abort-on-dangerous-api)
      ABORT_ON_DANGEROUS_API=1
      shift
      ;;
    --abort-on-credential-file)
      ABORT_ON_CREDENTIAL_FILE=1
      shift
      ;;
    --abort-on-exec)
      ABORT_ON_EXEC=1
      shift
      ;;
    --abort-on-env-access)
      ABORT_ON_ENV_ACCESS=1
      shift
      ;;
    --abort-on-file-mutation)
      ABORT_ON_FILE_MUTATION=1
      shift
      ;;
    --abort-on-network)
      ABORT_ON_NETWORK=1
      shift
      ;;
    --exec-allowlist)
      EXEC_ALLOWLIST="$2"
      shift 2
      ;;
    --env-allowlist)
      ENV_ALLOWLIST="$2"
      shift 2
      ;;
    --network-allowlist)
      NETWORK_ALLOWLIST="$2"
      shift 2
      ;;
    --path-allowlist)
      PATH_ALLOWLIST="$2"
      shift 2
      ;;
    --abort-on-path-traversal)
      ABORT_ON_PATH_TRAVERSAL=1
      shift
      ;;
    --trace-cmp)
      TRACE_CMP=1
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

if [[ ! -x "${ROOT_DIR}/build/shadowfuzz-dbi" ]]; then
  echo "run_afl: missing executable ${ROOT_DIR}/build/shadowfuzz-dbi" >&2
  echo "run_afl: build it first with: cmake -S . -B build && cmake --build build" >&2
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
if [[ -n "${DICT_PATH}" ]]; then
  AFL_ARGS=(-x "${DICT_PATH}" "${AFL_ARGS[@]}")
fi

TARGET_CMD=("${ROOT_DIR}/build/shadowfuzz-dbi")
if [[ -n "${POLICY_FILE}" ]]; then
  TARGET_CMD+=("--policy-file" "${POLICY_FILE}")
fi
if [[ "${ABORT_ON_DANGEROUS_API}" -eq 1 ]]; then
  TARGET_CMD+=("--abort-on-dangerous-api")
fi
if [[ "${ABORT_ON_CREDENTIAL_FILE}" -eq 1 ]]; then
  TARGET_CMD+=("--abort-on-credential-file")
fi
if [[ "${ABORT_ON_EXEC}" -eq 1 ]]; then
  TARGET_CMD+=("--abort-on-exec")
fi
if [[ "${ABORT_ON_ENV_ACCESS}" -eq 1 ]]; then
  TARGET_CMD+=("--abort-on-env-access")
fi
if [[ "${ABORT_ON_FILE_MUTATION}" -eq 1 ]]; then
  TARGET_CMD+=("--abort-on-file-mutation")
fi
if [[ "${ABORT_ON_NETWORK}" -eq 1 ]]; then
  TARGET_CMD+=("--abort-on-network")
fi
if [[ -n "${EXEC_ALLOWLIST}" ]]; then
  TARGET_CMD+=("--exec-allowlist" "${EXEC_ALLOWLIST}")
fi
if [[ -n "${ENV_ALLOWLIST}" ]]; then
  TARGET_CMD+=("--env-allowlist" "${ENV_ALLOWLIST}")
fi
if [[ -n "${NETWORK_ALLOWLIST}" ]]; then
  TARGET_CMD+=("--network-allowlist" "${NETWORK_ALLOWLIST}")
fi
if [[ -n "${PATH_ALLOWLIST}" ]]; then
  TARGET_CMD+=("--path-allowlist" "${PATH_ALLOWLIST}")
fi
if [[ "${ABORT_ON_PATH_TRAVERSAL}" -eq 1 ]]; then
  TARGET_CMD+=("--abort-on-path-traversal")
fi
if [[ "${TRACE_CMP}" -eq 1 ]]; then
  TARGET_CMD+=("--trace-cmp")
fi
if [[ -n "${NGRAM_SIZE}" ]]; then
  TARGET_CMD+=("--ngram" "${NGRAM_SIZE}")
fi
if [[ "${HITCOUNT_BUCKETS}" -eq 1 ]]; then
  TARGET_CMD+=("--hitcount-buckets")
fi
if [[ "${INLINE_COVERAGE}" -eq 1 ]]; then
  TARGET_CMD+=("--inline-coverage")
fi
if [[ "${PERSISTENT}" -eq 1 ]]; then
  TARGET_CMD+=("--persistent")
fi
TARGET_CMD+=("${TARGET}" "$@")
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
