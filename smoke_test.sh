#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}"

run_case() {
  local name="$1"
  local input="$2"
  shift 2

  echo "smoke: ${name}"
  printf '%s' "${input}" | "$@" >/dev/null
}

if [[ ! -x "${ROOT_DIR}/run.sh" ]]; then
  echo "smoke: missing run.sh" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/build/shadowfuzz-dbi" ]]; then
  echo "smoke: missing build/shadowfuzz-dbi" >&2
  echo "smoke: build first with: cmake -S . -B build && cmake --build build" >&2
  exit 1
fi

if [[ ! -f "${ROOT_DIR}/tools/forkserver_selftest.py" ]]; then
  echo "smoke: missing tools/forkserver_selftest.py" >&2
  exit 1
fi

if [[ ! -f "${ROOT_DIR}/tools/bench_shadowcov.py" ]]; then
  echo "smoke: missing tools/bench_shadowcov.py" >&2
  exit 1
fi

if [[ ! -f "${ROOT_DIR}/policies/smoke-oracles.policy" || \
      ! -f "${ROOT_DIR}/policies/composed-smoke.policy" || \
      ! -f "${ROOT_DIR}/policies/invalid-ngram.policy" || \
      ! -f "${ROOT_DIR}/policies/invalid-section.policy" ]]; then
  echo "smoke: missing policy fixtures" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/templates/cli_stdin_harness.sh" || \
      ! -x "${ROOT_DIR}/templates/file_input_harness.sh" || \
      ! -f "${ROOT_DIR}/templates/shared_object_entry_harness.c" || \
      ! -f "${ROOT_DIR}/templates/plugin_host_harness.c" ]]; then
  echo "smoke: missing harness templates" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/build/poc-a" || ! -x "${ROOT_DIR}/build/poc-b" || \
      ! -x "${ROOT_DIR}/build/poc-branch-churn" ]]; then
  echo "smoke: missing poc targets under build/" >&2
  echo "smoke: build first with: cmake -S . -B build && cmake --build build" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/build/harness-shared-object-entry" || \
      ! -x "${ROOT_DIR}/build/harness-plugin-host" || \
      ! -f "${ROOT_DIR}/build/libpoc-shared-entry.so" || \
      ! -f "${ROOT_DIR}/build/libpoc-plugin-target.so" ]]; then
  echo "smoke: missing harness validation targets under build/" >&2
  echo "smoke: build first with: cmake -S . -B build && cmake --build build" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/build/poc-stack-overflow" || ! -x "${ROOT_DIR}/build/poc-file-magic" ]]; then
  echo "smoke: missing extended poc targets under build/" >&2
  echo "smoke: build first with: cmake -S . -B build && cmake --build build" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/build/poc-format-string" || \
      ! -x "${ROOT_DIR}/build/poc-command-injection" || \
      ! -x "${ROOT_DIR}/build/poc-command-system" || \
      ! -x "${ROOT_DIR}/build/poc-strcmp-magic" || \
      ! -x "${ROOT_DIR}/build/poc-compare-more" || \
      ! -x "${ROOT_DIR}/build/poc-int-compare" || \
      ! -x "${ROOT_DIR}/build/poc-counter-loop" || \
      ! -x "${ROOT_DIR}/build/poc-path-open" || \
      ! -x "${ROOT_DIR}/build/poc-exec-path" || \
      ! -x "${ROOT_DIR}/build/poc-env-access" || \
      ! -x "${ROOT_DIR}/build/poc-credential-file" || \
      ! -x "${ROOT_DIR}/build/poc-network-connect" || \
      ! -x "${ROOT_DIR}/build/poc-network-send" || \
      ! -x "${ROOT_DIR}/build/poc-file-mutation" ]]; then
  echo "smoke: missing bug-class poc targets under build/" >&2
  echo "smoke: build first with: cmake -S . -B build && cmake --build build" >&2
  exit 1
fi

run_case "run.sh poc-a stdout path" $'hello\n' "${ROOT_DIR}/run.sh" "${ROOT_DIR}/build/poc-a"
run_case "run.sh poc-b non-crash path" $'ZZZZ\n' "${ROOT_DIR}/run.sh" "${ROOT_DIR}/build/poc-b"
run_case "shadowfuzz-dbi poc-a stdout path" $'hello\n' \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-a"
run_case "shadowfuzz-dbi poc-b non-crash path" $'ZZZZ\n' \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-b"
echo "smoke: shadowfuzz-dbi check mode"
"${ROOT_DIR}/build/shadowfuzz-dbi" --check "${ROOT_DIR}/build/poc-a" >/dev/null
echo "smoke: shadowfuzz-dbi cli options path"
"${ROOT_DIR}/build/shadowfuzz-dbi" --map-size 65536 --target-module poc-a \
  "${ROOT_DIR}/build/poc-a" </dev/null >/dev/null
echo "smoke: shadowfuzz-dbi direct crash path"
if printf 'ABCD\n' | "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-b" >/dev/null 2>&1; then
  echo "smoke: expected direct-run crash path to fail" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi stack overflow crash path"
if printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-stack-overflow" >/dev/null 2>&1; then
  echo "smoke: expected stack overflow crash path to fail" >&2
  exit 1
fi
file_magic_input="$(mktemp)"
printf 'SHDW\x01\x23FUZZ\x7f\xff' > "${file_magic_input}"
echo "smoke: shadowfuzz-dbi file input crash path"
if "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-file-magic" \
  "${file_magic_input}" >/dev/null 2>&1; then
  echo "smoke: expected file input crash path to fail" >&2
  rm -f "${file_magic_input}"
  exit 1
fi
rm -f "${file_magic_input}"
echo "smoke: shadowfuzz-dbi format string crash path"
if printf '%%%s%%%s%%%s\n' s s s | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-format-string" >/dev/null 2>&1; then
  echo "smoke: expected format string crash path to fail" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi command injection oracle crash path"
if printf 'alice;id\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-command-injection" >/dev/null 2>&1; then
  echo "smoke: expected command injection oracle crash path to fail" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi dangerous API hook crash path"
if printf 'alice;id\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-dangerous-api \
  "${ROOT_DIR}/build/poc-command-system" >/dev/null 2>&1; then
  echo "smoke: expected dangerous API hook crash path to fail" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi path traversal hook path"
printf 'safe-name\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-path-traversal \
  "${ROOT_DIR}/build/poc-path-open" >/dev/null 2>&1
if printf '../etc/passwd\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-path-traversal \
  "${ROOT_DIR}/build/poc-path-open" >/dev/null 2>&1; then
  echo "smoke: expected path traversal hook crash path to fail" >&2
  exit 1
fi
printf '../etc/passwd\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-path-traversal \
  --path-allowlist ../etc \
  "${ROOT_DIR}/build/poc-path-open" >/dev/null 2>&1
echo "smoke: shadowfuzz-dbi exec hook path"
printf 'relative-tool\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-exec \
  "${ROOT_DIR}/build/poc-exec-path" >/dev/null 2>&1
printf '/bin/true\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-exec --exec-allowlist true \
  "${ROOT_DIR}/build/poc-exec-path" >/dev/null 2>&1
if printf '/bin/sh\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-exec --exec-allowlist true \
  "${ROOT_DIR}/build/poc-exec-path" >/dev/null 2>&1; then
  echo "smoke: expected exec hook crash path to fail" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi env access hook path"
printf 'P\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-env-access \
  "${ROOT_DIR}/build/poc-env-access" >/dev/null 2>&1
if printf 'S\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-env-access \
  "${ROOT_DIR}/build/poc-env-access" >/dev/null 2>&1; then
  echo "smoke: expected env access hook crash path to fail" >&2
  exit 1
fi
printf 'S\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-env-access \
  --env-allowlist AWS_SECRET_ACCESS_KEY \
  "${ROOT_DIR}/build/poc-env-access" >/dev/null 2>&1
echo "smoke: shadowfuzz-dbi credential file hook path"
printf 'P\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-credential-file \
  "${ROOT_DIR}/build/poc-credential-file" >/dev/null 2>&1
if printf 'S\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-credential-file \
  "${ROOT_DIR}/build/poc-credential-file" >/dev/null 2>&1; then
  echo "smoke: expected credential file hook crash path to fail" >&2
  exit 1
fi
printf 'S\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-credential-file \
  --path-allowlist .aws \
  "${ROOT_DIR}/build/poc-credential-file" >/dev/null 2>&1
echo "smoke: shadowfuzz-dbi policy file path"
printf 'S\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" \
  --policy-file "${ROOT_DIR}/policies/smoke-oracles.policy" \
  "${ROOT_DIR}/build/poc-env-access" >/dev/null 2>&1
printf 'S\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" \
  --policy-file "${ROOT_DIR}/policies/smoke-oracles.policy" \
  "${ROOT_DIR}/build/poc-credential-file" >/dev/null 2>&1
printf 'S\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" \
  --policy-file "${ROOT_DIR}/policies/base.release.policy" \
  --policy-file "${ROOT_DIR}/policies/smoke-oracles.policy" \
  "${ROOT_DIR}/build/poc-env-access" >/dev/null 2>&1
printf 'S\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" \
  --policy-file "${ROOT_DIR}/policies/composed-smoke.policy" \
  "${ROOT_DIR}/build/poc-env-access" >/dev/null 2>&1
if printf 'I\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" \
  --policy-file "${ROOT_DIR}/policies/smoke-oracles.policy" \
  "${ROOT_DIR}/build/poc-credential-file" >/dev/null 2>&1; then
  echo "smoke: expected policy file credential crash path to fail" >&2
  exit 1
fi
if "${ROOT_DIR}/build/shadowfuzz-dbi" \
  --policy-file "${ROOT_DIR}/policies/invalid-ngram.policy" \
  "${ROOT_DIR}/build/poc-a" >/dev/null 2>&1; then
  echo "smoke: expected invalid ngram policy to fail" >&2
  exit 1
fi
if "${ROOT_DIR}/build/shadowfuzz-dbi" \
  --policy-file "${ROOT_DIR}/policies/invalid-section.policy" \
  "${ROOT_DIR}/build/poc-a" >/dev/null 2>&1; then
  echo "smoke: expected invalid section policy to fail" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi network hook path"
printf 'L\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-network \
  "${ROOT_DIR}/build/poc-network-connect" >/dev/null 2>&1
if printf 'R\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-network \
  "${ROOT_DIR}/build/poc-network-connect" >/dev/null 2>&1; then
  echo "smoke: expected network hook crash path to fail" >&2
  exit 1
fi
printf 'R\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-network \
  --network-allowlist 203.0.113.1 \
  "${ROOT_DIR}/build/poc-network-connect" >/dev/null 2>&1
echo "smoke: shadowfuzz-dbi network send hook path"
printf 'L\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-network \
  "${ROOT_DIR}/build/poc-network-send" >/dev/null 2>&1
if printf 'M\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-network \
  "${ROOT_DIR}/build/poc-network-send" >/dev/null 2>&1; then
  echo "smoke: expected network send hook crash path to fail" >&2
  exit 1
fi
printf 'M\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-network \
  --network-allowlist 169.254.169.254 \
  "${ROOT_DIR}/build/poc-network-send" >/dev/null 2>&1
echo "smoke: shadowfuzz-dbi file mutation hook path"
printf 'S\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-file-mutation \
  "${ROOT_DIR}/build/poc-file-mutation" >/dev/null 2>&1
if printf 'D\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-file-mutation \
  "${ROOT_DIR}/build/poc-file-mutation" >/dev/null 2>&1; then
  echo "smoke: expected file delete hook crash path to fail" >&2
  exit 1
fi
if printf 'T\n' | \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --abort-on-file-mutation \
  "${ROOT_DIR}/build/poc-file-mutation" >/dev/null 2>&1; then
  echo "smoke: expected file overwrite hook crash path to fail" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi trace-cmp coverage path"
cmp_base_map="$(mktemp)"
cmp_trace_map="$(mktemp)"
printf 'Open\n' | SHADOWCOV_BITMAP_OUT="${cmp_base_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-strcmp-magic" >/dev/null 2>&1
printf 'Open\n' | SHADOWCOV_BITMAP_OUT="${cmp_trace_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --trace-cmp "${ROOT_DIR}/build/poc-strcmp-magic" >/dev/null 2>&1
cmp_base_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${cmp_base_map}")"
cmp_trace_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${cmp_trace_map}")"
rm -f "${cmp_base_map}" "${cmp_trace_map}"
if [[ "${cmp_trace_count}" -le "${cmp_base_count}" ]]; then
  echo "smoke: expected trace-cmp to add coverage (${cmp_base_count} -> ${cmp_trace_count})" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi extended trace-cmp coverage path"
cmp_more_base_map="$(mktemp)"
cmp_more_trace_map="$(mktemp)"
printf 'Token-needle:blu\n' | SHADOWCOV_BITMAP_OUT="${cmp_more_base_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-compare-more" >/dev/null 2>&1 || true
printf 'Token-needle:blu\n' | SHADOWCOV_BITMAP_OUT="${cmp_more_trace_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --trace-cmp "${ROOT_DIR}/build/poc-compare-more" >/dev/null 2>&1 || true
cmp_more_base_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${cmp_more_base_map}")"
cmp_more_trace_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${cmp_more_trace_map}")"
rm -f "${cmp_more_base_map}" "${cmp_more_trace_map}"
if [[ "${cmp_more_trace_count}" -le "${cmp_more_base_count}" ]]; then
  echo "smoke: expected extended trace-cmp to add coverage (${cmp_more_base_count} -> ${cmp_more_trace_count})" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi integer trace-cmp coverage path"
int_cmp_base_map="$(mktemp)"
int_cmp_trace_map="$(mktemp)"
printf 'MCG\n' | SHADOWCOV_BITMAP_OUT="${int_cmp_base_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-int-compare" >/dev/null 2>&1 || true
printf 'MCG\n' | SHADOWCOV_BITMAP_OUT="${int_cmp_trace_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --trace-cmp "${ROOT_DIR}/build/poc-int-compare" >/dev/null 2>&1 || true
int_cmp_base_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${int_cmp_base_map}")"
int_cmp_trace_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${int_cmp_trace_map}")"
rm -f "${int_cmp_base_map}" "${int_cmp_trace_map}"
if [[ "${int_cmp_trace_count}" -le "${int_cmp_base_count}" ]]; then
  echo "smoke: expected integer trace-cmp to add coverage (${int_cmp_base_count} -> ${int_cmp_trace_count})" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi reg/reg integer trace-cmp coverage path"
reg_cmp_base_map="$(mktemp)"
reg_cmp_trace_map="$(mktemp)"
printf 'AAAAAAREG\n' | SHADOWCOV_BITMAP_OUT="${reg_cmp_base_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-int-compare" >/dev/null 2>&1 || true
printf 'AAAAAAREG\n' | SHADOWCOV_BITMAP_OUT="${reg_cmp_trace_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --trace-cmp "${ROOT_DIR}/build/poc-int-compare" >/dev/null 2>&1 || true
reg_cmp_base_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${reg_cmp_base_map}")"
reg_cmp_trace_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${reg_cmp_trace_map}")"
rm -f "${reg_cmp_base_map}" "${reg_cmp_trace_map}"
if [[ "${reg_cmp_trace_count}" -le "${reg_cmp_base_count}" ]]; then
  echo "smoke: expected reg/reg integer trace-cmp to add coverage (${reg_cmp_base_count} -> ${reg_cmp_trace_count})" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi ngram coverage path"
ngram_base_map="$(mktemp)"
ngram_map="$(mktemp)"
printf 'ABCD\n' | SHADOWCOV_BITMAP_OUT="${ngram_base_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-b" >/dev/null 2>&1 || true
printf 'ABCD\n' | SHADOWCOV_BITMAP_OUT="${ngram_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --ngram 4 "${ROOT_DIR}/build/poc-b" >/dev/null 2>&1 || true
ngram_base_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${ngram_base_map}")"
ngram_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${ngram_map}")"
if [[ "${ngram_base_count}" -le 0 || "${ngram_count}" -le 0 ]]; then
  echo "smoke: expected non-empty ngram coverage maps" >&2
  rm -f "${ngram_base_map}" "${ngram_map}"
  exit 1
fi
if cmp -s "${ngram_base_map}" "${ngram_map}"; then
  echo "smoke: expected ngram coverage map to differ from classic edge coverage" >&2
  rm -f "${ngram_base_map}" "${ngram_map}"
  exit 1
fi
rm -f "${ngram_base_map}" "${ngram_map}"
echo "smoke: shadowfuzz-dbi neverzero counter path"
neverzero_map="$(mktemp)"
wrapping_map="$(mktemp)"
printf 'LOOP' | SHADOWCOV_BITMAP_OUT="${neverzero_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-counter-loop" >/dev/null 2>&1
printf 'LOOP' | SHADOWCOV_DISABLE_NEVERZERO=1 SHADOWCOV_BITMAP_OUT="${wrapping_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-counter-loop" >/dev/null 2>&1
if cmp -s "${neverzero_map}" "${wrapping_map}"; then
  echo "smoke: expected neverzero and wrapping counter maps to differ" >&2
  rm -f "${neverzero_map}" "${wrapping_map}"
  exit 1
fi
rm -f "${neverzero_map}" "${wrapping_map}"
echo "smoke: shadowfuzz-dbi hitcount bucket path"
raw_hitcount_map="$(mktemp)"
bucket_hitcount_map="$(mktemp)"
printf 'LOOP' | SHADOWCOV_BITMAP_OUT="${raw_hitcount_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-counter-loop" >/dev/null 2>&1
printf 'LOOP' | SHADOWCOV_BITMAP_OUT="${bucket_hitcount_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --hitcount-buckets \
  "${ROOT_DIR}/build/poc-counter-loop" >/dev/null 2>&1
raw_hitcount_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${raw_hitcount_map}")"
bucket_hitcount_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${bucket_hitcount_map}")"
if [[ "${raw_hitcount_count}" -le 0 || "${bucket_hitcount_count}" -le 0 ]]; then
  echo "smoke: expected non-empty hitcount coverage maps" >&2
  rm -f "${raw_hitcount_map}" "${bucket_hitcount_map}"
  exit 1
fi
if cmp -s "${raw_hitcount_map}" "${bucket_hitcount_map}"; then
  echo "smoke: expected bucketed hitcount map to differ from raw counters" >&2
  rm -f "${raw_hitcount_map}" "${bucket_hitcount_map}"
  exit 1
fi
rm -f "${raw_hitcount_map}" "${bucket_hitcount_map}"
echo "smoke: shadowfuzz-dbi inline coverage path"
inline_map="$(mktemp)"
printf 'hello\n' | SHADOWCOV_BITMAP_OUT="${inline_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --inline-coverage \
  "${ROOT_DIR}/build/poc-a" >/dev/null 2>&1
inline_count="$(python3 -c 'import sys; print(sum(1 for b in open(sys.argv[1], "rb").read() if b))' "${inline_map}")"
rm -f "${inline_map}"
if [[ "${inline_count}" -le 0 ]]; then
  echo "smoke: expected non-empty inline coverage map" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi inline hitcount bucket path"
clean_bucket_map="$(mktemp)"
inline_bucket_map="$(mktemp)"
printf 'LOOP' | SHADOWCOV_BITMAP_OUT="${clean_bucket_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --hitcount-buckets \
  "${ROOT_DIR}/build/poc-counter-loop" >/dev/null 2>&1
printf 'LOOP' | SHADOWCOV_BITMAP_OUT="${inline_bucket_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --hitcount-buckets --inline-coverage \
  "${ROOT_DIR}/build/poc-counter-loop" >/dev/null 2>&1
if ! cmp -s "${clean_bucket_map}" "${inline_bucket_map}"; then
  echo "smoke: expected clean-call and inline bucket maps to match" >&2
  rm -f "${clean_bucket_map}" "${inline_bucket_map}"
  exit 1
fi
rm -f "${clean_bucket_map}" "${inline_bucket_map}"
echo "smoke: shadowfuzz-dbi inline ngram coverage path"
clean_ngram_inline_map="$(mktemp)"
inline_ngram_map="$(mktemp)"
printf 'ABCD\n' | SHADOWCOV_BITMAP_OUT="${clean_ngram_inline_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --ngram 4 \
  "${ROOT_DIR}/build/poc-b" >/dev/null 2>&1 || true
printf 'ABCD\n' | SHADOWCOV_BITMAP_OUT="${inline_ngram_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --ngram 4 --inline-coverage \
  "${ROOT_DIR}/build/poc-b" >/dev/null 2>&1 || true
if ! cmp -s "${clean_ngram_inline_map}" "${inline_ngram_map}"; then
  echo "smoke: expected clean-call and inline ngram maps to match" >&2
  rm -f "${clean_ngram_inline_map}" "${inline_ngram_map}"
  exit 1
fi
rm -f "${clean_ngram_inline_map}" "${inline_ngram_map}"
echo "smoke: shadowfuzz-dbi inline ngram bucket path"
clean_ngram_bucket_map="$(mktemp)"
inline_ngram_bucket_map="$(mktemp)"
printf 'ABCD\n' | SHADOWCOV_BITMAP_OUT="${clean_ngram_bucket_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --ngram 4 --hitcount-buckets \
  "${ROOT_DIR}/build/poc-b" >/dev/null 2>&1 || true
printf 'ABCD\n' | SHADOWCOV_BITMAP_OUT="${inline_ngram_bucket_map}" \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --ngram 4 --hitcount-buckets --inline-coverage \
  "${ROOT_DIR}/build/poc-b" >/dev/null 2>&1 || true
if ! cmp -s "${clean_ngram_bucket_map}" "${inline_ngram_bucket_map}"; then
  echo "smoke: expected clean-call and inline ngram bucket maps to match" >&2
  rm -f "${clean_ngram_bucket_map}" "${inline_ngram_bucket_map}"
  exit 1
fi
rm -f "${clean_ngram_bucket_map}" "${inline_ngram_bucket_map}"
echo "smoke: forkserver self-test"
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --stdin hello \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-a" >/dev/null
echo "smoke: forkserver shared-memory coverage self-test"
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --expect-coverage --stdin hello \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-a" >/dev/null
echo "smoke: forkserver crash self-test"
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --expect-signal SIGABRT --stdin ABCD \
  "${ROOT_DIR}/build/shadowfuzz-dbi" "${ROOT_DIR}/build/poc-b" >/dev/null
echo "smoke: forkserver pid-before-status self-test"
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --kill-after-pid --pid-timeout-ms 1000 \
  --expect-signal SIGKILL "${ROOT_DIR}/build/shadowfuzz-dbi" /bin/sleep 30 >/dev/null
echo "smoke: persistent harness forkserver self-test"
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --expect-coverage --stdin PER \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --persistent \
  "${ROOT_DIR}/build/poc-persistent-harness" >/dev/null
echo "smoke: persistent harness synthetic crash self-test"
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --expect-signal SIGABRT --stdin PERS \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --persistent \
  "${ROOT_DIR}/build/poc-persistent-harness" >/dev/null
echo "smoke: persistent shared object harness path"
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --expect-coverage --stdin safe \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --persistent \
  "${ROOT_DIR}/build/harness-shared-object-entry" \
  "${ROOT_DIR}/build/libpoc-shared-entry.so" target_entry >/dev/null
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --expect-signal SIGABRT --stdin 'SO!!' \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --persistent \
  "${ROOT_DIR}/build/harness-shared-object-entry" \
  "${ROOT_DIR}/build/libpoc-shared-entry.so" target_entry >/dev/null
echo "smoke: persistent plugin host harness path"
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --expect-coverage --stdin safe \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --persistent \
  "${ROOT_DIR}/build/harness-plugin-host" \
  "${ROOT_DIR}/build/libpoc-plugin-target.so" >/dev/null
python3 "${ROOT_DIR}/tools/forkserver_selftest.py" --expect-signal SIGABRT --stdin 'PLG!' \
  "${ROOT_DIR}/build/shadowfuzz-dbi" --persistent \
  "${ROOT_DIR}/build/harness-plugin-host" \
  "${ROOT_DIR}/build/libpoc-plugin-target.so" >/dev/null
echo "smoke: shadowcov benchmark tool self-test"
python3 "${ROOT_DIR}/tools/bench_shadowcov.py" --iterations 1 --warmups 0 \
  --configs clean,inline --target "${ROOT_DIR}/build/poc-branch-churn" >/dev/null
echo "smoke: harness template syntax self-test"
bash -n "${ROOT_DIR}/templates/cli_stdin_harness.sh"
bash -n "${ROOT_DIR}/templates/file_input_harness.sh"
cc -O2 -Wall -Wextra -o /tmp/shadowfuzz-so-entry-harness-check \
  "${ROOT_DIR}/templates/shared_object_entry_harness.c" -ldl
cc -O2 -Wall -Wextra -o /tmp/shadowfuzz-plugin-host-harness-check \
  "${ROOT_DIR}/templates/plugin_host_harness.c" -ldl
echo "smoke: shared object harness path"
printf 'safe\n' | "${ROOT_DIR}/build/shadowfuzz-dbi" --inline-coverage \
  "${ROOT_DIR}/build/harness-shared-object-entry" \
  "${ROOT_DIR}/build/libpoc-shared-entry.so" target_entry >/dev/null 2>&1
if printf 'SO!!' | "${ROOT_DIR}/build/shadowfuzz-dbi" --inline-coverage \
  "${ROOT_DIR}/build/harness-shared-object-entry" \
  "${ROOT_DIR}/build/libpoc-shared-entry.so" target_entry >/dev/null 2>&1; then
  echo "smoke: expected shared object harness crash path to fail" >&2
  exit 1
fi
echo "smoke: plugin host harness path"
printf 'safe\n' | "${ROOT_DIR}/build/shadowfuzz-dbi" --inline-coverage \
  "${ROOT_DIR}/build/harness-plugin-host" \
  "${ROOT_DIR}/build/libpoc-plugin-target.so" >/dev/null 2>&1
if printf 'PLG!' | "${ROOT_DIR}/build/shadowfuzz-dbi" --inline-coverage \
  "${ROOT_DIR}/build/harness-plugin-host" \
  "${ROOT_DIR}/build/libpoc-plugin-target.so" >/dev/null 2>&1; then
  echo "smoke: expected plugin harness crash path to fail" >&2
  exit 1
fi
echo "smoke: shadowfuzz-dbi check failure path"
if "${ROOT_DIR}/build/shadowfuzz-dbi" --check "${ROOT_DIR}/build/does-not-exist" >/dev/null 2>&1; then
  echo "smoke: expected check failure path to fail" >&2
  exit 1
fi

echo "smoke: ok"
