# shadowfuzz roadmap

This file tracks the next implementation priorities for turning shadowfuzz from
a working DBI fuzzing backend prototype into a more useful AFL++ backend.

## 1. Persistent mode

Goal: reduce per-testcase overhead by avoiding a full `drrun` / DynamoRIO startup
for every input.

Planned milestones:

- Define the first supported persistent execution contract. Done:
  `--persistent` expects a target harness that consumes
  `SHADOWFUZZ_PERSISTENT_IN_FD` / `SHADOWFUZZ_PERSISTENT_OUT_FD`.
- Add a minimal persistent harness target for controlled validation. Done:
  `poc-persistent-harness`.
- Reset coverage bitmap state between iterations. Done for the controlled
  harness protocol via `SHADOWCOV_PERSISTENT_RESET_HOOK` and the `SIGUSR2`
  reset signal.
- Return per-iteration status to AFL++. Done for the controlled harness
  protocol using wait-status encoded iteration results.
- Only then generalize toward real closed-source targets.

Current constraint: arbitrary binary persistent mode is not a small patch. The
first implementation should be narrow, documented, and testable.

Next:

- Persistent coverage gating. Done for the controlled harness protocol:
  `SIGUSR1` resets/enables coverage for target logic and `SIGUSR2` disables it
  before harness transport writes the iteration status.
- Generalize the contract for real closed-source harnesses. Done for the
  shared-object entrypoint and plugin-host templates via
  `templates/shadowfuzz_persistent.h`.

Next:

- Validate persistent shared-object and plugin-host recipes against real
  third-party targets and record target-specific notes.

## 2. Comparison feedback expansion

Already implemented:

- `strcmp`
- `strncmp`
- `memcmp`
- `strcasecmp`
- `strncasecmp`
- `strstr`
- `memmem`
- integer compare instruction tracing for x86 immediate compares
- broader x86 integer compare tracing for register/register and memory/immediate
  forms

Next:

- Further compare tracing tuning for noisy targets and additional x86 compare
  forms as needed.

## 3. Dangerous API / semantic oracle expansion

Already implemented:

- `system`
- `popen`
- `open` / `openat` / `fopen` path traversal oracle
- `exec*` family with a whitelist policy
- `getenv` / `secure_getenv` sensitive environment access oracle
- `connect` non-loopback network oracle
- `send` / `sendto` suspicious outbound payload oracle
- file deletion and overwrite oracle hooks
- common credential file access oracle for `.aws/credentials`, `.kube/config`,
  `.netrc`, SSH private keys, and similar paths
- target-specific path allowlist for path traversal and file mutation oracles
- target-specific path allowlist support for credential file oracle exceptions
- target-specific environment variable allowlist for sensitive env access
  oracle
- target-specific network allowlist for `connect` IPs and outbound payload
  tokens
- target-specific policy files that bundle oracle toggles and path, network,
  exec, and environment allowlists for repeatable real-target runs
- policy file schema hardening with `[oracles]`, `[allowlists]`, `[coverage]`,
  and `[target]` sections plus stricter key, empty value, and `ngram`
  validation
- richer policy composition via repeated `--policy-file` layering and
  relative `include=...` directives

Next:
- Real-target policy refinement as more recipes are validated

## 4. Hitcount bucket

Goal: make bitmap counter behavior closer to AFL++ hitcount classification and
reduce noisy counter differences.

Already implemented:

- Optional AFL-style bucketed coverage counters via `SHADOWCOV_HITCOUNT_BUCKETS`
  or `--hitcount-buckets`.

Release note:

- `docs/BENCHMARK.md` records the current coverage-mode benchmark for
  `v0.1.0-alpha.1`.

## 5. Inline instrumentation

Goal: replace the current clean-call coverage hot path with lower-overhead inline
counter updates.

Already implemented:

- Optional inline edge counter fast path via `SHADOWCOV_INLINE_COVERAGE` or
  `--inline-coverage` for `ngram=1` raw counters.
- Inline hitcount bucket counter updates for `ngram=1`.
- Inline n-gram history mixing and history updates.
- Benchmark harness for clean-call, inline, hitcount bucket, and n-gram mode
  comparisons on `poc-branch-churn`.

Status:

- Feature-complete for the current roadmap scope. Further work is performance
  tuning on larger targets, not missing inline functionality.

## 6. Real target harness templates

Goal: prove the backend on targets beyond toy POCs.

Already implemented:

- CLI parser fuzzing
- file parser fuzzing
- closed-source `.so` entrypoint fuzzing
- plugin host fuzzing

Artifacts:

- `templates/cli_stdin_harness.sh`
- `templates/file_input_harness.sh`
- `templates/shared_object_entry_harness.c`
- `templates/plugin_host_harness.c`
- `docs/HARNESS_TEMPLATES.md`
- `docs/TARGET_RECIPES.md`
- local `.so` entrypoint validation target
- local plugin host validation target

Next:

- Validate recipes against real third-party targets and record target-specific
  notes.

Release note:

- `docs/TARGET_RECIPES.md` includes a validated GNU coreutils `base64` 9.4
  third-party CLI recipe.

## 7. Release packaging

Already implemented:

- `VERSION`
- `CHANGELOG.md`
- `docs/RELEASE_NOTES_v0.1.0-alpha.1.md`
- `docs/LIMITATIONS.md`
- `docs/AFLPP_MODE.md`

Next:

- Commit the release files and create the annotated git tag
  `v0.1.0-alpha.1`.
