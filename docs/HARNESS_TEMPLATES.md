# Harness Templates

These templates are starting points for running real targets under
`shadowfuzz-dbi`. AFL++ still owns mutation, queue management, and crash
triage; the harness only adapts testcase bytes into the target's expected input
shape.

## CLI Parser

Use this when the target already reads from stdin:

```bash
AFL_NO_UI=1 ./run_afl.sh --inline-coverage -V 60 \
  /path/to/cli-target --target-option
```

If a wrapper is useful for setting environment variables or fixed argv, start
from:

```bash
templates/cli_stdin_harness.sh /path/to/cli-target --target-option
```

## File Parser

Use this when the target expects a file path. `run_afl.sh --file` appends `@@`
when the command does not already contain it:

```bash
AFL_NO_UI=1 ./run_afl.sh --file --inline-coverage -V 60 \
  /path/to/file-parser @@ --strict
```

The matching shell template is:

```bash
templates/file_input_harness.sh /path/to/file-parser @@ --strict
```

## Closed-Source Shared Object Entry Point

When a closed-source `.so` exposes a stable entrypoint, compile the generic
entrypoint harness:

```bash
cc -O2 -Wall -Wextra -o build/so-entry-harness \
  templates/shared_object_entry_harness.c -ldl
```

The target symbol must have this shape:

```c
int entry_symbol(const uint8_t *data, size_t size);
```

Run it with stdin testcase input:

```bash
AFL_NO_UI=1 ./run_afl.sh --inline-coverage -V 60 \
  ./build/so-entry-harness /path/to/library.so entry_symbol
```

The same harness also supports the experimental persistent protocol:

```bash
AFL_NO_UI=1 ./run_afl.sh --persistent -V 60 \
  ./build/so-entry-harness /path/to/library.so entry_symbol
```

When `--persistent` is used, `shadowfuzz-dbi` passes
`SHADOWFUZZ_PERSISTENT_IN_FD` and `SHADOWFUZZ_PERSISTENT_OUT_FD` to the
harness. The template loops on those fds, opens coverage only around
`entry_symbol(data, size)` with `SIGUSR1` / `SIGUSR2`, and returns a wait-status
encoded per-iteration result to AFL++.

## Plugin Host

Use the plugin host template when plugins follow this shape:

```c
int plugin_init(void);                         /* optional */
int plugin_process(const uint8_t *data, size_t size);
void plugin_fini(void);                        /* optional */
```

Build and run:

```bash
cc -O2 -Wall -Wextra -o build/plugin-host-harness \
  templates/plugin_host_harness.c -ldl

AFL_NO_UI=1 ./run_afl.sh --inline-coverage -V 60 \
  ./build/plugin-host-harness /path/to/plugin.so
```

Persistent mode is available for the same plugin ABI:

```bash
AFL_NO_UI=1 ./run_afl.sh --persistent -V 60 \
  ./build/plugin-host-harness /path/to/plugin.so
```

`plugin_init()` runs once before the persistent loop, `plugin_process()` runs
once per testcase, and `plugin_fini()` runs when the loop exits. If the plugin
crashes during `plugin_process()`, the executor reports that real process
signal to AFL++ and starts a fresh persistent child on the next command.

## Persistent Harness Helper

C harnesses can reuse:

```c
#include "shadowfuzz_persistent.h"
```

The helper exposes `shadowfuzz_maybe_run_persistent(callback, user_data)`.
It returns `-1` when the process was not launched in persistent mode, so the
harness can fall back to its normal one-shot stdin path. In persistent mode it
owns testcase transport, coverage gating, and wait-status result encoding.

## Oracle Selection

Enable semantic oracles only when they match the target and the expected
behavior:

```bash
./run_afl.sh --abort-on-dangerous-api ...
./run_afl.sh --abort-on-path-traversal ...
./run_afl.sh --abort-on-file-mutation ...
./run_afl.sh --abort-on-network ...
./run_afl.sh --abort-on-env-access ...
./run_afl.sh --abort-on-credential-file ...
```

For real targets, prefer starting with coverage-only runs, then add one oracle
at a time so crash meaning stays clear.

When a target has known-safe resources, keep the oracle enabled and add a
target-specific allowlist instead of disabling the oracle:

```bash
./run_afl.sh --abort-on-path-traversal \
  --path-allowlist ./fixtures,/tmp/target-work ...

./run_afl.sh --abort-on-network \
  --network-allowlist 127.0.0.1,203.0.113.10,metadata.test.local ...

./run_afl.sh --abort-on-env-access \
  --env-allowlist PATH,AWS_REGION ...

./run_afl.sh --abort-on-credential-file \
  --path-allowlist ./fixtures,/tmp/target-work ...
```

Path allowlists are prefix matches. Network allowlists match `connect()` IP
prefixes and `send` / `sendto` payload substrings. Env allowlists are exact
environment variable name matches.

For repeatable real-target runs, move stable oracle choices into a policy file:

```bash
./run_afl.sh --policy-file policies/oracles.example.policy ...
```

Policy files use `key=value` lines with `#` comments. They can also group
settings under `[oracles]`, `[allowlists]`, `[coverage]`, and `[target]`.
The parser rejects unknown sections, unknown keys, empty string values, and
invalid `ngram` values. Later CLI flags override earlier policy defaults, so
target recipes can keep the baseline policy stable and override one field for a
specific experiment.

Policies can be layered either by repeating `--policy-file` or by adding a
root-level include:

```bash
./run_afl.sh --policy-file policies/base.release.policy \
  --policy-file policies/base64.release.policy ...
```

```ini
include=base.release.policy

[target]
module=base64
```
