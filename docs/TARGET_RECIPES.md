# Target Recipes

This file records repeatable harness recipes. The first recipes use local
validation targets so the harness templates can be tested without downloading
third-party code. Add third-party target notes here as they are validated.

## Third-Party CLI: GNU coreutils base64

Status: validated locally for the `v0.1.0-alpha.1` release prep.

Target:

```text
/usr/bin/base64
```

Version:

```text
base64 (GNU coreutils) 9.4
```

Harness template:

```text
CLI stdin
```

Policy:

```text
policies/base64.release.policy
```

The policy includes `policies/base.release.policy`, then disables semantic
oracles that are not useful for this simple decoder and pins the target module
to `base64`.

Direct validation:

```bash
./build/shadowfuzz-dbi --check /usr/bin/base64

printf 'QQ==\n' | ./build/shadowfuzz-dbi \
  --policy-file policies/base64.release.policy /usr/bin/base64 -d
```

Expected stdout from the second command:

```text
A
```

Short AFL++ validation:

```bash
AFL_NO_UI=1 ./run_afl.sh --inline-coverage -V 2 \
  -o /tmp/shadowfuzz-base64-afl /usr/bin/base64 -d
```

Observed local stats:

- AFL++ version: `++4.09c`
- runtime: 2 seconds
- executions: 57
- execs/sec: 25.92
- new corpus items: 5
- crashes: 0
- hangs: 0
- stability: 100.00%
- bitmap coverage: 0.52%

Notes:

- The default repository seeds are not base64-specific, so AFL++ warns that
  some test cases look useless. This is expected for the smoke recipe.
- A real campaign should use valid and invalid base64 seed examples and a small
  dictionary for base64 alphabet and padding tokens.

## Local Shared Object Entrypoint

Build:

```bash
cmake --build build
```

Harness target:

```text
build/harness-shared-object-entry
```

Library target:

```text
build/libpoc-shared-entry.so
```

Entrypoint symbol:

```text
target_entry
```

Direct validation:

```bash
printf 'safe\n' | ./build/shadowfuzz-dbi --inline-coverage \
  ./build/harness-shared-object-entry ./build/libpoc-shared-entry.so target_entry

printf 'SO!!' | ./build/shadowfuzz-dbi --inline-coverage \
  ./build/harness-shared-object-entry ./build/libpoc-shared-entry.so target_entry
```

Fuzzing command:

```bash
AFL_NO_UI=1 ./run_afl.sh --inline-coverage -V 10 \
  -o afl-out-so-entry ./build/harness-shared-object-entry \
  ./build/libpoc-shared-entry.so target_entry
```

Persistent fuzzing command:

```bash
AFL_NO_UI=1 ./run_afl.sh --persistent -V 10 \
  -o afl-out-so-entry-persistent ./build/harness-shared-object-entry \
  ./build/libpoc-shared-entry.so target_entry
```

## Local Plugin Host

Build:

```bash
cmake --build build
```

Harness target:

```text
build/harness-plugin-host
```

Plugin target:

```text
build/libpoc-plugin-target.so
```

Required plugin symbol:

```text
plugin_process
```

Optional plugin symbols:

```text
plugin_init
plugin_fini
```

Direct validation:

```bash
printf 'safe\n' | ./build/shadowfuzz-dbi --inline-coverage \
  ./build/harness-plugin-host ./build/libpoc-plugin-target.so

printf 'PLG!' | ./build/shadowfuzz-dbi --inline-coverage \
  ./build/harness-plugin-host ./build/libpoc-plugin-target.so
```

Fuzzing command:

```bash
AFL_NO_UI=1 ./run_afl.sh --inline-coverage -V 10 \
  -o afl-out-plugin-host ./build/harness-plugin-host \
  ./build/libpoc-plugin-target.so
```

Persistent fuzzing command:

```bash
AFL_NO_UI=1 ./run_afl.sh --persistent -V 10 \
  -o afl-out-plugin-host-persistent ./build/harness-plugin-host \
  ./build/libpoc-plugin-target.so
```

## Adding A Third-Party Recipe

For each validated third-party target, record:

- target version and build flags
- harness template used
- exact `run_afl.sh` command
- policy file path, if a reusable policy is used
- dictionary path, if any
- enabled semantic oracles
- target-specific allowlists such as `--path-allowlist`,
  `--network-allowlist`, `--env-allowlist`, and `--exec-allowlist`
- whether `--path-allowlist` is also allowing expected credential-like
  fixture paths when `--abort-on-credential-file` is enabled
- known expected crashes or false positives
- any required environment variables
