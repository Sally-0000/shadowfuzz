# shadowfuzz

`shadowfuzz` is an experimental AFL++-compatible DBI execution backend for
Linux binaries. It runs targets under DynamoRIO, collects AFL-style coverage,
writes feedback into AFL++ shared memory, and adds optional comparison feedback
and semantic oracles for bug classes that do not naturally crash.

Current release: `v0.1.0-alpha.1`

## What It Provides

- AFL++ forkserver-compatible executor: `build/shadowfuzz-dbi`
- DynamoRIO coverage client: `build/libshadowcov.so`
- AFL shared-memory bitmap support
- inline coverage, hitcount buckets, n-gram context, and neverzero counters
- comparison tracing for common string/memory APIs and selected x86 compares
- semantic oracles for shell APIs, path traversal, exec paths, sensitive
  environment access, network activity, file mutation, and credential paths
- target policy files with sectioned schema, validation, layering, and
  `include=...`
- experimental persistent harness protocol
- harness templates for stdin CLIs, file-input CLIs, shared-object entrypoints,
  and plugin hosts

This is an alpha backend prototype, not an upstream AFL++ mode yet. See
the "Current Limits" section for the current boundaries.

## Build

The default build expects a DynamoRIO SDK at:

```text
third_party/DynamoRIO-Linux-11.3.0-1/cmake
```

Override it when needed:

```bash
cmake -S . -B build \
  -DSHADOWFUZZ_DYNAMORIO_DIR=/path/to/dynamorio/cmake
cmake --build build
```

Run the smoke suite:

```bash
./smoke_test.sh
```

## Run A Target Directly

Use `shadowfuzz-dbi` for normal testing:

```bash
./build/shadowfuzz-dbi ./target [args...]
```

Useful options:

```bash
./build/shadowfuzz-dbi --check ./target
./build/shadowfuzz-dbi --inline-coverage ./target
./build/shadowfuzz-dbi --trace-cmp ./target
./build/shadowfuzz-dbi --ngram 4 ./target
./build/shadowfuzz-dbi --hitcount-buckets ./target
./build/shadowfuzz-dbi --policy-file policies/oracles.example.policy ./target
```

Standalone DynamoRIO coverage is also available for debugging:

```bash
./run.sh ./target
```

Without AFL++ shared memory, standalone mode writes `coverage.map` in the
current directory.

## Run With AFL++

The recommended AFL++ entry is:

```bash
AFL_SKIP_BIN_CHECK=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
afl-fuzz -i seeds -o afl-out -- ./build/shadowfuzz-dbi ./target
```

The helper script wraps the same model:

```bash
AFL_NO_UI=1 ./run_afl.sh -V 60 -o afl-out ./target
```

For file-input targets:

```bash
AFL_NO_UI=1 ./run_afl.sh --file -V 60 -o afl-out-file ./target @@
```

## Semantic Oracles

Enable oracles only when they match the target and the campaign goal:

```bash
./run_afl.sh --abort-on-dangerous-api ./target
./run_afl.sh --abort-on-path-traversal ./target
./run_afl.sh --abort-on-credential-file ./target
./run_afl.sh --abort-on-exec --exec-allowlist true,echo ./target
./run_afl.sh --abort-on-env-access --env-allowlist PATH,AWS_REGION ./target
./run_afl.sh --abort-on-network --network-allowlist 127.0.0.1 ./target
./run_afl.sh --abort-on-file-mutation ./target
```

These oracles turn selected semantic events into aborts so AFL++ can save them
as findings. Target-specific allowlists are expected for real software.

## Policy Files

Policy files store repeatable target defaults:

```ini
include=base.release.policy

[oracles]
dangerous_api=true
path_traversal=true
network=true

[allowlists]
path=./fixtures,/tmp/target-work
network=127.0.0.1,203.0.113.

[coverage]
trace_cmp=true
hitcount_buckets=true
ngram=2

[target]
module=target-binary
```

Use one or more policies in order:

```bash
./run_afl.sh \
  --policy-file policies/base.release.policy \
  --policy-file policies/base64.release.policy \
  /usr/bin/base64 -d
```

Later policy values override earlier values. CLI flags after a policy override
policy defaults.

## Persistent Harnesses

Persistent mode requires a harness that implements the shadowfuzz protocol:

```bash
AFL_NO_UI=1 ./run_afl.sh --persistent -V 60 \
  ./build/harness-shared-object-entry /path/to/libtarget.so entry_symbol
```

Supported templates:

- `templates/shared_object_entry_harness.c`
- `templates/plugin_host_harness.c`
- `templates/shadowfuzz_persistent.h`

Generic arbitrary-binary persistent mode is not implemented.

## Examples

Stack overflow POC:

```bash
AFL_NO_UI=1 ./run_afl.sh -V 5 -o afl-out-stack ./build/poc-stack-overflow
```

Format string POC:

```bash
AFL_NO_UI=1 ./run_afl.sh -V 10 -x dicts/format.dict \
  -o afl-out-format ./build/poc-format-string
```

Command injection oracle POC:

```bash
AFL_NO_UI=1 ./run_afl.sh --abort-on-dangerous-api -V 10 \
  -x dicts/cmdi.dict -o afl-out-cmdi-hook ./build/poc-command-system
```

Third-party CLI recipe:

```bash
printf 'QQ==\n' | ./build/shadowfuzz-dbi \
  --policy-file policies/base64.release.policy /usr/bin/base64 -d
```

Expected output:

```text
A
```

## Current Limits

- This is an alpha prototype, not a packaged upstream AFL++ mode.
- Normal mode still starts DynamoRIO for each testcase, so throughput is lower
  than mature persistent instrumentation modes.
- Generic arbitrary-binary persistent mode is not implemented; persistent mode
  requires a compatible harness.
- Semantic oracles are intentionally pattern and policy based. Tune allowlists
  per target to avoid expected crashes.


## Release

After committing release files:

```bash
git tag -a v0.1.0-alpha.1 -m "shadowfuzz v0.1.0-alpha.1"
git push origin main
git push origin v0.1.0-alpha.1
```
