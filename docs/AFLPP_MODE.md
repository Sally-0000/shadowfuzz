# AFL++ Mode Notes

`shadowfuzz` is designed as an AFL++ execution backend, not as a standalone
fuzzer. AFL++ owns mutation, scheduling, corpus management, crash triage,
timeouts, and UI. `shadowfuzz-dbi` owns target execution under DynamoRIO and
writes feedback into AFL++ shared memory.

## Recommended Entry

Use `shadowfuzz-dbi` directly under AFL++:

```bash
AFL_SKIP_BIN_CHECK=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
afl-fuzz -i seeds -o afl-out -- ./build/shadowfuzz-dbi ./target
```

The helper script wraps the same model:

```bash
AFL_NO_UI=1 ./run_afl.sh -V 60 -o afl-out ./target
```

## Data Flow

```text
afl-fuzz
  -> shadowfuzz-dbi
    -> drrun
      -> libshadowcov.so
        -> target binary
        -> AFL++ shared memory bitmap
```

`shadowfuzz-dbi` implements the forkserver control surface expected by AFL++.
For each testcase, it starts the target under DynamoRIO, relays stdin or `@@`
file input, and reports the child wait status back to AFL++.

## Current Mode Status

Implemented:

- forkserver handshake;
- shared-memory coverage via `__AFL_SHM_ID` / `AFL_SHM_ID`;
- stdin and file-input target modes;
- crash signal propagation;
- direct-run mode for local debugging;
- policy files and semantic oracle configuration;
- experimental persistent harness mode.

Not yet implemented:

- upstream AFL++ mode packaging;
- generic persistent conversion for arbitrary binaries;
- full AFL++ CmpLog compatibility;
- automatic target library discovery and symbol selection.

## Persistent Harness Mode

For harnesses that implement the shadowfuzz persistent protocol:

```bash
AFL_NO_UI=1 ./run_afl.sh --persistent -V 60 \
  ./build/harness-shared-object-entry /path/to/libtarget.so entry_symbol
```

The harness receives testcase bytes over
`SHADOWFUZZ_PERSISTENT_IN_FD` / `SHADOWFUZZ_PERSISTENT_OUT_FD`. It gates
coverage around target logic with `SIGUSR1` and `SIGUSR2`, then returns an
encoded wait status for each iteration.

## Policy Layering

Multiple policies may be passed. They are applied in command-line order:

```bash
./run_afl.sh \
  --policy-file policies/base.release.policy \
  --policy-file policies/base64.release.policy \
  /usr/bin/base64 -d
```

Policies may also include another policy with a relative path:

```ini
include=base.release.policy

[target]
module=base64
```

Later values override earlier values. CLI flags after a policy override policy
defaults.
