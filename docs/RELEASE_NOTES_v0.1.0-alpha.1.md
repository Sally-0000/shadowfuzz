# shadowfuzz v0.1.0-alpha.1 Release Notes

Date: 2026-05-16

This release is a working AFL++-compatible DBI backend prototype for Linux
binaries. It is suitable for local experimentation, recipe development, and
continued backend engineering. It should not be presented as a production-ready
AFL++ mode yet.

## Release Identity

- Version file: `VERSION`
- Release label: `v0.1.0-alpha.1`
- Current source baseline when prepared: `7e0a9b5`
- Suggested git tag after committing release files:

```bash
git tag -a v0.1.0-alpha.1 -m "shadowfuzz v0.1.0-alpha.1"
```

Do not create the tag before committing these release files; otherwise the tag
will point at an older tree.

## Highlights

- AFL++ forkserver-compatible `shadowfuzz-dbi` executor.
- DynamoRIO coverage backend with AFL shared-memory bitmap support.
- Inline coverage, hitcount buckets, n-gram context, and neverzero counters.
- String/memory API comparison feedback and x86 integer compare tracing.
- Semantic oracles for shell command injection, path traversal, exec paths,
  sensitive environment access, network activity, file mutation, and credential
  file access.
- Target policy files with sectioned schema validation, repeated
  `--policy-file` layering, and relative `include=...` composition.
- Experimental persistent harness protocol for controlled harnesses.
- Harness templates for CLI stdin, file input, `.so` entrypoints, and plugin
  hosts.
- Local smoke suite and benchmark tooling.

## Validation

The following commands passed on the release-prep machine:

```bash
cmake --build build
./smoke_test.sh
tools/bench_shadowcov.py --iterations 5 --warmups 1 \
  --json-out /tmp/shadowfuzz_bench.json --target build/poc-branch-churn
printf 'QQ==\n' | ./build/shadowfuzz-dbi \
  --policy-file policies/base64.release.policy /usr/bin/base64 -d
AFL_NO_UI=1 ./run_afl.sh --inline-coverage -V 2 \
  -o /tmp/shadowfuzz-base64-afl /usr/bin/base64 -d
```

The base64 AFL++ smoke run used GNU coreutils `base64` 9.4 and completed with
57 executions, 5 new corpus items, 0 crashes, 0 hangs, and 100.00% stability.

## Known Limits

See `docs/LIMITATIONS.md` for the detailed list. The important release-level
limits are:

- generic arbitrary-binary persistent mode is not implemented;
- per-testcase `drrun` startup is still expensive outside controlled
  persistent harnesses;
- comparison feedback is useful but not a full AFL++ CmpLog replacement;
- semantic oracles need target-specific policy tuning to avoid false positives.
