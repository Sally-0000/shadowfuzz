# Changelog

## v0.1.0-alpha.1 - 2026-05-16

Initial public prototype release candidate.

### Added

- AFL++ forkserver-compatible `shadowfuzz-dbi` executor.
- DynamoRIO `shadowcov` client with AFL-style shared-memory coverage.
- Stable module-offset coverage IDs, main-module filtering, neverzero counters,
  n-gram context, hitcount buckets, and optional inline coverage updates.
- Comparison feedback for common string/memory APIs and x86 integer compares.
- Semantic oracles for dangerous shell APIs, path traversal, exec allowlists,
  sensitive environment access, network connect/send, destructive file
  mutation, and common credential file paths.
- Target policy files with sections, validation, repeated `--policy-file`
  layering, and relative `include=...` support.
- Experimental persistent harness protocol and reusable C helper.
- Harness templates for stdin CLIs, file-input CLIs, shared-object entrypoints,
  and plugin hosts.
- Smoke tests, forkserver self-tests, benchmark tooling, and local POC targets.

### Validated

- Full local `./smoke_test.sh` suite.
- GNU coreutils `base64` 9.4 third-party CLI parser recipe.
- Coverage-mode benchmark on `poc-branch-churn`.

### Known Limits

- This is an alpha backend prototype, not a production AFL++ mode.
- Generic arbitrary-binary persistent mode is not implemented.
- Performance is still dominated by per-testcase DynamoRIO startup outside the
  controlled persistent harness protocol.
