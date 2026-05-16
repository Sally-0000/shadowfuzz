# Known Limitations

This document is part of the `v0.1.0-alpha.1` release boundary.

## Backend Maturity

- `shadowfuzz-dbi` is forkserver-compatible enough for AFL++ integration, but
  it is not packaged as an upstream AFL++ mode.
- The executor still launches `drrun` for each testcase in the normal path.
  This keeps behavior simple and debuggable, but it is slower than QEMU mode,
  FRIDA mode, or a mature persistent DBI backend.
- The legacy `afl-shadow-trace` wrapper remains for debugging and comparison;
  new recipes should use `shadowfuzz-dbi`.

## Persistent Mode

- Persistent mode only supports harnesses that implement the
  `SHADOWFUZZ_PERSISTENT_IN_FD` / `SHADOWFUZZ_PERSISTENT_OUT_FD` protocol.
- The project does not yet auto-convert arbitrary closed-source binaries into
  persistent targets.
- Persistent coverage gating currently relies on the controlled harness
  contract and `SIGUSR1` / `SIGUSR2` reset hooks.

## Coverage And Feedback

- Default coverage is main-module focused. Use `--instrument-all` only when
  library coverage is required and the extra noise is acceptable.
- Inline coverage is implemented for the current roadmap scope, but larger
  targets still need benchmark-driven tuning.
- Comparison feedback covers common libc string/memory APIs and selected x86
  compare forms. It is not a drop-in equivalent to AFL++ CmpLog.
- Bitmap pressure has not been tuned against large real-world binaries.

## Semantic Oracles

- Oracles intentionally convert semantic events into aborts so AFL++ can triage
  them as crashes. This is useful for bug-class discovery, but it can create
  expected crashes if the policy is too broad.
- Path, network, environment, exec, and credential-file policies should be
  tuned per target.
- Network send allowlists match payload substrings. Treat them as pragmatic
  fuzzing controls, not a security policy engine.
- Credential-file matching is pattern based and intentionally conservative.

## Platform Scope

- The current implementation is Linux-focused.
- DynamoRIO 11.3.0 is the tested DBI runtime in this workspace.
- x86-specific comparison tracing is guarded by architecture checks; other
  architectures need dedicated work.

## Release Process

- `VERSION` records the intended release label.
- A git tag should be created only after committing release files. Tagging a
  dirty worktree would point at an older tree and misrepresent the release.
