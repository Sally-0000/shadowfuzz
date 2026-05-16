#!/usr/bin/env python3

import ctypes
import os
import select
import signal
import struct
import sys


AFL_FORKSRV_FD = 198
IPC_PRIVATE = 0
IPC_CREAT = 0o1000
IPC_RMID = 0
DEFAULT_MAP_SIZE = 1 << 16


class SysvShm:
    def __init__(self, size: int) -> None:
        self.size = size
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
        self.libc.shmget.restype = ctypes.c_int
        self.libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self.libc.shmat.restype = ctypes.c_void_p
        self.libc.shmdt.argtypes = [ctypes.c_void_p]
        self.libc.shmdt.restype = ctypes.c_int
        self.libc.shmctl.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
        ]
        self.libc.shmctl.restype = ctypes.c_int

        self.shm_id = self.libc.shmget(IPC_PRIVATE, size, IPC_CREAT | 0o600)
        if self.shm_id < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))

        self.ptr = self.libc.shmat(self.shm_id, None, 0)
        if self.ptr == ctypes.c_void_p(-1).value:
            err = ctypes.get_errno()
            self.remove()
            raise OSError(err, os.strerror(err))

        ctypes.memset(self.ptr, 0, size)

    def bytes(self) -> bytes:
        return ctypes.string_at(self.ptr, self.size)

    def close(self) -> None:
        if getattr(self, "ptr", None):
            self.libc.shmdt(self.ptr)
            self.ptr = None

    def remove(self) -> None:
        if getattr(self, "shm_id", -1) >= 0:
            self.libc.shmctl(self.shm_id, IPC_RMID, None)
            self.shm_id = -1

    def cleanup(self) -> None:
        self.close()
        self.remove()


def main() -> int:
    expect_signal = None
    expect_exit = None
    stdin_data = None
    kill_after_pid = False
    pid_timeout_ms = 1000
    expect_coverage = False
    shm_map_size = 0
    argv = sys.argv[1:]

    while argv and argv[0].startswith("--"):
        option = argv[0]
        if option == "--expect-coverage":
            expect_coverage = True
            if shm_map_size == 0:
                shm_map_size = DEFAULT_MAP_SIZE
            argv = argv[1:]
        elif option == "--afl-shm-map-size":
            if len(argv) < 2:
                print("forkserver-selftest: --afl-shm-map-size requires a value", file=sys.stderr)
                return 1
            try:
                shm_map_size = int(argv[1], 0)
            except ValueError:
                print(f"forkserver-selftest: invalid shm map size {argv[1]}", file=sys.stderr)
                return 1
            argv = argv[2:]
        elif option == "--kill-after-pid":
            kill_after_pid = True
            argv = argv[1:]
        elif option == "--pid-timeout-ms":
            if len(argv) < 2:
                print("forkserver-selftest: --pid-timeout-ms requires a value", file=sys.stderr)
                return 1
            try:
                pid_timeout_ms = int(argv[1], 0)
            except ValueError:
                print(f"forkserver-selftest: invalid pid timeout {argv[1]}", file=sys.stderr)
                return 1
            argv = argv[2:]
        elif option == "--expect-signal":
            if len(argv) < 2:
                print("forkserver-selftest: --expect-signal requires a value", file=sys.stderr)
                return 1
            try:
                expect_signal = getattr(signal, argv[1])
            except AttributeError:
                print(f"forkserver-selftest: unknown signal {argv[1]}", file=sys.stderr)
                return 1
            argv = argv[2:]
        elif option == "--expect-exit":
            if len(argv) < 2:
                print("forkserver-selftest: --expect-exit requires a value", file=sys.stderr)
                return 1
            try:
                expect_exit = int(argv[1], 0)
            except ValueError:
                print(f"forkserver-selftest: invalid exit code {argv[1]}", file=sys.stderr)
                return 1
            argv = argv[2:]
        elif option == "--stdin":
            if len(argv) < 2:
                print("forkserver-selftest: --stdin requires a value", file=sys.stderr)
                return 1
            stdin_data = argv[1].encode()
            argv = argv[2:]
        else:
            print(f"forkserver-selftest: unknown option {option}", file=sys.stderr)
            return 1

    if len(argv) < 1:
        print(
            "usage: forkserver_selftest.py [--expect-signal SIGABRT] [--expect-exit N] "
            "[--expect-coverage] [--afl-shm-map-size N] "
            "[--kill-after-pid] [--pid-timeout-ms N] "
            "[--stdin DATA] "
            "/path/to/shadowfuzz-dbi [target args...]",
            file=sys.stderr,
        )
        return 1

    if shm_map_size < 0 or (shm_map_size > 0 and shm_map_size & (shm_map_size - 1)):
        print("forkserver-selftest: shm map size must be a power of two", file=sys.stderr)
        return 1
    if expect_coverage and shm_map_size == 0:
        shm_map_size = DEFAULT_MAP_SIZE

    shm = None
    if shm_map_size > 0:
        try:
            shm = SysvShm(shm_map_size)
        except OSError as exc:
            print(f"forkserver-selftest: failed to create shm: {exc}", file=sys.stderr)
            return 1
        os.environ["__AFL_SHM_ID"] = str(shm.shm_id)
        os.environ["SHADOWCOV_MAP_SIZE"] = str(shm_map_size)

    ctl_read, ctl_write = os.pipe()
    st_read, st_write = os.pipe()
    stdin_read, stdin_write = os.pipe()

    def preexec() -> None:
        os.dup2(stdin_read, 0)
        os.dup2(ctl_read, AFL_FORKSRV_FD)
        os.dup2(st_write, AFL_FORKSRV_FD + 1)
        os.set_inheritable(0, True)
        os.set_inheritable(AFL_FORKSRV_FD, True)
        os.set_inheritable(AFL_FORKSRV_FD + 1, True)
        os.close(stdin_write)
        os.close(ctl_write)
        os.close(st_read)

    pid = os.fork()
    if pid == 0:
        preexec()
        os.execv(argv[0], argv)
        os._exit(127)

    os.close(ctl_read)
    os.close(st_write)
    os.close(stdin_read)

    handshake = os.read(st_read, 4)
    if len(handshake) != 4:
        print("forkserver-selftest: missing handshake", file=sys.stderr)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        if shm is not None:
            shm.cleanup()
        return 1

    os.write(ctl_write, struct.pack("<I", 0))
    if stdin_data is not None:
        os.write(stdin_write, stdin_data)
    os.close(stdin_write)

    ready, _, _ = select.select([st_read], [], [], pid_timeout_ms / 1000.0)
    if not ready:
        print("forkserver-selftest: timed out waiting for child pid", file=sys.stderr)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        if shm is not None:
            shm.cleanup()
        return 1

    child_pid_raw = os.read(st_read, 4)
    if len(child_pid_raw) != 4:
        print("forkserver-selftest: incomplete child pid response", file=sys.stderr)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        if shm is not None:
            shm.cleanup()
        return 1

    child_pid = struct.unpack("<I", child_pid_raw)[0]
    if child_pid <= 0:
        print(f"forkserver-selftest: invalid child pid {child_pid}", file=sys.stderr)
        if shm is not None:
            shm.cleanup()
        return 1

    if kill_after_pid:
        os.kill(child_pid, signal.SIGKILL)

    status_raw = os.read(st_read, 4)

    os.close(ctl_write)
    os.close(st_read)

    os.waitpid(pid, 0)

    if len(child_pid_raw) != 4 or len(status_raw) != 4:
        print("forkserver-selftest: incomplete forkserver response", file=sys.stderr)
        if shm is not None:
            shm.cleanup()
        return 1

    status = struct.unpack("<I", status_raw)[0]

    if expect_signal is not None:
        if not os.WIFSIGNALED(status):
            print("forkserver-selftest: expected signaled child status", file=sys.stderr)
            if shm is not None:
                shm.cleanup()
            return 1
        sig = os.WTERMSIG(status)
        if sig != expect_signal:
            print(
                f"forkserver-selftest: expected signal {expect_signal.name}, got {signal.Signals(sig).name}",
                file=sys.stderr,
            )
            if shm is not None:
                shm.cleanup()
            return 1
        if expect_coverage and shm is not None and not any(shm.bytes()):
            print("forkserver-selftest: expected non-empty coverage bitmap", file=sys.stderr)
            shm.cleanup()
            return 1
        if shm is not None:
            shm.cleanup()
        print(f"forkserver-selftest: ok pid={child_pid} signal={signal.Signals(sig).name}")
        return 0

    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        print(f"forkserver-selftest: child signaled with {signal.Signals(sig).name}", file=sys.stderr)
        if shm is not None:
            shm.cleanup()
        return 1

    if not os.WIFEXITED(status):
        print(f"forkserver-selftest: unexpected wait status {status}", file=sys.stderr)
        if shm is not None:
            shm.cleanup()
        return 1

    exit_code = os.WEXITSTATUS(status)
    if expect_exit is not None and exit_code != expect_exit:
        print(
            f"forkserver-selftest: expected exit {expect_exit}, got {exit_code}",
            file=sys.stderr,
        )
        if shm is not None:
            shm.cleanup()
        return 1
    if expect_coverage and shm is not None and not any(shm.bytes()):
        print("forkserver-selftest: expected non-empty coverage bitmap", file=sys.stderr)
        shm.cleanup()
        return 1
    if shm is not None:
        shm.cleanup()
    print(f"forkserver-selftest: ok pid={child_pid} exit={exit_code}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
