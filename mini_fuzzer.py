#!/usr/bin/env python3

import argparse
import os
import random
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


DEFAULT_MAP_SIZE = 1 << 16
DEFAULT_SEED = b"fuzz\n"
INTERESTING_BYTES = [
    0x00,
    0x0A,
    0x20,
    0x30,
    0x31,
    0x41,
    0x42,
    0x43,
    0x44,
    0x61,
    0x62,
    0x63,
    0x64,
    0x7F,
    0x80,
    0xFF,
]
CRASH_SIGNALS = {
    signal.SIGSEGV,
    signal.SIGABRT,
    signal.SIGILL,
    signal.SIGFPE,
    signal.SIGBUS,
    signal.SIGTRAP,
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Minimal coverage-guided fuzzer prototype for shadowcov"
    )
    parser.add_argument(
        "--cmd",
        required=True,
        help="Command template used to run the target, e.g. './run.sh ./target @@'",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Feed mutated input via stdin instead of replacing @@ in --cmd",
    )
    parser.add_argument(
        "--seeds",
        default="seeds",
        help="Seed directory. If missing or empty, a default seed is created.",
    )
    parser.add_argument(
        "--out",
        default="findings",
        help="Output directory for queue, crashes, hangs, and stats.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Number of fuzz iterations to execute.",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=1000,
        help="Per-execution timeout in milliseconds.",
    )
    parser.add_argument(
        "--max-len",
        type=int,
        default=4096,
        help="Maximum mutated input length.",
    )
    parser.add_argument(
        "--map-size",
        type=int,
        default=DEFAULT_MAP_SIZE,
        help="Coverage bitmap size. Must match SHADOWCOV_MAP_SIZE.",
    )
    parser.add_argument(
        "--keep-timeouts",
        action="store_true",
        help="Save timeout-inducing inputs under hangs/.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-iteration execution details.",
    )
    return parser.parse_args()


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def ensure_seed_corpus(seed_dir: Path):
    ensure_dir(seed_dir)
    seeds = sorted(p for p in seed_dir.iterdir() if p.is_file())
    if seeds:
        return [(p.read_bytes(), p.name) for p in seeds]

    seed_path = seed_dir / "seed0"
    seed_path.write_bytes(DEFAULT_SEED)
    return [(DEFAULT_SEED, seed_path.name)]


def rand_byte():
    return random.randrange(256)


def rand_interesting_byte():
    if random.random() < 0.7:
        return random.choice(INTERESTING_BYTES)
    return rand_byte()


def mutate(data: bytes, max_len: int) -> bytes:
    buf = bytearray(data if data else DEFAULT_SEED)
    mutation_count = random.randint(1, 8)

    for _ in range(mutation_count):
        if not buf:
            buf.append(rand_byte())
            continue

        op = random.choice(
            [
                "flip_bit",
                "set_byte",
                "insert_byte",
                "delete_byte",
                "clone_chunk",
                "overwrite_chunk",
            ]
        )

        if op == "flip_bit":
            idx = random.randrange(len(buf))
            bit = 1 << random.randrange(8)
            buf[idx] ^= bit
        elif op == "set_byte":
            idx = random.randrange(len(buf))
            buf[idx] = rand_interesting_byte()
        elif op == "insert_byte":
            if len(buf) < max_len:
                idx = random.randrange(len(buf) + 1)
                buf[idx:idx] = bytes([rand_interesting_byte()])
        elif op == "delete_byte":
            if len(buf) > 1:
                idx = random.randrange(len(buf))
                del buf[idx]
        elif op == "clone_chunk":
            if len(buf) < max_len:
                start = random.randrange(len(buf))
                end = min(len(buf), start + random.randint(1, 16))
                chunk = buf[start:end]
                insert_at = random.randrange(len(buf) + 1)
                space = max_len - len(buf)
                buf[insert_at:insert_at] = chunk[:space]
        elif op == "overwrite_chunk":
            start = random.randrange(len(buf))
            width = min(len(buf) - start, random.randint(1, 16))
            for i in range(width):
                buf[start + i] = rand_interesting_byte()

    if len(buf) > max_len:
        del buf[max_len:]
    if not buf:
        buf.append(0)
    return bytes(buf)


def build_command(cmd_template: str, input_path: Path | None):
    argv = shlex.split(cmd_template)
    if input_path is not None:
        argv = [str(input_path) if token == "@@" else token for token in argv]
    return argv


def classify_crash(returncode: int):
    if returncode >= 0:
        return False, ""
    sig = -returncode
    if sig in CRASH_SIGNALS:
        try:
            name = signal.Signals(sig).name
        except ValueError:
            name = f"SIG{sig}"
        return True, name
    return False, ""


def load_bitmap(bitmap_path: Path, expected_size: int):
    data = bitmap_path.read_bytes()
    if len(data) != expected_size:
        raise ValueError(
            f"unexpected bitmap size {len(data)}, expected {expected_size}"
        )
    return data


def save_artifact(directory: Path, prefix: str, iteration: int, data: bytes):
    path = directory / f"{prefix}_{iteration:06d}"
    path.write_bytes(data)
    return path


def main():
    args = parse_args()

    if args.stdin and "@@" in args.cmd:
        print("error: choose either --stdin or @@ placeholder, not both", file=sys.stderr)
        return 2
    if not args.stdin and "@@" not in args.cmd:
        print("error: --cmd must contain @@ unless --stdin is used", file=sys.stderr)
        return 2
    if args.map_size <= 0 or args.map_size & (args.map_size - 1):
        print("error: --map-size must be a power of two", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    queue_dir = out_dir / "queue"
    crash_dir = out_dir / "crashes"
    hang_dir = out_dir / "hangs"
    stats_path = out_dir / "stats.txt"
    for path in (out_dir, queue_dir, crash_dir, hang_dir):
        ensure_dir(path)

    corpus = ensure_seed_corpus(Path(args.seeds))
    for idx, (seed_bytes, seed_name) in enumerate(corpus):
        (queue_dir / f"id_{idx:06d}_{seed_name}").write_bytes(seed_bytes)

    virgin_map = bytearray(args.map_size)
    total_execs = 0
    total_crashes = 0
    total_hangs = 0
    total_saved = len(corpus)
    start = time.time()

    with tempfile.TemporaryDirectory(prefix="shadowfuzz-") as tmpdir:
        tmpdir_path = Path(tmpdir)
        input_path = tmpdir_path / "input.bin"
        bitmap_path = tmpdir_path / "coverage.map"

        for iteration in range(args.iterations):
            parent_data, parent_name = random.choice(corpus)
            mutated = mutate(parent_data, args.max_len)

            if not args.stdin:
                input_path.write_bytes(mutated)
                cmd = build_command(args.cmd, input_path)
                stdin_data = None
            else:
                cmd = build_command(args.cmd, None)
                stdin_data = mutated

            env = os.environ.copy()
            env["SHADOWCOV_BITMAP_OUT"] = str(bitmap_path)
            env["SHADOWCOV_MAP_SIZE"] = str(args.map_size)

            if bitmap_path.exists():
                bitmap_path.unlink()

            try:
                proc = subprocess.run(
                    cmd,
                    input=stdin_data,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    timeout=args.timeout_ms / 1000.0,
                )
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                proc = None

            total_execs += 1

            if timed_out:
                total_hangs += 1
                if args.keep_timeouts:
                    save_artifact(hang_dir, "hang", iteration, mutated)
                outcome = "timeout"
                new_edges = 0
            else:
                if not bitmap_path.exists():
                    print(
                        f"error: target run did not produce bitmap at {bitmap_path}",
                        file=sys.stderr,
                    )
                    return 1

                bitmap = load_bitmap(bitmap_path, args.map_size)
                new_edge_indexes = [
                    idx for idx, value in enumerate(bitmap) if value and not virgin_map[idx]
                ]
                new_edges = len(new_edge_indexes)
                for idx in new_edge_indexes:
                    virgin_map[idx] = 1

                is_crash, signal_name = classify_crash(proc.returncode)
                if is_crash:
                    total_crashes += 1
                    save_artifact(crash_dir, f"crash_{signal_name.lower()}", iteration, mutated)
                    outcome = f"crash:{signal_name}"
                elif new_edges > 0:
                    name = f"id_{total_saved:06d}_iter_{iteration:06d}"
                    (queue_dir / name).write_bytes(mutated)
                    corpus.append((mutated, name))
                    total_saved += 1
                    outcome = "new"
                else:
                    outcome = "old"

            if args.verbose or iteration % 50 == 0 or outcome in ("new", "timeout") or outcome.startswith("crash:"):
                elapsed = max(time.time() - start, 0.001)
                execs_per_sec = total_execs / elapsed
                print(
                    f"[{iteration + 1}/{args.iterations}] "
                    f"parent={parent_name} len={len(mutated)} outcome={outcome} "
                    f"new_edges={new_edges} corpus={len(corpus)} "
                    f"execs={total_execs} exec/s={execs_per_sec:.1f}"
                )

    elapsed = max(time.time() - start, 0.001)
    unique_edges = sum(1 for value in virgin_map if value)
    summary = [
        f"execs={total_execs}",
        f"execs_per_sec={total_execs / elapsed:.2f}",
        f"saved_inputs={total_saved}",
        f"queue_size={len(corpus)}",
        f"unique_edges={unique_edges}",
        f"crashes={total_crashes}",
        f"timeouts={total_hangs}",
        f"elapsed_sec={elapsed:.2f}",
    ]
    stats_path.write_text("\n".join(summary) + "\n", encoding="utf-8")

    print("=== mini_fuzzer summary ===")
    for line in summary:
        print(line)
    print(f"artifacts={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
