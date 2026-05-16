#!/usr/bin/env python3
import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path


CONFIGS = {
    "clean": [],
    "inline": ["--inline-coverage"],
    "bucket": ["--hitcount-buckets"],
    "inline_bucket": ["--inline-coverage", "--hitcount-buckets"],
    "ngram4": ["--ngram", "4"],
    "inline_ngram4": ["--inline-coverage", "--ngram", "4"],
    "ngram4_bucket": ["--ngram", "4", "--hitcount-buckets"],
    "inline_ngram4_bucket": ["--inline-coverage", "--ngram", "4", "--hitcount-buckets"],
}


def run_once(executor, target, config_args, stdin_data, timeout):
    start = time.perf_counter()
    completed = subprocess.run(
        [str(executor), *config_args, str(target)],
        input=stdin_data,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )
    elapsed = time.perf_counter() - start
    return completed.returncode, elapsed


def bench_config(name, executor, target, stdin_data, iterations, warmups, timeout):
    config_args = CONFIGS[name]
    for _ in range(warmups):
        rc, _ = run_once(executor, target, config_args, stdin_data, timeout)
        if rc != 0:
            raise RuntimeError(f"{name}: warmup exited with {rc}")

    samples = []
    for _ in range(iterations):
        rc, elapsed = run_once(executor, target, config_args, stdin_data, timeout)
        if rc != 0:
            raise RuntimeError(f"{name}: benchmark exited with {rc}")
        samples.append(elapsed)

    return {
        "config": name,
        "args": config_args,
        "iterations": iterations,
        "mean_ms": statistics.fmean(samples) * 1000.0,
        "median_ms": statistics.median(samples) * 1000.0,
        "min_ms": min(samples) * 1000.0,
        "max_ms": max(samples) * 1000.0,
    }


def print_markdown(results):
    print("| config | mean ms | median ms | min ms | max ms |")
    print("| --- | ---: | ---: | ---: | ---: |")
    for item in results:
        print(
            f"| {item['config']} | {item['mean_ms']:.2f} | "
            f"{item['median_ms']:.2f} | {item['min_ms']:.2f} | {item['max_ms']:.2f} |"
        )


def main():
    parser = argparse.ArgumentParser(description="Benchmark shadowfuzz-dbi coverage modes")
    parser.add_argument("--executor", default="build/shadowfuzz-dbi")
    parser.add_argument("--target", default="build/poc-branch-churn")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--stdin", default="A")
    parser.add_argument("--json-out")
    parser.add_argument(
        "--configs",
        default="clean,inline,bucket,inline_bucket,ngram4,inline_ngram4,ngram4_bucket,inline_ngram4_bucket",
        help="Comma-separated config names",
    )
    args = parser.parse_args()

    executor = Path(args.executor)
    target = Path(args.target)
    if not executor.exists():
        raise SystemExit(f"missing executor: {executor}")
    if not target.exists():
        raise SystemExit(f"missing target: {target}")
    if args.iterations <= 0:
        raise SystemExit("--iterations must be positive")
    if args.warmups < 0:
        raise SystemExit("--warmups must be non-negative")

    config_names = [name.strip() for name in args.configs.split(",") if name.strip()]
    unknown = [name for name in config_names if name not in CONFIGS]
    if unknown:
        raise SystemExit(f"unknown config(s): {', '.join(unknown)}")

    stdin_data = args.stdin.encode("utf-8")
    results = [
        bench_config(
            name,
            executor,
            target,
            stdin_data,
            args.iterations,
            args.warmups,
            args.timeout,
        )
        for name in config_names
    ]

    print_markdown(results)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
