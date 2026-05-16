# Benchmark Report

Release: `v0.1.0-alpha.1`

Date: 2026-05-16

Command:

```bash
tools/bench_shadowcov.py --iterations 5 --warmups 1 \
  --json-out /tmp/shadowfuzz_bench.json --target build/poc-branch-churn
```

Target:

```text
build/poc-branch-churn
```

Results:

| config | mean ms | median ms | min ms | max ms |
| --- | ---: | ---: | ---: | ---: |
| clean | 114.20 | 114.17 | 114.09 | 114.40 |
| inline | 63.95 | 63.99 | 63.78 | 64.05 |
| bucket | 114.10 | 114.10 | 114.06 | 114.13 |
| inline_bucket | 64.00 | 64.02 | 63.90 | 64.10 |
| ngram4 | 114.09 | 114.07 | 113.95 | 114.21 |
| inline_ngram4 | 73.98 | 63.99 | 63.83 | 113.94 |
| ngram4_bucket | 114.01 | 114.02 | 113.96 | 114.03 |
| inline_ngram4_bucket | 64.07 | 64.07 | 63.92 | 64.26 |

Interpretation:

- Inline coverage reduces this local benchmark from about 114 ms to about
  64 ms per run, roughly a 1.8x improvement.
- Clean-call hitcount bucket and n-gram variants remain close to clean-call
  baseline because startup and clean-call overhead dominate.
- `inline_ngram4` had one slow outlier in this five-sample run; median time
  stayed aligned with the other inline modes.
- These measurements include executor and DynamoRIO startup overhead. They are
  useful for relative local comparisons, not as final throughput claims for
  real targets.

To reproduce with fewer samples:

```bash
tools/bench_shadowcov.py --iterations 1 --warmups 0 \
  --configs clean,inline --target build/poc-branch-churn
```
