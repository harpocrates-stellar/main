# ZK proof generation and verification benchmarks

Reproducible performance and memory baselines for browser, native, CI, and
Soroban-adjacent verification.

## Quick start

```bash
# Unit tests (no nargo/bb required)
python -m pytest zk/bench -q

# Synthetic CI-style run (writes zk/bench/results/ when outcome=ok)
zk/bench/run.sh run --target ci --synthetic

# Hardware/runtime metadata only
zk/bench/run.sh metadata

# Compare against published thresholds in zk/bench/baselines.lock.json
zk/bench/run.sh compare --report zk/bench/results/<report>.json

# Browser/Node path (requires compiled ACIR + frontend deps)
node zk/bench/browser_runner.mjs
```

See [docs/zk-benchmarks.md](../../docs/zk-benchmarks.md).
