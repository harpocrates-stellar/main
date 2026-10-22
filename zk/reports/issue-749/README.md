# Issue #749: circuit constraint mutation report

This is the checked-in evidence for the completed local mutation campaign.
[report.json](report.json) preserves the original structured output, including
every mutation's source location, owning function, outcome and failing test
names. The JSON's `log` fields name the original execution logs; those logs are
run outputs rather than files included in this snapshot. Scheduled runs upload
the complete report directory and logs as GitHub Actions artifacts.

## Recorded run

- Date: 2026-10-22 (Asia/Shanghai).
- Tested source commit: [`95cfdde99c04736c79fd1874a76069e72feb10c2`](https://github.com/PHTPSN/main/commit/95cfdde99c04736c79fd1874a76069e72feb10c2).
- Upstream base: `35e4b428a89195c99500de43aae75cfb2c002492`.
- Environment: WSL Ubuntu 24.04, pinned Nargo `1.0.0-beta.9`
  (`6abff2f16e1c1314ba30708d1cf032a536de3d19`).
- Campaign budget: 2,100 seconds; timeout per Nargo invocation: 180 seconds.
- Elapsed: **89.412 seconds**; exit status: **0**.
- Result: **52 killed, zero survivors, zero errors, timeouts or untested mutants**.

Each binary package with mutation targets passed its unmodified baseline first.
Every mutant was executed in a temporary copy with exactly one production
`assert` / `assert_eq` disabled. A completed failing Nargo test report counted
as a kill; compilation failures and timeouts did not. The input vectors came
from the executable Noir tests. The four packages with zero production
assertions are included in the inventory with zero targets.

| Circuit | Constraints | Killed | Survived | Errors / untested | Seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| redacted_ancestry | 18 | 18 | 0 | 0 | 22.419 |
| redacted_ancestry_helper | 0 | 0 | 0 | 0 | 0.002 |
| revocation_witness | 11 | 11 | 0 | 0 | 13.478 |
| revocation_witness_helper | 0 | 0 | 0 | 0 | 0.003 |
| selective_disclosure | 17 | 17 | 0 | 0 | 44.467 |
| silent_witness | 4 | 4 | 0 | 0 | 6.579 |
| silent_witness_aggregator | 2 | 2 | 0 | 0 | 1.516 |
| silent_witness_aggregator_helper | 0 | 0 | 0 | 0 | 0.002 |
| silent_witness_helper | 0 | 0 | 0 | 0 | 0.002 |

## Reproduce

From the repository root, with the Nargo version pinned by
`zk/toolchain.lock.json` on `PATH`:

```bash
python3 zk/tools/mutate_constraints.py \
  --budget-seconds 2100 --timeout-seconds 180 \
  --report-dir tmp/constraint-mutations
```

For the generator and real-compiler integration checks:

```bash
NARGO=nargo python3 -m unittest discover -s zk/tools -p test_mutate_constraints.py -v
```

All 19 generator/integration tests passed in the recorded validation. The
broader ZK Python tools/benchmark run had 207 passes, three skips and one
existing benchmark failure: `test_oversized_witness_fails_deterministically`
expects `witness_oversized`, while the implementation returns `oversized`.
That identical failure was reproduced on unmodified upstream base `35e4b42`.

## CI status and scope

The [manual workflow run](https://github.com/PHTPSN/main/actions/runs/39689866767)
used the tested commit with `mutation_only=true`. GitHub did not allocate a
runner or start any steps because the fork account was locked by a billing
issue. Cloud runtime validation therefore remains pending; the measured time
above is local and excludes runner provisioning and toolchain installation.

This report measures deletion detection in the checked-in Noir source. It
does not establish source equality with published browser artifacts or prove
that the entire proof system has no missing constraints. See the
[mutation workflow documentation](../../../docs/zk-fuzzing.md#scheduled-circuit-constraint-mutation-checks-749)
for baseline repairs, redundant-guard tests, exit codes and scheduled reporting.
