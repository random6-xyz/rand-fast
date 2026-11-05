# Calibrated overhead gates

`tools/bench-check.sh` compares a candidate `fast-bench` report with a
calibrated baseline. It enforces only metrics that repeated measurements
showed to be stable; unstable metrics stay visible as `report-only`.

## Calibration

Representative paired runs:

| Environment | Guest kernel | vCPUs | Repetitions | Runs |
| --- | --- | --- | --- | --- |
| Local KVM | 7.2.0-rc6 | 8 | 2 per mode | A/B |
| Local TCG | 6.12.115 | 4 | 2 per mode | A/B |

The two KVM runs agreed within 2% on throughput ratios and collector CPU. The
two TCG runs agreed within 4% on throughput ratios; collector CPU was again
stable, but its absolute value is much higher (for I/O it is around 115% of one
CPU) because TCG emulates the guest. These A/B pairs are enough to reject large
regressions; a 10% change is inside the observed noise and is not claimed to be
detectable. CI noise should be measured again before tightening a threshold. The accelerator and vCPU count are
therefore part of the comparability check, and a KVM baseline is never used
against a TCG candidate.

## Metrics and thresholds

The policy lives in `tools/bench/policy.json`. A candidate is compared with the
baseline mode by mode:

| Metric | Enforced | Limit | Rationale |
| --- | --- | --- | --- |
| `ops_ratio` | yes | candidate ≥ baseline × 0.80 | A 20% additional throughput loss is a real regression, not noise. |
| `collector_cpu_pct` | yes | candidate ≤ baseline × 1.50 + 2 points | Allows runner noise while catching a large new cost. |
| `lost_events` | yes | candidate ≤ baseline + 50, and ≤ 100 | Loss is a correctness signal; a small absolute allowance covers a busier run. A baseline above the 100 cap is itself invalid. |
| `p95_ratio` | no | candidate ≤ baseline × 1.50 | Tail latency is useful evidence but too noisy on shared runners yet. |
| `valid_runs` | yes | at least one per mode | Missing data is never a performance pass. |

The checker fails on a missing mode, a missing **enforced** metric, a metadata
mismatch (kernel/accelerator/vCPUs/duration/repetitions/warmup), an invalid
run, a baseline that would fail its own policy, and any enforced threshold
breach. A missing report-only metric is shown as `report-only`, not a failure.
It writes `rand-fast/bench-check/v1` JSON with per-metric baselines,
candidates, limits and status, so a CI artifact explains a failure without
re-running the benchmark.

## Baseline

The committed baseline (`bench/baseline-6.12.115-tcg-4cpu.json`) was produced by
the `Collector overhead benchmark` CI job (run 41962142998, 2026-02) on the
pinned 6.12.115 kernel under TCG with four vCPUs, using the same
`BENCH_DURATION`, `BENCH_REPETITIONS` and `BENCH_WARMUP` as the gate. It must be
refreshed only from a green run of unchanged code, and the refresh commit must include the
job URL and date. KVM and TCG baselines are separate files.

To refresh:

1. Run the benchmark job on the target commit.
2. Download the `benchmark-report` artifact.
3. Verify `metadata.kernel`, `metadata.accelerator` and `metadata.cpus` match
   the intended environment and that every mode has a valid run.
4. Replace the baseline file, run `tools/bench-check.sh` against it, and note
   the CI run in the commit message.

Rollback is the same procedure with the previous baseline file. A baseline is
never edited in place to make a failing candidate pass; a real change in
overhead needs a reviewed baseline refresh.

## CI wiring

The `Overhead regression gate` job runs when a PR carries the
`benchmark-gate` label. It depends on the report-only benchmark job, downloads
its artifact, compares it with the committed TCG baseline, and uploads the
check JSON even on failure. The benchmark job remains report-only on
`schedule`, `workflow_dispatch` and the `benchmark` label; only
`benchmark-gate` enforces thresholds.

## Demonstrating the gate

`tools/test-bench-check.sh` feeds synthetic reports to the checker. It shows
that a stable candidate passes, a 3× collector CPU increase fails, a 50%
throughput drop fails, excess event loss fails, an invalid run fails, a missing
mode fails, and an accelerator mismatch fails. It also proves that the
report-only p95 change does not fail the gate.

The checker is not a substitute for a real regression test: the calibration
data above, and the deliberate-regression fixture, are what justify enabling a
threshold. A metric whose repeated runs disagree stays `enforced: false` until
new calibration data supports a threshold.
