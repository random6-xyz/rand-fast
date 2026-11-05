# Collector overhead benchmark

`tools/bench.sh` runs a paired baseline/instrumented benchmark inside the QEMU
guest and writes `target/bench-report.json`.

## What is measured

For each mode (`cpu`, `io`, `lock`, `net`) the harness starts the workload
alone, then starts the same workload with `fast diagnose` attached:

- target throughput (`ops`) and p50/p95/p99 latency from the workload's own
  report; the `cpu` mode faults fresh anonymous memory, `io` reads O_DIRECT,
  `lock` contends on a futex, and `net` exchanges loopback requests;
- collector CPU as a percentage of one CPU, read from `/proc/<pid>/stat`; this
  includes the eBPF load/verification and attach time because the percentage is
  over the whole collector lifetime;
- collector peak resident set from `VmHWM`;
- perf-buffer loss from the collector's JSON document;
- wall time and the raw reports for both phases.

Runs are paired and the order alternates (baseline first on even repetitions,
instrumented first on odd ones) so a slow drift does not always favour one
side. Warmup runs are discarded. A run with zero operations, a missing report,
a collector that fails, or missing collector CPU data is marked invalid; the
harness exits non-zero and the report keeps the error. Invalid data is never a
performance pass.

## Running it

```sh
KERNEL=/path/to/bzImage tools/bench.sh
```

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `KERNEL` | required | Kernel image to boot. |
| `OUT_DIR` | `target/bench` | Host directory for the guest log. |
| `BENCH_OUT` | `target/bench-report.json` | Extracted report. |
| `BENCH_DURATION` | `3s` | Duration of each phase. |
| `BENCH_REPETITIONS` | `1` | Recorded repetitions per mode. |
| `BENCH_WARMUP` | `0` | Discarded warmup repetitions per mode. |
| `BENCH_MODES` | `cpu,io,lock,net` | Modes to run. |

The I/O mode requires `FAST_BLOCK_DEVICE=1` and an `IO_HOG_PATH` on the guest's
block disk; `--io-path` overrides it and the effective path is recorded in the
report metadata. If the guest fell back to a tmpfs path, the run is marked invalid
rather than reported as a valid I/O measurement.

A local KVM run with one recorded repetition and no warmup spends about six
seconds of guest time per mode; a TCG CI run is slower and noisier. The report records the kernel,
CPU count, accelerator and load average; comparisons must match the
accelerator and kernel before the numbers mean anything.

## Report

`target/bench-report.json` uses schema `rand-fast/bench/v1` and contains:

- `metadata`: kernel, CPUs, accelerator, load average, binary paths, and the
  effective I/O path;
- `runs[]`: per mode and repetition, the baseline and instrumented phases,
  collector CPU/RSS/loss, ratios, and any error;
- `summary[]`: valid-run count and medians of the throughput and p95 ratios,
  median collector CPU, peak RSS and maximum loss.

`ops_ratio` below 1 means the workload did less work while observed;
`p95_ratio` above 1 means the observed tail was slower. Direct collector cost
(`collector_cpu_pct`, `collector_rss_bytes`) is reported separately from impact
on the observed process, because a cheap collector can still perturb a
latency-sensitive workload.

## CI

The `Collector overhead benchmark` job runs on `schedule`,
`workflow_dispatch`, or a PR labelled `benchmark`. It builds the pinned
6.12.115 kernel, runs one repetition per mode under TCG with four vCPUs, and
uploads the report. It is report-only: functional failures fail
the job, but the timings are not compared to a threshold until a matching
baseline has been calibrated.

Shared runners are not production hardware. TCG and KVM numbers are not
interchangeable, and a report from one accelerator must not be used as the
baseline for the other.
