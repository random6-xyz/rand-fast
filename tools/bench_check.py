#!/usr/bin/env python3
"""Compare a candidate overhead report with a calibrated baseline.

The checker is deliberately strict about missing data: a report that cannot
prove it is comparable to the baseline is a failure, never a pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "rand-fast/bench/v1"
POLICY_SCHEMA = "rand-fast/bench-policy/v1"


def load(path: Path) -> dict:
    try:
        with path.open() as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        print(f"bench-check: FAIL: cannot read {path}: {error}", file=sys.stderr)
        raise SystemExit(2) from error


def fail(message: str) -> None:
    print(f"bench-check: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def summary(report: dict, mode: str) -> dict | None:
    for item in report.get("summary", []):
        if item.get("mode") == mode:
            return item
    return None


def check_metadata(baseline: dict, candidate: dict) -> list[str]:
    problems: list[str] = []
    bmeta = baseline.get("metadata", {})
    cmeta = candidate.get("metadata", {})
    for field in (
        "kernel",
        "accelerator",
        "cpus",
        "duration_ms",
        "repetitions",
        "warmup",
    ):
        if bmeta.get(field) != cmeta.get(field):
            problems.append(
                f"metadata {field}: baseline={bmeta.get(field)!r} candidate={cmeta.get(field)!r}"
            )
    return problems


def check_metric(
    name: str,
    policy: dict,
    baseline: float | int | None,
    candidate: float | int | None,
) -> tuple[bool, str]:
    rules = policy["metrics"][name]
    if baseline is None or candidate is None:
        return False, "missing from the report"
    if name == "ops_ratio":
        limit = float(baseline) * (1.0 - float(rules["max_drop_pct"]) / 100.0)
        return float(candidate) >= limit, f">= {limit:.4f}"
    if name == "p95_ratio":
        limit = float(baseline) * (1.0 + float(rules["max_increase_pct"]) / 100.0)
        return float(candidate) <= limit, f"<= {limit:.4f}"
    if name == "collector_cpu_pct":
        limit = (
            float(baseline) * (1.0 + float(rules["max_increase_pct"]) / 100.0)
            + float(rules.get("absolute_slack", 0.0))
        )
        return float(candidate) <= limit, f"<= {limit:.4f}"
    if name == "lost_events":
        limit = float(baseline) + float(rules.get("max_increase", 0))
        absolute = float(rules.get("max_absolute", float("inf")))
        return float(candidate) <= min(limit, absolute), (
            f"<= {min(limit, absolute):.0f}"
        )
    return False, "unknown metric"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    baseline = load(args.baseline)
    candidate = load(args.candidate)
    policy = load(args.policy)
    for label, report in (("baseline", baseline), ("candidate", candidate)):
        if report.get("schema") != SCHEMA:
            fail(f"{label} has schema {report.get('schema')!r}, expected {SCHEMA!r}")
    if policy.get("schema") != POLICY_SCHEMA:
        fail(f"policy has schema {policy.get('schema')!r}, expected {POLICY_SCHEMA!r}")
    if not policy.get("required_modes"):
        fail("policy has no required_modes")
    for name, rules in policy.get("metrics", {}).items():
        if "enforced" not in rules:
            fail(f"policy metric {name!r} has no enforced flag")

    problems = check_metadata(baseline, candidate)
    # A baseline that would fail its own policy is not a calibration point.
    for label, report in (("baseline", baseline), ("candidate", candidate)):
        if label == "candidate":
            continue
        for mode in policy.get("required_modes", []):
            bsum = summary(report, mode)
            if bsum is None:
                problems.append(f"baseline mode {mode}: missing from the report")
                continue
            if bsum.get("valid_runs", 0) < policy.get("min_valid_runs", 1):
                problems.append(
                    f"baseline mode {mode}: only {bsum.get('valid_runs', 0)} valid run(s)"
                )
            if bsum.get("runs", 0) != bsum.get("valid_runs", 0):
                problems.append(
                    f"baseline mode {mode}: {bsum.get('runs', 0)} run(s), "
                    f"{bsum.get('valid_runs', 0)} valid"
                )
            for name, rules in policy.get("metrics", {}).items():
                if not rules.get("enforced"):
                    continue
                if name == "collector_cpu_pct":
                    value = bsum.get("collector_cpu_pct_median")
                elif name == "lost_events":
                    value = bsum.get("lost_events_max")
                else:
                    value = bsum.get(f"{name}_median")
                ok, limit = check_metric(name, policy, value, value)
                if not ok:
                    problems.append(
                        f"baseline mode {mode}: {name}={value} is outside its own limit {limit}"
                    )
    rows: list[dict] = []
    for mode in policy.get("required_modes", []):
        bsum = summary(baseline, mode)
        csum = summary(candidate, mode)
        if bsum is None or csum is None:
            problems.append(f"mode {mode}: missing from the report")
            continue
        if csum.get("valid_runs", 0) < policy.get("min_valid_runs", 1):
            problems.append(
                f"mode {mode}: only {csum.get('valid_runs', 0)} valid run(s)"
            )
        if csum.get("runs", 0) != csum.get("valid_runs", 0):
            problems.append(
                f"mode {mode}: {csum.get('runs', 0)} run(s), "
                f"{csum.get('valid_runs', 0)} valid"
            )
        for name, rules in policy["metrics"].items():
            if name == "collector_cpu_pct":
                bvalue, cvalue, field = (
                    bsum.get("collector_cpu_pct_median"),
                    csum.get("collector_cpu_pct_median"),
                    "collector_cpu_pct_median",
                )
            elif name == "lost_events":
                bvalue, cvalue, field = (
                    bsum.get("lost_events_max"),
                    csum.get("lost_events_max"),
                    "lost_events_max",
                )
            else:
                bvalue, cvalue, field = (
                    bsum.get(f"{name}_median"),
                    csum.get(f"{name}_median"),
                    f"{name}_median",
                )
            ok, limit = check_metric(name, policy, bvalue, cvalue)
            enforced = bool(rules.get("enforced"))
            if not ok and enforced:
                problems.append(f"mode {mode}: {field} {cvalue} outside {limit}")
            rows.append(
                {
                    "mode": mode,
                    "metric": name,
                    "field": field,
                    "enforced": enforced,
                    "baseline": bvalue,
                    "candidate": cvalue,
                    "limit": limit,
                    "ok": ok,
                    "status": "pass" if ok else ("fail" if enforced else "report-only"),
                }
            )

    result = {
        "schema": "rand-fast/bench-check/v1",
        "baseline": str(args.baseline),
        "candidate": str(args.candidate),
        "policy": policy,
        "problems": problems,
        "checks": rows,
        "ok": not problems,
    }
    print(f"{'mode':<6} {'metric':<20} {'baseline':>10} {'candidate':>10} {'limit':<14} status")
    for row in rows:
        print(
            f"{row['mode']:<6} {row['metric']:<20} "
            f"{str(row['baseline']):>10} {str(row['candidate']):>10} "
            f"{row['limit']:<14} {row['status']}"
        )
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    if problems:
        for problem in problems:
            print(f"bench-check: FAIL: {problem}", file=sys.stderr)
        return 1
    print("bench-check: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
