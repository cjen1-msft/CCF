#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Measure the current trace-validation pipeline with cold and warm builds."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import platform
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

from Shared.capture_traces import SCENARIOS, capture, find_repo_root
from validate import validate

ROOT = Path(__file__).resolve().parent
RUNS = (
    ("bad_network", ROOT / "Traces/Captured/bad_network.ndjson"),
    ("soft_rollback", ROOT / "Traces/Captured/soft_rollback.ndjson"),
    ("bad_network-direct", ROOT / "Traces/Mutated/bad_network-direct.ndjson"),
    ("bad_network-indirect", ROOT / "Traces/Mutated/bad_network-indirect.ndjson"),
    ("soft_rollback-direct", ROOT / "Traces/Mutated/soft_rollback-direct.ndjson"),
    ("soft_rollback-indirect", ROOT / "Traces/Mutated/soft_rollback-indirect.ndjson"),
)


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return value


def timed_command(command: list[str], *, cwd: Path, log: Path) -> float:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    wall_time_ms = (time.perf_counter_ns() - started) / 1_000_000
    log.write_text(
        completed.stdout + completed.stderr,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed; see {log}")
    return wall_time_ms


def find_cvc5(requested: Path | None) -> Path:
    if requested is not None:
        return requested
    located = shutil.which("cvc5")
    if located is None:
        raise RuntimeError("cvc5 was not found on PATH; pass --cvc5")
    return Path(located)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = fraction * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def aggregate_samples(samples: list[dict[str, object]]) -> dict[str, object]:
    result = dict(samples[-1])
    timing_keys = (
        "check_sat_wall_ms",
        "core_reduction_wall_ms",
        "decision_wall_ms",
        "proof_wall_ms",
        "total_solver_wall_ms",
        "unsat_core_wall_ms",
        "validation_wall_ms",
    )
    for key in timing_keys:
        values = [float(sample[key]) for sample in samples if key in sample]
        if values:
            result[key] = statistics.median(values)
            result[f"{key}_p90"] = percentile(values, 0.9)
    phase_names = samples[-1]["phase_wall_ms"]
    assert isinstance(phase_names, dict)
    result["phase_wall_ms"] = {
        phase: statistics.median(
            float(sample["phase_wall_ms"][phase]) for sample in samples
        )
        for phase in phase_names
    }
    result["samples"] = samples
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cvc5", type=Path)
    parser.add_argument(
        "--samples",
        type=int,
        default=5,
        help="interleaved capture and validation samples per trace",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "Measurements/pipeline.json",
    )
    parser.add_argument(
        "--artifacts",
        type=Path,
        default=ROOT / "Artifacts/benchmark",
    )
    parser.add_argument(
        "--core-reduction-seconds",
        type=float,
        default=10.0,
        help="wall-clock budget for each UNSAT explanation",
    )
    parser.add_argument(
        "--reuse-build-timings",
        action="store_true",
        help="keep cold and warm build timings already stored in --output",
    )
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be positive")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.artifacts.mkdir(parents=True, exist_ok=True)
    repo_root = find_repo_root()
    driver = repo_root / "build/raft_driver"

    capture_samples: dict[str, list[float]] = {scenario: [] for scenario in SCENARIOS}
    capture_results: dict[str, tuple[bytes, bool]] = {}
    for sample in range(args.samples):
        order = SCENARIOS if sample % 2 == 0 else tuple(reversed(SCENARIOS))
        for scenario in order:
            output, wall_time_ms = capture(
                driver,
                repo_root / "tests/raft_scenarios" / scenario,
            )
            fixture = ROOT / "Traces/Captured" / f"{scenario}.ndjson"
            capture_samples[scenario].append(wall_time_ms)
            capture_results[scenario] = (output, output == fixture.read_bytes())
    captures = {
        scenario: {
            "matches_fixture": capture_results[scenario][1],
            "records": len(capture_results[scenario][0].splitlines()),
            "samples_wall_ms": capture_samples[scenario],
            "wall_time_ms": statistics.median(capture_samples[scenario]),
            "wall_time_ms_p90": percentile(capture_samples[scenario], 0.9),
        }
        for scenario in SCENARIOS
    }

    if args.reuse_build_timings:
        existing = read_json(args.output)
        cold_build_ms = existing["lean"]["cold_build_wall_ms"]
        warm_build_ms = existing["lean"]["warm_build_wall_ms"]
    else:
        project_build = ROOT / ".lake/build"
        if project_build.exists():
            shutil.rmtree(project_build)
        cold_build_ms = timed_command(
            ["lake", "build", "Demo"],
            cwd=ROOT,
            log=args.artifacts / "lean-cold-build.log",
        )
        warm_build_ms = timed_command(
            ["lake", "build", "Demo"],
            cwd=ROOT,
            log=args.artifacts / "lean-warm-build.log",
        )

    cvc5 = find_cvc5(args.cvc5)
    validation_samples: dict[str, list[dict[str, object]]] = {
        name: [] for name, _ in RUNS
    }
    run_paths = dict(RUNS)
    for sample in range(args.samples):
        order = RUNS if sample % 2 == 0 else tuple(reversed(RUNS))
        for name, trace in order:
            output_directory = args.artifacts / name
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                validate(
                    trace,
                    output_directory,
                    cvc5=cvc5,
                    core_reduction_budget_seconds=args.core_reduction_seconds,
                )
            result = json.loads(
                (output_directory / "result.json").read_text(encoding="utf-8")
            )
            validation_samples[name].append(result)
    validations: dict[str, object] = {}
    for name, samples in validation_samples.items():
        output_directory = args.artifacts / name
        certificate = json.loads(
            (output_directory / "certificate.json").read_text(encoding="utf-8")
        )
        validations[name] = {
            **aggregate_samples(samples),
            "actions": certificate["counts"]["actions"],
            "observations": certificate["counts"]["observations"],
            "states": certificate["counts"]["actions"] + 1,
            "trace": str(run_paths[name].relative_to(ROOT)),
            "trace_records": certificate["counts"]["raw_records"],
        }

    cvc5_version = subprocess.run(
        [str(cvc5), "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()[0]

    args.output.write_text(
        json.dumps(
            {
                "capture": captures,
                "environment": {
                    "cvc5": cvc5_version,
                    "git_revision": subprocess.run(
                        ["git", "rev-parse", "HEAD"],
                        cwd=repo_root,
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.strip(),
                    "machine": platform.machine(),
                    "platform": platform.platform(),
                    "python": sys.version.split()[0],
                    "samples_per_trace": args.samples,
                },
                "lean": {
                    "cold_build_wall_ms": cold_build_ms,
                    "warm_build_wall_ms": warm_build_ms,
                },
                "validations": validations,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
