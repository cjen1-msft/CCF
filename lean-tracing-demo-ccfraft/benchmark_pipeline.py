#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Measure raw normalization and checked encoding without deleting build products."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import contextlib
import io
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

from Shared.capture_traces import SCENARIOS, capture, find_repo_root
from Shared.solver import find_cvc5
from validate import VALIDATION_ERRORS, artifact_paths, read_bounds, validate
import validate_checked as checked

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


def measure_proof_gate(artifacts: Path) -> dict[str, object]:
    """Measure the existing incremental gate, including a possible cache hit."""
    started = time.perf_counter_ns()
    gate = checked.build_proof_gate(ROOT, artifacts / "lean-proof-gate.log")
    return {
        "proof_gate": gate,
        "proof_gate_wall_ms": (time.perf_counter_ns() - started) / 1_000_000,
        "measurement": "incremental proof gate; existing build products retained",
    }


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
    if len({sample["status"] for sample in samples}) != 1:
        raise RuntimeError("validation statuses changed between benchmark samples")
    result = dict(samples[-1])
    timing_keys = (
        "check_sat_wall_ms",
        "core_reduction_wall_ms",
        "encoder_wall_ms",
        "checked_validation_wall_ms",
        "proof_wall_ms",
        "total_solver_wall_ms",
        "core_solver_wall_ms",
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bounds", type=Path, required=True)
    parser.add_argument("--cvc5", type=Path)
    parser.add_argument(
        "--samples",
        type=int,
        default=5,
        help="interleaved validation samples per trace, including capture unless disabled",
    )
    parser.add_argument(
        "--saved-traces",
        action="store_true",
        help="benchmark saved traces without running raft_driver or recapturing scenarios",
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
        help="reuse checked proof-gate timing metadata from --output",
    )
    args = parser.parse_args(argv)
    if args.samples < 1:
        parser.error("--samples must be positive")
    repo_root = ROOT.parent if args.saved_traces else find_repo_root()
    driver = repo_root / "build/raft_driver"
    destinations = [args.output]
    if not args.reuse_build_timings:
        destinations.append(args.artifacts / "lean-proof-gate.log")
    for name, _ in RUNS:
        destinations.extend(artifact_paths(args.artifacts / name))
    inputs = (
        args.bounds,
        driver,
        *(repo_root / "tests/raft_scenarios" / scenario for scenario in SCENARIOS),
        *(trace for _, trace in RUNS),
        *(ROOT / "Traces/Captured" / f"{scenario}.ndjson" for scenario in SCENARIOS),
    )
    try:
        checked.reject_artifact_collisions(inputs, destinations)
    except VALIDATION_ERRORS as error:
        parser.error(str(error))
    previous_gate = None
    if args.reuse_build_timings:
        previous_gate = read_json(args.output).get("lean")
        if (
            not isinstance(previous_gate, dict)
            or "proof_gate_wall_ms" not in previous_gate
            or not isinstance(previous_gate.get("proof_gate"), dict)
            or previous_gate["proof_gate"].get("build_target") != checked.ENCODER_TARGET
            or previous_gate["proof_gate"].get("checked") is not True
        ):
            parser.error("--reuse-build-timings requires checked encoder measurements")
    args.output.unlink(missing_ok=True)
    try:
        bounds = read_bounds(args.bounds)
        cvc5 = find_cvc5(args.cvc5)
    except VALIDATION_ERRORS as error:
        parser.error(str(error))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.artifacts.mkdir(parents=True, exist_ok=True)

    scenarios = () if args.saved_traces else SCENARIOS
    capture_samples: dict[str, list[float]] = {scenario: [] for scenario in scenarios}
    capture_results: dict[str, tuple[bytes, bool]] = {}
    for sample in range(args.samples):
        order = scenarios if sample % 2 == 0 else tuple(reversed(scenarios))
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
        for scenario in scenarios
    }

    lean = (
        {**previous_gate, "reused": True}
        if previous_gate is not None
        else measure_proof_gate(args.artifacts)
    )

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
                    bounds=bounds,
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
            (output_directory / "reduced-certificate.json").read_text(encoding="utf-8")
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
                "bounds": dict(bounds),
                "capture": captures,
                "trace_source": (
                    "saved" if args.saved_traces else "saved_with_capture_comparison"
                ),
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
                "lean": lean,
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
