#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Regress saved raw captures and measure complete native validation runs."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time

from native_input import unique_object
from native_run import NativeRun
from native_solver import find_z3
from reduction import ReductionError
from Shared.solver import ValidationError

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "Traces/native_suite.json"


@dataclass(frozen=True)
class CaptureCase:
    trace: str
    source: Path
    bootstrap: tuple[str, ...]
    expected: str
    reason: str


def load_cases(manifest: Path = MANIFEST) -> list[CaptureCase]:
    document = json.loads(
        manifest.read_text(encoding="utf-8"), object_pairs_hook=unique_object
    )
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "directories", "cases"}
        or document["schema"] != "ccfraft-native-suite/v1"
        or not isinstance(document["cases"], list)
        or not document["cases"]
    ):
        raise ValidationError("expected a nonempty ccfraft-native-suite/v1 manifest")
    root = manifest.parent.resolve()
    directories = document["directories"]
    if (
        not isinstance(directories, list)
        or not directories
        or any(not isinstance(folder, str) or not folder for folder in directories)
        or len(directories) != len(set(directories))
    ):
        raise ValidationError("directories must be distinct relative trace folders")
    for folder in directories:
        path = root / folder
        if (
            Path(folder).is_absolute()
            or ".." in Path(folder).parts
            or not path.is_dir()
            or not path.resolve().is_relative_to(root)
        ):
            raise ValidationError(f"invalid trace directory: {folder!r}")
    discovered = {
        path.relative_to(root).as_posix(): path
        for folder in directories
        for path in (root / folder).rglob("*.ndjson")
        if path.is_file()
    }
    cases = []
    seen = set()
    for item in document["cases"]:
        if not isinstance(item, dict) or set(item) != {
            "trace",
            "bootstrap",
            "expected",
            "reason",
        }:
            raise ValidationError(
                "each case requires trace, bootstrap, expected, reason"
            )
        trace = item["trace"]
        if not isinstance(trace, str) or trace not in discovered or trace in seen:
            raise ValidationError(f"unknown or duplicate capture: {trace!r}")
        source = discovered[trace]
        if not source.resolve().is_relative_to(root):
            raise ValidationError(f"capture escapes the trace directory: {trace}")
        bootstrap = item["bootstrap"]
        if (
            not isinstance(bootstrap, list)
            or not bootstrap
            or any(not isinstance(name, str) or not name for name in bootstrap)
            or len(bootstrap) != len(set(bootstrap))
        ):
            raise ValidationError(f"{trace}: bootstrap must name distinct identities")
        if item["expected"] not in ("sat", "unsat"):
            raise ValidationError(f"{trace}: expected must be sat or unsat")
        if not isinstance(item["reason"], str) or not item["reason"].strip():
            raise ValidationError(f"{trace}: explain the expected verdict")
        cases.append(
            CaptureCase(
                trace, source, tuple(bootstrap), item["expected"], item["reason"]
            )
        )
        seen.add(trace)
    missing = set(discovered) - seen
    if missing:
        raise ValidationError(f"captures missing suite metadata: {sorted(missing)}")
    return cases


def prepare(output: Path) -> None:
    """Build once before any measured run, retaining the build log."""
    with (output / "lean-build.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(
            [
                "lake",
                "build",
                "Sparse.NativeParameterizedFrameDecoded",
                "Sparse.NativeEncodeMain",
            ],
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode:
        raise ValidationError(f"Lean build failed; see {output / 'lean-build.log'}")


def run_case(case: CaptureCase, output: Path, z3: Path) -> dict:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter_ns()
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "native_lean.py"),
            str(case.source),
            "--raw",
            "--bootstrap",
            *case.bootstrap,
            "--output-dir",
            str(output),
            "--z3",
            str(z3),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    total_ms = (time.perf_counter_ns() - started) / 1_000_000
    (output / "cli.stdout").write_text(result.stdout, encoding="utf-8")
    (output / "cli.stderr").write_text(result.stderr, encoding="utf-8")
    if result.returncode:
        raise ValidationError(
            f"{case.trace}: native CLI exited {result.returncode}; see {output / 'cli.stderr'}"
        )
    run = NativeRun.load(output)
    if json.loads(result.stdout, object_pairs_hook=unique_object) != run.result:
        raise ValidationError(f"{case.trace}: CLI result differs from retained result")
    if run.result["status"] != case.expected:
        raise ValidationError(
            f"{case.trace}: expected {case.expected}, got {run.result['status']}; "
            f"expectation: {case.reason}; artifacts: {output}"
        )
    return {
        "trace": case.trace,
        "status": run.result["status"],
        "total_ms": total_ms,
        "solver_ms": run.result["solver_ms"],
        "instructions": len(run.document["instructions"]),
        "clauses": len(run.details["clauses"]),
        "output": str(output),
    }


def run_suite(
    cases: list[CaptureCase],
    output: Path,
    z3: Path,
    *,
    samples: int = 1,
    warmups: int = 0,
) -> dict:
    if not cases:
        raise ValidationError("the suite requires at least one capture")
    if samples < 1 or warmups < 0:
        raise ValidationError("samples must be positive and warmups nonnegative")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    prepare(output)
    measured = {case.trace: [] for case in cases}
    for iteration in range(warmups + samples):
        warming = iteration < warmups
        label = (
            f"warmup-{iteration + 1}"
            if warming
            else f"sample-{iteration - warmups + 1}"
        )
        for case in cases:
            directory = output / Path(case.trace).with_suffix("") / label
            result = run_case(case, directory, z3)
            if not warming:
                measured[case.trace].append(result)
    rows = []
    for case in cases:
        results = measured[case.trace]
        totals = [result["total_ms"] for result in results]
        rows.append(
            {
                "trace": case.trace,
                "expected": case.expected,
                "reason": case.reason,
                "median_total_ms": statistics.median(totals),
                "min_total_ms": min(totals),
                "max_total_ms": max(totals),
                "median_solver_ms": statistics.median(
                    result["solver_ms"] for result in results
                ),
                "samples": results,
            }
        )
    report = {
        "schema": "ccfraft-native-suite-results/v1",
        "measurement": (
            "Native CLI wall time: process startup, raw reduction, Lean invocation, "
            "SMT emission, Z3 and result/artifact writing. Initial lake build, "
            "warmup runs and subsequent explorer artifact loading are excluded."
        ),
        "samples_per_case": samples,
        "warmups_per_case": warmups,
        "cases": rows,
    }
    (output / "summary.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--z3", type=Path)
    parser.add_argument(
        "--case", action="append", default=[], help="manifest trace path"
    )
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--warmups", type=int, default=0)
    args = parser.parse_args()
    try:
        cases = load_cases(args.manifest)
        if args.output_dir.resolve().is_relative_to(args.manifest.parent.resolve()):
            raise ValidationError("suite output must be outside the trace directory")
        selected = set(args.case)
        unknown = selected - {case.trace for case in cases}
        if unknown:
            raise ValidationError(f"unknown selected cases: {sorted(unknown)}")
        if selected:
            cases = [case for case in cases if case.trace in selected]
        report = run_suite(
            cases,
            args.output_dir,
            find_z3(args.z3),
            samples=args.samples,
            warmups=args.warmups,
        )
    except (ValidationError, ReductionError, OSError, ValueError) as error:
        parser.exit(2, f"native capture suite: {error}\n")
    for case in report["cases"]:
        print(
            f"{case['trace']}: {case['expected']} (expected); "
            f"total {case['median_total_ms'] / 1000:.3f}s "
            f"[{case['min_total_ms'] / 1000:.3f}, {case['max_total_ms'] / 1000:.3f}]; "
            f"Z3 {case['median_solver_ms'] / 1000:.3f}s"
        )


if __name__ == "__main__":
    main()
