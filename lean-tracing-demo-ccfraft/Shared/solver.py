#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Discover and run cvc5, retaining every byte of solver evidence.

These helpers are backend independent: they know how to find the solver, run
it on one SMT-LIB file, classify its status line, and read the payload of one
post-check query. They do not know how any formula was produced.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

SOLVER_STATUSES = frozenset({"sat", "unsat", "unknown"})


class ValidationError(RuntimeError):
    """Report solver discovery, execution, or output failures."""


@dataclass(frozen=True)
class SolverRun:
    """One complete cvc5 invocation."""

    status: str
    stdout: str
    stderr: str
    wall_time_ms: float


def find_cvc5(requested: Path | None) -> Path:
    """Return the requested cvc5 executable, or the one on PATH."""

    if requested is not None:
        candidate = requested.expanduser()
        if not candidate.is_file():
            raise ValidationError(f"cvc5 executable does not exist: {candidate}")
        return candidate
    located = shutil.which("cvc5")
    if located is None:
        raise ValidationError("cvc5 was not found on PATH; pass --cvc5")
    return Path(located)


def solver_status(stdout: str) -> str:
    """Return the first solver status line printed by cvc5."""

    statuses = [
        line.strip() for line in stdout.splitlines() if line.strip() in SOLVER_STATUSES
    ]
    if not statuses:
        raise ValidationError("cvc5 stdout did not contain sat, unsat, or unknown")
    return statuses[0]


def run_solver(
    cvc5: Path,
    formula_path: Path,
    output_directory: Path,
    artifact_stem: str,
    *,
    extra_arguments: Sequence[str] = (),
) -> SolverRun:
    """Run cvc5 on one formula and keep its stdout and stderr on disk."""

    started = time.perf_counter_ns()
    completed = subprocess.run(
        [str(cvc5), "--lang=smt2", *extra_arguments, str(formula_path)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    wall_time_ms = (time.perf_counter_ns() - started) / 1_000_000
    stdout_path = output_directory / f"{artifact_stem}.stdout"
    stderr_path = output_directory / f"{artifact_stem}.stderr"
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise ValidationError(
            f"cvc5 failed with exit code {completed.returncode}; "
            f"see {stdout_path} and {stderr_path}"
        )
    return SolverRun(
        solver_status(completed.stdout),
        completed.stdout,
        completed.stderr,
        wall_time_ms,
    )


def query_payload(run: SolverRun, query: str) -> str:
    """Return the text cvc5 printed after the status line for one query."""

    lines = run.stdout.splitlines(keepends=True)
    status_position = next(
        (
            position
            for position, line in enumerate(lines)
            if line.strip() in SOLVER_STATUSES
        ),
        None,
    )
    if status_position is None:
        raise ValidationError(f"{query} output has no solver status")
    payload = "".join(lines[status_position + 1 :])
    if not payload.strip():
        raise ValidationError(f"cvc5 returned no {query}")
    if payload.lstrip().startswith("(error"):
        raise ValidationError(f"cvc5 rejected {query}: {payload.strip()}")
    return payload
