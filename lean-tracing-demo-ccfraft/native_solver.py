# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run Z3 on Lean-owned scripts and conditional query text."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from Shared.solver import SolverRun, ValidationError, solver_status


def find_z3(requested: Path | None) -> Path:
    """Resolve the explicitly selected Z3 executable or search PATH."""
    if requested is not None:
        candidate = requested.expanduser()
        if not candidate.is_file():
            raise ValidationError(f"Z3 executable does not exist: {candidate}")
        return candidate
    located = shutil.which("z3")
    if located is None:
        raise ValidationError("Z3 was not found on PATH; pass --z3")
    return Path(located)


def run_z3(
    executable: Path, script: str, core_query: str, directory: Path, name: str
) -> SolverRun:
    """Retain one verdict and, only for UNSAT, its named core."""
    started = time.perf_counter_ns()
    stdout_path = directory / f"{name}.stdout"
    stderr_path = directory / f"{name}.stderr"
    with stderr_path.open("w", encoding="utf-8") as stderr, subprocess.Popen(
        [str(executable), "-in", "unsat_core=true"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr,
        text=True,
        encoding="utf-8",
    ) as process:
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(script)
        process.stdin.flush()
        first = process.stdout.readline()
        rest, _ = process.communicate(
            input=core_query if first.strip() == "unsat" else None
        )
    output = first + rest
    stdout_path.write_text(output, encoding="utf-8")
    if process.returncode != 0:
        raise ValidationError(
            f"Z3 failed with exit code {process.returncode}; "
            f"see {stdout_path} and {stderr_path}"
        )
    if any(line.lstrip().startswith("(error") for line in output.splitlines()):
        raise ValidationError(f"Z3 rejected the script or query; see {stdout_path}")
    return SolverRun(
        solver_status(output),
        output,
        stderr_path.read_text(encoding="utf-8"),
        (time.perf_counter_ns() - started) / 1_000_000,
    )
