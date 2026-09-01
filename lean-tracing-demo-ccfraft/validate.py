#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Validate a captured CCFRaft trace with the projected-state SMT backend.

The SMT result covers only the term, role, log-length, commit-index,
allocation, and joined projection in ``Shared/smt.py``. This executable does
not run the Lean-proved full symbolic lowering.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from reduction import ReductionError, build_certificate, write_certificate
from Shared.smt import (
    SmtEncodingError,
    add_query,
    build_formula,
    write_formula,
)
from Shared.trace_io import NDJSONError, read_ndjson


class ValidationError(RuntimeError):
    """Report solver discovery, execution, or output failures."""


@dataclass(frozen=True)
class SolverRun:
    """One complete cvc5 invocation."""

    status: str
    stdout: str
    stderr: str
    wall_time_ms: float


def _find_cvc5(requested: Path | None) -> Path:
    if requested is not None:
        candidate = requested.expanduser()
        if not candidate.is_file():
            raise ValidationError(f"cvc5 executable does not exist: {candidate}")
        return candidate
    located = shutil.which("cvc5")
    if located is None:
        raise ValidationError("cvc5 was not found on PATH; pass --cvc5")
    return Path(located)


def _solver_status(stdout: str) -> str:
    statuses = [
        line.strip()
        for line in stdout.splitlines()
        if line.strip() in {"sat", "unsat", "unknown"}
    ]
    if not statuses:
        raise ValidationError("cvc5 stdout did not contain sat, unsat, or unknown")
    return statuses[0]


def _run_solver(
    cvc5: Path,
    formula_path: Path,
    output_directory: Path,
    artifact_stem: str,
) -> SolverRun:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        [str(cvc5), "--lang=smt2", str(formula_path)],
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
        _solver_status(completed.stdout),
        completed.stdout,
        completed.stderr,
        wall_time_ms,
    )


def _query_payload(run: SolverRun, query: str) -> str:
    lines = run.stdout.splitlines(keepends=True)
    status_position = next(
        (
            position
            for position, line in enumerate(lines)
            if line.strip() in {"sat", "unsat", "unknown"}
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


def validate(
    input_path: Path,
    output_directory: Path,
    *,
    cvc5: Path | None = None,
    show_proof: bool = False,
) -> str:
    """Reduce, encode, solve, and retain all solver evidence."""

    output_directory.mkdir(parents=True, exist_ok=True)
    certificate = build_certificate(read_ndjson(input_path))
    certificate_path = output_directory / "certificate.json"
    write_certificate(certificate_path, certificate)

    formula = build_formula(certificate)
    formula_path = output_directory / "formula.smt2"
    write_formula(formula_path, formula)

    solver = _find_cvc5(cvc5)
    status_run = _run_solver(
        solver,
        formula_path,
        output_directory,
        "cvc5-status",
    )
    status = status_run.status
    print(status, flush=True)

    result: dict[str, object] = {
        "certificate": certificate_path.name,
        "cvc5": str(solver),
        "formula": formula_path.name,
        "nodes": list(formula.nodes),
        "check_sat_wall_ms": status_run.wall_time_ms,
        "status": status,
        "total_solver_wall_ms": status_run.wall_time_ms,
    }

    if status == "unsat":
        core_formula_path = output_directory / "formula-unsat-core.smt2"
        write_formula(core_formula_path, add_query(formula.text, "get-unsat-core"))
        core_run = _run_solver(
            solver,
            core_formula_path,
            output_directory,
            "cvc5-unsat-core",
        )
        if core_run.status != "unsat":
            raise ValidationError("unsat-core run did not reproduce UNSAT")
        core = _query_payload(core_run, "an unsat core")
        core_path = output_directory / "unsat-core.txt"
        core_path.write_text(core, encoding="utf-8")

        proof_formula_path = output_directory / "formula-proof.smt2"
        write_formula(proof_formula_path, add_query(formula.text, "get-proof"))
        proof_run = _run_solver(
            solver,
            proof_formula_path,
            output_directory,
            "cvc5-proof",
        )
        if proof_run.status != "unsat":
            raise ValidationError("proof run did not reproduce UNSAT")
        proof = _query_payload(proof_run, "a proof")
        proof_path = output_directory / "proof.txt"
        proof_path.write_text(proof, encoding="utf-8")
        result.update(
            {
                "proof": proof_path.name,
                "proof_checked_by_cvc5": True,
                "proof_wall_ms": proof_run.wall_time_ms,
                "unsat_core": core_path.name,
                "unsat_core_checked_by_cvc5": True,
                "unsat_core_wall_ms": core_run.wall_time_ms,
                "total_solver_wall_ms": (
                    status_run.wall_time_ms
                    + core_run.wall_time_ms
                    + proof_run.wall_time_ms
                ),
            }
        )
        if show_proof:
            print(proof, end="" if proof.endswith("\n") else "\n")

    (output_directory / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return status


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="captured NDJSON trace")
    parser.add_argument(
        "output_directory",
        type=Path,
        nargs="?",
        help="directory for the certificate, formula, and solver output",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="directory for the certificate, formula, and solver output",
    )
    parser.add_argument(
        "--cvc5",
        type=Path,
        help="cvc5 executable; defaults to cvc5 on PATH",
    )
    parser.add_argument(
        "--show-proof",
        action="store_true",
        help="print the checked cvc5 proof after the status line",
    )
    args = parser.parse_args(argv)
    if args.output_directory is None and args.output_dir is None:
        parser.error("an output directory is required")
    if (
        args.output_directory is not None
        and args.output_dir is not None
        and args.output_directory != args.output_dir
    ):
        parser.error("give the output directory once")
    args.output_directory = args.output_dir or args.output_directory
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        validate(
            args.input,
            args.output_directory,
            cvc5=args.cvc5,
            show_proof=args.show_proof,
        )
    except (
        NDJSONError,
        ReductionError,
        SmtEncodingError,
        ValidationError,
        OSError,
    ) as error:
        print(f"validation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
