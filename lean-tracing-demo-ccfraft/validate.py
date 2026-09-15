#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Reduce raw CCFRaft traces to symbolic certificates for the checked encoder.

The caller must declare all five model bounds. Normalization preserves partial
observations and does not choose an entry state. Only the checked backend can
issue a bounded-model verdict; Python reduction and provenance remain trusted.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import sys
import time

from raw_normalization import BOUND_FIELDS, normalize
from reduction import ReductionError, preprocess, reduce, write_certificate
from Shared.smt import SmtEncodingError, add_query, write_formula
from Shared.solver import (
    SolverRun,
    ValidationError,
    find_cvc5,
    query_payload,
    run_solver,
    solver_status,
)
from Shared.trace_io import NDJSONError, read_ndjson
import validate_checked as checked

# Historical imports are aliases, not alternate solver implementations.
_find_cvc5 = find_cvc5
_solver_status = solver_status
_run_solver = run_solver
_query_payload = query_payload

__all__ = ["SolverRun", "ValidationError", "validate"]

RAW_ARTIFACTS = (
    "certificate.json",
    "reduced-certificate.json",
    "normalization.json",
    "provenance.json",
    "evidence.json",
    "proof.txt",
    "formula-reduced-proof.smt2",
)
VALIDATION_ERRORS = (
    NDJSONError,
    ReductionError,
    SmtEncodingError,
    ValidationError,
    OSError,
    json.JSONDecodeError,
    UnicodeError,
)


def require_bounds(bounds: object) -> Mapping[str, object]:
    """Reject invalid profiles before capture, parsing, or native gate work."""
    if not isinstance(bounds, Mapping):
        raise ReductionError(
            "explicit bounds Mapping is required; CLI callers must pass --bounds"
        )
    if set(bounds) != BOUND_FIELDS:
        raise ReductionError("declare exactly the five model bounds")
    if not all(type(value) is int and value >= 0 for value in bounds.values()):
        raise ReductionError("model bounds must be non-negative integers")
    return bounds


def read_bounds(path: Path) -> Mapping[str, object]:
    """Read and validate an explicit five-bound JSON profile."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ReductionError(f"bounds profile is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ReductionError("bounds profile must be a JSON object")
    return require_bounds(value)


def artifact_paths(output_directory: Path) -> tuple[Path, ...]:
    return (
        *checked.artifact_paths(output_directory),
        *(output_directory / name for name in RAW_ARTIFACTS),
    )


def clear_artifacts(
    output_directory: Path, *, protected_inputs: Sequence[Path] = ()
) -> None:
    """Reject input collisions before clearing artifacts from either runner."""
    paths = artifact_paths(output_directory)
    checked.reject_artifact_collisions(protected_inputs, paths)
    output_directory.mkdir(parents=True, exist_ok=True)
    for path in paths:
        path.unlink(missing_ok=True)


def _proof(output_directory: Path, result: dict[str, object], show: bool) -> None:
    """Retain the historical proof query without reimplementing core reduction."""
    formula = (output_directory / "formula-reduced.smt2").read_text(encoding="utf-8")
    proof_formula = output_directory / "formula-reduced-proof.smt2"
    write_formula(proof_formula, add_query(formula, "get-proof"))
    solver = result["cvc5"]
    if not isinstance(solver, str):
        raise ValidationError("checked result has no solver path")
    proof_run = run_solver(Path(solver), proof_formula, output_directory, "cvc5-proof")
    if proof_run.status != "unsat":
        raise ValidationError("proof run did not reproduce UNSAT")
    proof = query_payload(proof_run, "a proof")
    (output_directory / "proof.txt").write_text(proof, encoding="utf-8")
    result.update(
        proof="proof.txt",
        proof_checked_by_cvc5=True,
        proof_formula=proof_formula.name,
        proof_scope=result["core_kind"],
        proof_wall_ms=proof_run.wall_time_ms,
    )
    total = result["total_solver_wall_ms"]
    if not isinstance(total, (int, float)):
        raise ValidationError("checked result has no total solver timing")
    result["total_solver_wall_ms"] = total + proof_run.wall_time_ms
    if show:
        print(proof, end="" if proof.endswith("\n") else "\n")


def validate(
    input_path: Path,
    output_directory: Path,
    *,
    bounds: Mapping[str, object] | None = None,
    cvc5: Path | None = None,
    show_proof: bool = False,
    inspect_group: int | None = None,
    core_reduction_budget_seconds: float = 5.0,
    encode_only: bool = False,
) -> str:
    """Normalize then delegate to the checked backend, with no fallback.

    Missing bounds are an error, including on a reused output directory.
    ``encode_only`` still builds the proof gate and runs the checked encoder,
    but returns ``encoded`` rather than a solver verdict. SMT cores describe
    constraints, not replayable subsequences of raw actions.
    """
    started = time.perf_counter_ns()
    clear_artifacts(output_directory, protected_inputs=(input_path,))
    try:
        bounds = require_bounds(bounds)
        if inspect_group is not None and inspect_group < 1:
            raise ValidationError("--inspect-group selects a step, so it starts at 1")
        if encode_only and show_proof:
            raise ValidationError("encode-only cannot produce a solver proof")
        phases: dict[str, float] = {}
        phase_started = time.perf_counter_ns()
        records = read_ndjson(input_path)
        phases["ndjson_parse"] = (time.perf_counter_ns() - phase_started) / 1_000_000
        phase_started = time.perf_counter_ns()
        preprocessed = preprocess(records)
        phases["preprocess"] = (time.perf_counter_ns() - phase_started) / 1_000_000
        phase_started = time.perf_counter_ns()
        reduced = reduce(preprocessed)
        phases["reduction"] = (time.perf_counter_ns() - phase_started) / 1_000_000
        phase_started = time.perf_counter_ns()
        write_certificate(output_directory / "reduced-certificate.json", reduced)
        phases["reduced_certificate_write"] = (
            time.perf_counter_ns() - phase_started
        ) / 1_000_000
        phase_started = time.perf_counter_ns()
        normalized = normalize(reduced)
        certificate = normalized.certificate(bounds)
        phases["normalization"] = (time.perf_counter_ns() - phase_started) / 1_000_000
        phase_started = time.perf_counter_ns()
        certificate_path = output_directory / "certificate.json"
        write_certificate(certificate_path, certificate)
        write_certificate(
            output_directory / "normalization.json",
            {
                "node_names": normalized.node_names,
                "transaction_names": {
                    name: {"unknown": name} for name in normalized.unknowns
                },
            },
        )
        write_certificate(
            output_directory / "evidence.json",
            {str(index): evidence for index, evidence in normalized.evidence.items()},
        )
        provenance = {}
        action_boundary = 0
        for index, step in enumerate(normalized.steps, 1):
            action_boundary += step["kind"] == "action"
            provenance[str(index)] = {
                "provenance": step["provenance"],
                "rule": step["rule"],
                "action_boundary": action_boundary,
            }
        write_certificate(output_directory / "provenance.json", provenance)
        phases["certificate_write"] = (
            time.perf_counter_ns() - phase_started
        ) / 1_000_000
        phase_started = time.perf_counter_ns()
        if encode_only:
            gate = checked.build_proof_gate(
                checked.PROJECT_ROOT, output_directory / "lake-build.log"
            )
            encoder_ms = checked.run_encoder(
                checked.PROJECT_ROOT,
                certificate_path,
                output_directory,
                inspect_group=inspect_group,
            )
            constraint_map = checked.read_constraint_map(
                output_directory / "constraint-map.json", inspect_group=inspect_group
            )
            if not (output_directory / "formula.smt2").is_file():
                raise ValidationError("the Lean encoder emitted no formula")
            status = "encoded"
            result = {
                "status": status,
                "proof_gate": gate,
                "encoder_wall_ms": encoder_ms,
                "constraint_map": "constraint-map.json",
                "formula": "formula.smt2",
                "assurance": checked._assurance(
                    constraint_map, inspect_group=inspect_group
                ),
                "interpretation": "checked encoding only; the solver was not run",
            }
        else:
            status = checked.validate_checked(
                certificate_path,
                output_directory,
                cvc5=cvc5,
                inspect_group=inspect_group,
                core_reduction_budget_seconds=core_reduction_budget_seconds,
            )
            result = json.loads(
                (output_directory / "result.json").read_text(encoding="utf-8")
            )
            if not isinstance(result, dict) or result.get("status") != status:
                raise ValidationError("checked result does not match returned status")
            result["checked_validation_wall_ms"] = result["validation_wall_ms"]
        phases["checked_backend"] = (time.perf_counter_ns() - phase_started) / 1_000_000
        if status == "unsat":
            _proof(output_directory, result, show_proof)
        result.update(
            certificate=certificate_path.name,
            reduced_certificate="reduced-certificate.json",
            normalization="normalization.json",
            provenance="provenance.json",
            evidence="evidence.json",
            raw_trace=str(input_path.resolve()),
            nodes=list(normalized.node_names.values()),
            phase_wall_ms=phases,
            validation_wall_ms=(time.perf_counter_ns() - started) / 1_000_000,
        )
        write_certificate(output_directory / "result.json", result)
        return status
    except VALIDATION_ERRORS as error:
        (output_directory / "result.json").unlink(missing_ok=True)
        checked._record_failure(output_directory, error)
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="captured NDJSON trace")
    parser.add_argument("output_directory", type=Path, nargs="?")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--bounds",
        type=Path,
        required=True,
        help="JSON object declaring all five bounds",
    )
    parser.add_argument("--cvc5", type=Path, help="cvc5 executable; defaults to PATH")
    parser.add_argument("--show-proof", action="store_true")
    parser.add_argument("--inspect-group", type=int)
    parser.add_argument(
        "--core-reduction-seconds",
        type=float,
        default=5.0,
        help="wall-clock budget for automatic UNSAT core reduction",
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
        # Profile loading can fail before validate() has cleared an earlier run.
        clear_artifacts(
            args.output_directory, protected_inputs=(args.input, args.bounds)
        )
        bounds = read_bounds(args.bounds)
        validate(
            args.input,
            args.output_directory,
            bounds=bounds,
            cvc5=args.cvc5,
            show_proof=args.show_proof,
            inspect_group=args.inspect_group,
            core_reduction_budget_seconds=args.core_reduction_seconds,
        )
    except checked.ArtifactCollision as error:
        print(f"validation refused: {error}", file=sys.stderr)
        return 2
    except VALIDATION_ERRORS as error:
        checked._record_failure(args.output_directory, error)
        print(f"validation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
