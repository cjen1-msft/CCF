#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run the experimental Lean native encoder on reduced Model input."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from native_input import canonical_json, unique_object
from native_origin import RAW_ARTIFACTS, reduce_raw
from native_reduction import native_document
from native_run import (
    ARTIFACTS,
    ENCODER,
    RUN_SCHEMA,
    artifact_hashes,
    core_names,
    run_assurance,
    validate_encoding,
)
from native_solver import find_z3, run_z3
from reduction import ReductionError
from Shared.solver import ValidationError

ROOT = Path(__file__).resolve().parent


def _invoke_encoder(document: object, *arguments: str) -> str:
    """Canonicalize input; Lean validates it and emits every SMT expression."""
    canonical = canonical_json(document)
    completed = subprocess.run(
        ["lake", "env", "lean", "--run", "Sparse/NativeEncodeMain.lean", *arguments],
        cwd=ROOT,
        input=canonical,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if completed.returncode != 0:
        raise ValidationError(
            f"Lean encoder exited {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed.stdout


def encode(document: object) -> str:
    return _invoke_encoder(document)


def encode_details(document: object) -> dict:
    return validate_encoding(
        document,
        json.loads(
            _invoke_encoder(document, "--details"), object_pairs_hook=unique_object
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--z3", type=Path)
    parser.add_argument("--cells", action="store_true", help="use the unproved canonical-cell backend")
    parser.add_argument("--cells-initial-state", type=Path, help="explicit initial allocation, ledger lengths, and queue extents")
    parser.add_argument("--cells-timeout", type=float, default=60, help="cell-backend solver wall-time limit")
    parser.add_argument("--cells-capacity-scale", type=int, default=1, help="multiply derived capacities for differential checks")
    parser.add_argument("--cells-profile", action="store_true", help="collect cell-backend Z3 statistics and quantifier traces")
    parser.add_argument(
        "--raw", action="store_true", help="reduce a raw NDJSON capture"
    )
    parser.add_argument(
        "--bootstrap", nargs="+", help="explicit initial configuration for --raw"
    )
    args = parser.parse_args()
    if args.raw != (args.bootstrap is not None):
        parser.error("--raw requires --bootstrap; --bootstrap is only valid with --raw")
    if args.cells:
        if args.cells_initial_state is None:
            parser.error("--cells requires --cells-initial-state")
        if args.cells_timeout <= 1:
            parser.error("--cells-timeout must be greater than one second")
        try:
            from native_cells_cli import run_cells
            run_cells(args)
        except ModuleNotFoundError as error:
            parser.exit(2, f"Canonical-cell dependency missing: {error}. Use a Python environment with z3-solver.\n")
        except (ValidationError, ReductionError, OSError, ValueError) as error:
            parser.exit(2, f"canonical cells: {error}\n")
        return
    if args.cells_initial_state is not None:
        parser.error("--cells-initial-state is only valid with --cells")
    try:
        reserved = ARTIFACTS + RAW_ARTIFACTS + ("result.json", "result.json.tmp")
        if args.trace.resolve() in {
            (args.output_dir / name).resolve() for name in reserved
        }:
            raise ValidationError("input trace aliases a reserved output artifact")
        args.output_dir.mkdir(parents=True, exist_ok=True)
        result_path = args.output_dir / "result.json"
        result_path.unlink(missing_ok=True)
        raw_data = args.trace.read_bytes()
        origin = reduce_raw(raw_data) if args.raw else None
        document = (
            native_document(origin.trace, args.bootstrap)
            if origin is not None
            else json.loads(raw_data.decode("utf-8"), object_pairs_hook=unique_object)
        )
        z3 = find_z3(args.z3)
        details = encode_details(document)
        formula = args.output_dir / "trace.smt2"
        formula.write_text(details["script"], encoding="ascii")
        artifacts = [("input.json", document), ("encoding.json", details)]
        if origin is not None:
            (args.output_dir / "raw.ndjson").write_bytes(raw_data)
            artifacts.append(("reduction.json", origin.certificate))
        for name, value in artifacts:
            (args.output_dir / name).write_text(
                json.dumps(value, ensure_ascii=True, allow_nan=False) + "\n",
                encoding="utf-8",
            )
        result = run_z3(
            z3,
            details["script"],
            details["queries"]["unsatCore"],
            args.output_dir,
            "trace",
        )
        core_names(result, details)
        summary = {
            "schema": RUN_SCHEMA,
            "encoder": ENCODER,
            "solver": "z3",
            "status": result.status,
            "solver_ms": result.wall_time_ms,
            "assurance": run_assurance(raw=args.raw),
            "artifacts": artifact_hashes(args.output_dir, raw=args.raw),
            **({"origin": "raw"} if args.raw else {}),
        }
        temporary_result = args.output_dir / "result.json.tmp"
        temporary_result.write_text(json.dumps(summary) + "\n", encoding="utf-8")
        temporary_result.replace(result_path)
    except (ValidationError, ReductionError, OSError, ValueError) as error:
        parser.exit(2, f"native Lean encoder: {error}\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
