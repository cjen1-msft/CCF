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
from native_run import (
    ASSURANCE,
    ENCODER,
    RUN_SCHEMA,
    artifact_hashes,
    core_names,
    validate_encoding,
)
from native_solver import find_z3, run_z3
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
    args = parser.parse_args()
    try:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        result_path = args.output_dir / "result.json"
        result_path.unlink(missing_ok=True)
        document = json.loads(
            args.trace.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
        details = encode_details(document)
        z3 = find_z3(args.z3)
        formula = args.output_dir / "trace.smt2"
        formula.write_text(details["script"], encoding="ascii")
        for name, value in (("input.json", document), ("encoding.json", details)):
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
            "assurance": ASSURANCE,
            "artifacts": artifact_hashes(args.output_dir),
        }
        temporary_result = args.output_dir / "result.json.tmp"
        temporary_result.write_text(json.dumps(summary) + "\n", encoding="utf-8")
        temporary_result.replace(result_path)
    except (ValidationError, OSError, ValueError) as error:
        parser.exit(2, f"native Lean encoder: {error}\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
