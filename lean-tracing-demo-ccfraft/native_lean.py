#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run the experimental Lean native encoder on reduced Model input."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

from native_input import unique_object
from Shared.solver import ValidationError, find_cvc5, run_solver

ROOT = Path(__file__).resolve().parent
SOLVER_ARGUMENTS = ("--arrays-exp", "--mbqi")


def encode(document: object) -> str:
    """Canonicalize input; Lean validates it and emits every SMT expression."""
    canonical = json.dumps(
        document,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    )
    completed = subprocess.run(
        ["lake", "env", "lean", "--run", "Sparse/NativeEncodeMain.lean"],
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--cvc5", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(
            args.trace.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
        script = encode(document)
        cvc5 = find_cvc5(args.cvc5)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        formula = args.output_dir / "trace.smt2"
        formula.write_text(script, encoding="ascii")
        result = run_solver(
            cvc5, formula, args.output_dir, "trace", extra_arguments=SOLVER_ARGUMENTS
        )
    except (ValidationError, OSError, ValueError) as error:
        parser.exit(2, f"native Lean encoder: {error}\n")
    print(
        json.dumps(
            {
                "encoder": "native-lean-experimental",
                "status": result.status,
                "solver_ms": result.wall_time_ms,
            }
        )
    )


if __name__ == "__main__":
    main()
