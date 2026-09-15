#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Differential complete-handler fixtures for the finite-cell representation."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from encoding_study import FULL_CYCLE, save, solve
from native_cells import lower
from native_lean import encode_details


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    completed = subprocess.run(
        ["lake", "env", "lean", "--run", "Sparse/NativeArrayAppendReceiveFixtureMain.lean"],
        cwd=PROJECT, capture_output=True, text=True, check=True,
    )
    selected = {}
    for fixture in json.loads(completed.stdout):
        selected.setdefault((fixture["branch"], fixture["expected"]), fixture)
    save(args.output / "fixtures.json", list(selected.values()))
    results = []
    for index, fixture in enumerate(selected.values()):
        native = encode_details(fixture["trace"])
        capacities = {"nodes": len(fixture["trace"]["nodes"]), "ledger": 8, "queue": 8}
        cells = lower(native, capacities, initial=False)
        directory = args.output / f"case-{index}"
        save(directory / "native.json", native)
        save(directory / "cells.json", cells)
        row = {"branch": fixture["branch"], "expected": fixture["expected"], "scenario": fixture["scenario"]}
        for name, script in (("native", native["script"]), ("cells", cells["script"])):
            result = solve(directory / name, [script.removesuffix("(check-sat)\n")],
                           FULL_CYCLE, args.z3, 60, False)
            row[name] = result
            if result["status"] != fixture["expected"]:
                save(args.output / "failure.json", row)
                raise ValueError(f"Model fixture disagrees: {row}")
        results.append(row)
        save(args.output / "summary.json", results)
        print(index, row["branch"], row["expected"], flush=True)


if __name__ == "__main__":
    main()
