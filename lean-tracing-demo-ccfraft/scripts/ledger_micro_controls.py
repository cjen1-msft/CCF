#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Operation-matrix controls and symbolic laws for the ledger microbenchmarks."""

import argparse
import json
from pathlib import Path
import subprocess

from encoding_study import FULL_CYCLE, PROJECT, save, solve
from ledger_microbench import generate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    parser.add_argument("--typed-equality", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    requests = []
    operations = [
        ("append", ["native", "store", "cells", "ssa"], [0, 3]),
        ("rollback", ["native", "relation"], [0, 8]),
        ("equality", ["native", "ground", "cells", "canonical", "ssa"], [1, 4]),
    ]
    if args.typed_equality:
        operations = [("equality", ["native", "typed-normalized", "typed-direct"], [1, 4])]
    for operation, variants, starts in operations:
        for variant in variants:
            for count in (1, 3):
                for initial in starts:
                    for observation in ("final", "each", "last"):
                        for negative in (False, True):
                            requests.append({
                                "operation": operation, "variant": variant, "count": count,
                                "initialLength": initial, "observation": observation, "negative": negative,
                            })
    generated, seconds = generate(requests)
    save(args.output / "requests.json", requests)
    save(args.output / "emission.json", {"scripts": len(generated), "seconds": seconds})
    rows = []
    for index, (request, data) in enumerate(zip(requests, generated, strict=True)):
        result = solve(args.output / f"matrix-{index}", [data["encoding"]["script"].removesuffix("(check-sat)\n")],
                       FULL_CYCLE, args.z3, 60, False)
        rows.append({"request": request, "expected": data["metadata"]["expected"], "result": result})
        save(args.output / "matrix.json", rows)
        if result["status"] != data["metadata"]["expected"]:
            raise ValueError(f"Operation-matrix check failed: {rows[-1]}")
    process = subprocess.run(
        ["lake", "env", "lean", "--run", "Prototype/LedgerMicroLawsMain.lean"],
        cwd=PROJECT, text=True, capture_output=True, check=True,
    )
    laws = json.loads(process.stdout)
    rows = []
    for case in laws:
        result = solve(args.output / case["name"], [case["script"].removesuffix("(check-sat)\n")],
                       FULL_CYCLE, args.z3, 60, False)
        rows.append({"name": case["name"], "expected": case["expected"], "result": result})
        save(args.output / "laws.json", rows)
        if result["status"] != case["expected"]:
            raise ValueError(f"Symbolic helper law failed: {case['name']}")


if __name__ == "__main__":
    main()
