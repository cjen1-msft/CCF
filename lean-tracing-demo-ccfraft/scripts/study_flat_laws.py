#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Check scalar reconstruction and consistency of flat representation headers."""

import argparse
import json
from pathlib import Path

from encoding_study import FULL_CYCLE, save, solve
from study_flat_values import flatten_constant, render, target_sort


def project(expression, sort, route):
    for step in route:
        if step == "is_left":
            expression = f"((_ is (native_left ({render(sort[1])}) {render(sort)})) {expression})"
            sort = "Bool"
        else:
            accessor, side = {
                "fst": ("native_fst", 1), "snd": ("native_snd", 2),
                "left": ("native_left_value", 1), "right": ("native_right_value", 2),
            }[step]
            expression = f"({accessor} {expression})"
            sort = sort[side]
    return expression


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    original = json.loads((args.corpus / "inputs/callback-22/encoding.json").read_text())["script"]
    header = original.split("(declare-const ", 1)[0]
    rows = []
    for kind in ("entry", "packet"):
        sort = target_sort(2, kind)
        declarations, fields = flatten_constant("c_candidate", sort)
        script = header + f"(declare-const c_original {render(sort)})\n" + declarations
        for index, field in enumerate(fields):
            projection = project("c_original", sort, field["route"])
            script += f'(assert (! (= {field["name"]} {projection}) :named field_{index}))\n'
        script += "(assert (! (not (= c_candidate c_original)) :named reconstruction_difference))\n"
        result = solve(args.output / kind, [script], FULL_CYCLE, args.z3, 60, False)
        rows.append({"kind": kind, "expected": "unsat", "result": result})
        save(args.output / "summary.json", rows)
        if result["status"] != "unsat":
            raise ValueError(f"Reconstruction law failed: {kind}: {result}")


if __name__ == "__main__":
    main()
