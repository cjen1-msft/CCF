#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Differential Model-fixture controls for isolated Lean receive prototypes."""

import argparse
import json
from pathlib import Path
import subprocess

from encoding_study import FULL_CYCLE, PROJECT, save, solve


def lean(module, document=None, arguments=()):
    command = ["lake", "env", "lean", "--run", module]
    if document is not None:
        command.append("--batch")
        command.extend(arguments)
    result = subprocess.run(
        command, cwd=PROJECT, text=True, capture_output=True, check=True,
        input=None if document is None else json.dumps(document, sort_keys=True, separators=(",", ":")),
    )
    return json.loads(result.stdout)


def name_assertions(script):
    lines = []
    index = 0
    for line in script.splitlines(keepends=True):
        if line.startswith("(assert "):
            if not line.endswith(")\n") or ":named " in line:
                raise ValueError("Expected an unnamed, single-line native assertion")
            lines.append(f"(assert (! {line[8:-2]} :named assertion_{index}))\n")
            index += 1
        else:
            lines.append(line)
    if index == 0:
        raise ValueError("No native assertions found")
    return "".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    parser.add_argument("--reference-module")
    parser.add_argument("--reference-arguments", nargs="*", default=[])
    parser.add_argument("--candidate-arguments", nargs="*", default=[])
    parser.add_argument("--cells-bound", type=int)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixtures = lean("Sparse/NativeArrayAppendReceiveFixtureMain.lean")
    selected = {}
    for fixture in fixtures:
        key = (fixture["branch"], fixture["expected"], fixture["scenario"])
        selected.setdefault(key, fixture)
    cases = list(selected.values())
    save(args.output / "fixtures.json", cases)
    documents = [case["trace"] for case in cases]
    if args.reference_module:
        baseline = [item["script"] for item in lean(
            f"Prototype/{args.reference_module}.lean", documents, args.reference_arguments)]
    else:
        baseline = [name_assertions(script) for script in lean("Sparse/NativeEncodeMain.lean", documents)]
    candidate = lean(f"Prototype/{args.module}.lean", documents, args.candidate_arguments)
    if args.cells_bound is not None:
        from study_finite_cells import transform
        candidate = [
            {**item, "script": transform(item["script"], len(item["input"]["nodes"]), args.cells_bound)[0]}
            for item in candidate
        ]
    results = []
    for index, (case, original, proposed) in enumerate(zip(cases, baseline, candidate, strict=True)):
        row = {"index": index, "branch": case["branch"], "scenario": case["scenario"],
               "expected": case["expected"]}
        for name, script in (("reference", original), ("candidate", proposed["script"])):
            if not script.endswith("(check-sat)\n"):
                raise ValueError("Unexpected script query")
            result = solve(args.output / f"{index}-{name}", [script.removesuffix("(check-sat)\n")],
                           FULL_CYCLE, args.z3, 60, False)
            row[name] = result
            if result["status"] != case["expected"]:
                save(args.output / "failure.json", row)
                raise ValueError(f"Differential control failed: {row}")
        results.append(row)
        save(args.output / "summary.json", results)
        print(index, case["branch"], case["scenario"], case["expected"], flush=True)


if __name__ == "__main__":
    main()
