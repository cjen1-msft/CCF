#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Serial real-capture C checks with capacity sensitivity and source-core replay."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from encoding_study import FULL_CYCLE, save, solve
from native_origin import reduce_raw
from native_reduction import native_document
from reduction import ReductionError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    parser.add_argument("--counts", nargs="+", type=int, default=[22, 34, 40, 69])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = PROJECT / "Traces/Captured/bad_network.ndjson"
    lines = source.read_bytes().splitlines(keepends=True)
    results = []
    for requested in args.counts:
        count = requested
        while True:
            raw = b"".join(lines[:count])
            try:
                origin = reduce_raw(raw)
                break
            except ReductionError as error:
                if "AppendEntries receive lacks its response helper" not in str(error) or count == len(lines):
                    raise
                count += 1
        document = native_document(origin.trace, ["0"])
        prefix = args.output / f"prefix-{count}.ndjson"
        prefix.write_bytes(raw)
        initial = args.output / f"initial-{count}.json"
        save(initial, {"allocated": ["0"], "ledger_lengths": {
            node: 2 if node == "0" else 0 for node in document["nodes"]}, "queues": []})
        for scale in ([1, 2] if count == 22 else [1]):
            directory = args.output / f"run-{count}-{scale}"
            command = [
                sys.executable, str(PROJECT / "native_lean.py"), str(prefix),
                "--raw", "--bootstrap", "0", "--cells", "--cells-initial-state", str(initial),
                "--cells-capacity-scale", str(scale), "--cells-timeout", "60", "--cells-profile",
                "--z3", args.z3, "--output-dir", str(directory),
            ]
            completed = subprocess.run(command, cwd=PROJECT, capture_output=True, text=True)
            save(args.output / f"command-{count}-{scale}.json", {
                "command": command, "returncode": completed.returncode,
                "stdout": completed.stdout, "stderr": completed.stderr,
            })
            if completed.returncode:
                raise ValueError(f"Real C runner failed: {completed.stderr}")
            result = json.loads((directory / "result.json").read_text())
            reference = (directory / "reference.smt2").read_text()
            baseline = solve(directory / "reference-solver", [reference.removesuffix("(check-sat)\n")],
                             FULL_CYCLE, args.z3, 60, False)
            results.append({"requested": requested, "records": count, "scale": scale,
                            "cells": result, "same_initial_reference": baseline})
            save(args.output / "summary.json", results)
            if result["status"] == "unsat" or baseline["status"] == "unsat":
                raise ValueError(f"Unexpected UNSAT on an original prefix: {count}")
            cells = json.loads((directory / "cells-encoding.json").read_text())
            # Contradict the last native observation, not a synthetic type predicate.
            clauses = cells["clauses"]
            last_name = cells["groups"][-1]["start"]
            selected = next(c for c in clauses if c["name"] == f"assertion_{last_name}")
            script = cells["script"].removesuffix("(check-sat)\n")
            script += f'(assert (! (not {selected["expression"]}) :named cells_conflict))\n'
            negative = solve(directory / "negative", [script], FULL_CYCLE, args.z3, 60, False)
            if negative["status"] != "unsat":
                raise ValueError("Late contradictory cell observation was not rejected")
            mapping = {c["name"]: c["expression"] for c in clauses}
            mapping["cells_conflict"] = f'(not {selected["expression"]})'
            if not set(negative["core"]) <= mapping.keys():
                raise ValueError("Unknown negative-core label")
            replay = cells["script"].split("(assert ", 1)[0] + "".join(
                f"(assert (! {mapping[name]} :named {name}))\n" for name in negative["core"]
            )
            checked = solve(directory / "core-replay", [replay], FULL_CYCLE, args.z3, 60, False)
            if checked["status"] != "unsat":
                raise ValueError("Canonical-cell source core did not replay")
            results[-1].update(negative=negative, core_replay=checked)
            save(args.output / "summary.json", results)
            print(count, scale, result["status"], result["solver_seconds"],
                  "reference", baseline["status"], baseline.get("solver_seconds"), flush=True)


if __name__ == "__main__":
    main()
