#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Check C's shared-state miters and replay source cores by instruction groups."""

import argparse
import json
from pathlib import Path
import subprocess

from encoding_study import FULL_CYCLE, PROJECT, save, solve


def grouped(details):
    groups = {}
    for index, group in enumerate(details["groups"]):
        clauses = details["clauses"][group["start"]:group["stop"]]
        groups[f"study_group_{index}"] = "(and true " + " ".join(
            clause["expression"] for clause in clauses
        ) + ")"
    body = "".join(f'(assert (! {c["expression"]} :named {c["name"]}))\n' for c in details["clauses"])
    suffix = body + "(check-sat)\n"
    if not details["script"].endswith(suffix):
        raise ValueError("Native clause metadata mismatch")
    groups["study_conflict"] = "(not " + details["clauses"][details["groups"][-1]["start"]]["expression"] + ")"
    return details["script"][:-len(suffix)], groups


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    parser.add_argument("--broad-miters", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    miters = []
    if args.broad_miters:
        completed = subprocess.run(
            ["lake", "env", "lean", "--run", "Prototype/EvidenceMiterMain.lean"],
            cwd=PROJECT, text=True, capture_output=True, check=True,
        )
        miters = json.loads(completed.stdout)
    rows = []
    for case in miters:
        feasible = solve(args.output / f'{case["name"]}-feasible',
                         [case["feasibleScript"].removesuffix("(check-sat)\n")],
                         FULL_CYCLE, args.z3, 60, False)
        rows.append({"kind": "miter-feasibility", "name": case["name"], "result": feasible})
        save(args.output / "summary.json", rows)
        if feasible["status"] != "sat":
            raise ValueError(f"Cannot establish non-vacuous miter: {case['name']}: {feasible}")
        result = solve(args.output / case["name"], [case["script"].removesuffix("(check-sat)\n")],
                       FULL_CYCLE, args.z3, 60, False)
        rows.append({"kind": "shared-state-miter", "name": case["name"], "result": result})
        save(args.output / "summary.json", rows)
        if result["status"] in {"sat", "error"}:
            raise ValueError(f"Conditional-equivalence miter failed: {case['name']}")
    sources = {}
    for mode in ("generic", "specialised"):
        details = json.loads(
            (args.corpus / "variants" / f"evidence-{mode}-v2" / "bad-prefix-34/encoding.json").read_text()
        )
        sources[mode] = grouped(details)
    for mode, (head, groups) in sources.items():
        script = head + "".join(f"(assert (! {expression} :named {name}))\n" for name, expression in groups.items())
        result = solve(args.output / f"negative-{mode}", [script], FULL_CYCLE, args.z3, 60, False)
        if result["status"] != "unsat" or "study_conflict" not in result["core"]:
            raise ValueError(f"Negative control failed: {result}")
        replays = {}
        for target, (target_head, target_groups) in sources.items():
            if not set(result["core"]) <= target_groups.keys():
                raise ValueError("Unknown instruction-group core name")
            replay = target_head + "".join(
                f"(assert (! {target_groups[name]} :named {name}))\n" for name in result["core"]
            )
            checked = solve(args.output / f"{mode}-replay-{target}", [replay], "(check-sat)\n",
                            args.z3, 60, False)
            if checked["status"] != "unsat":
                raise ValueError(f"Instruction-group core replay failed: {checked}")
            replays[target] = checked
        rows.append({"kind": "negative-core", "mode": mode, "result": result, "replays": replays})
        save(args.output / "summary.json", rows)


if __name__ == "__main__":
    main()
