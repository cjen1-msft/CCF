#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Model-derived C path controls, including feasible shared-state successor miters."""

import argparse
import json
from pathlib import Path
import subprocess

from encoding_study import FULL_CYCLE, PROJECT, save, solve


def lean(module, arguments=(), data=None):
    completed = subprocess.run(
        ["lake", "env", "lean", "--run", f"Prototype/{module}.lean", *arguments],
        cwd=PROJECT, text=True, capture_output=True, check=True,
        input=None if data is None else json.dumps(data, sort_keys=True, separators=(",", ":")),
    )
    return json.loads(completed.stdout)


def envelope(fixture):
    document = fixture["trace"]
    items = document["instructions"]
    index = next(i for i, item in enumerate(items) if item["kind"] == "receiveAppendEntries")
    action = items[index]
    facts = {item["kind"]: item["value"] for item in items[:index]
             if item.get("node") == action["destination"] and "value" in item}
    packet = next(item["value"] for item in items[:index] if item["kind"] == "queuePoint"
                  and item["source"] == action["source"] and item["destination"] == action["destination"]
                  and item["index"] == 0)
    path = "appendAtEnd" if facts["logLength"] == packet["prevLogIndex"] else "rejectBeyondEnd"
    plan = {
        "instruction": index, "source": action["source"], "destination": action["destination"],
        "path": path, "oldLength": facts["logLength"], "previous": packet["prevLogIndex"],
        "term": packet["term"], "entriesLength": len(packet["entries"]),
        "leaderCommit": packet["leaderCommit"], "previousTerm": packet["prevLogTerm"],
        "oldCommit": facts["commit"], "sourceLine": 0, "responseLine": 0, "executionLine": 0,
    }
    return {"input": document, "plans": [plan]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixtures = lean("EvidenceFixtureMain")
    inputs = [envelope(fixture) for fixture in fixtures]
    save(args.output / "fixtures.json", fixtures)
    save(args.output / "envelopes.json", inputs)
    generic = lean("TraceEvidenceMain", ["--batch", "generic"], inputs)
    specialised = lean("TraceEvidenceMain", ["--batch", "specialised"], inputs)
    rows = []
    selected = {}
    for index, (fixture, data, g, s) in enumerate(zip(fixtures, inputs, generic, specialised, strict=True)):
        row = {"index": index, "expected": fixture["expected"], "scenario": fixture["scenario"]}
        for mode, details in (("generic", g), ("specialised", s)):
            result = solve(args.output / f"{index}-{mode}",
                           [details["script"].removesuffix("(check-sat)\n")],
                           FULL_CYCLE, args.z3, 60, False)
            row[mode] = result
            if result["status"] != fixture["expected"]:
                save(args.output / "failure.json", row)
                raise ValueError(f"Model fixture mismatch: {index}: {row}")
        rows.append(row)
        save(args.output / "summary.json", rows)
        if fixture["expected"] == "sat":
            plan = data["plans"][0]
            key = (plan["path"], plan["oldLength"], plan["source"] == plan["destination"])
            selected.setdefault(key, {**data, "name": f"fixture-{index}"})
    miters = lean("EvidenceMiterMain", ["--fixtures"], list(selected.values()))
    checks = []
    for case in miters:
        for field, expected in (("feasibleScript", "sat"), ("script", "unsat")):
            result = solve(args.output / f'{case["name"]}-{field}',
                           [case[field].removesuffix("(check-sat)\n")],
                           FULL_CYCLE, args.z3, 60, False)
            checks.append({"name": case["name"], "query": field, "expected": expected, "result": result})
            save(args.output / "miters.json", checks)
            if result["status"] != expected:
                raise ValueError(f"Model-grounded miter inconclusive or failed: {checks[-1]}")


if __name__ == "__main__":
    main()
