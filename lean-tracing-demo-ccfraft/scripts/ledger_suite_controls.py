#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Check matched ledger backends against native operations and each other."""

from copy import deepcopy
import argparse
import json
from pathlib import Path
import re
import subprocess

from encoding_study import FULL_CYCLE, PROJECT, digest, save, solve
from ledger_suite import closure, encode, helpers, oracle, plan


def rename(encoded, header, prefix):
    body = encoded["script"][len(header):]
    symbols = re.findall(r"\(declare-const ([A-Za-z0-9_]+) ", body)
    names = set(symbols) | set(encoded["groups"])
    return re.sub(r"[A-Za-z_][A-Za-z0-9_]*",
                  lambda m: prefix + m[0] if m[0] in names else m[0], body)


def difference(stream, left, right):
    clauses = []
    for state, size in left["state_lengths"].items():
        if right["state_lengths"][state] != size:
            raise ValueError("Backend static state extents differ")
        clauses.append(f"(not (= l_length_{state} r_length_{state}))")
        for index in range(size):
            a = f'l_{left["cell_symbols"][state][index]}' if left["representation"] == "C" else f"(select l_{state} {index})"
            b = f'r_{right["cell_symbols"][state][index]}' if right["representation"] == "C" else f"(select r_{state} {index})"
            clauses.append(f"(not (= {a} {b}))")
    for event in stream["events"]:
        if event["kind"] == "equality":
            clauses.append(f'(not (= l_{event["result"]} r_{event["result"]}))')
    return "(or false " + " ".join(clauses) + ")"


def operand_tails(stream, representation):
    if stream["workload"] not in ("equality", "mixed") or representation == "C":
        return ""
    if stream["workload"] == "mixed":
        sides = {name: side for side, name in enumerate(stream["initial_states"])}
        for event in stream["events"]:
            if event["kind"] != "equality":
                sides[event["after"]] = sides[event["before"]]
        index = stream["capacity"] + 3
        return "".join(
            f"(assert (! (= (select {state} {index}) "
            f'{"(make_transaction (- 9) (- 2))" if side == 0 else "(make_signature 0)"}) '
            f":named different_tail_{state}))\n"
            for state, side in sides.items()
        )
    comparison = stream["events"][0]
    left, right = comparison["left"], comparison["right"]
    index = stream["capacity"] + 3
    return (
        f"(assert (! (= (select {left} {index}) (make_transaction (- 9) (- 2))) :named left_operand_tail))\n"
        f"(assert (! (= (select {right} {index}) (make_signature 0)) :named right_operand_tail))\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--helpers", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    parser.add_argument("--workload", choices=["append", "rollback", "equality", "mixed"], required=True)
    parser.add_argument("--representation", choices=["R", "C", "A"], required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    header = helpers(args.helpers)
    files = ["scripts/ledger_suite.py", "scripts/ledger_suite_controls.py", "scripts/encoding_study.py",
             "Prototype/LedgerSuiteTermsMain.lean", "Prototype/LedgerSuiteOracleMain.lean",
             "Sparse/NativeArrayLogWrite.lean", "Sparse/NativeLogSpliceEncoding.lean",
             "Sparse/NativeValues.lean"]
    save(args.output / "configuration.json", {
        "workload": args.workload, "representation": args.representation,
        "source_hashes": {name: digest((PROJECT / name).read_bytes()) for name in files},
        "native_helper_sha256": digest(header.encode()),
        "native_dependencies": json.loads((args.helpers / "native-terms.json").read_text())["dependency_hashes"],
    })
    for name in files:
        path = args.output / "sources" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((PROJECT / name).read_bytes())
    streams = []
    for initial in (1, 4):
        for regime in ("concrete", "symbolic"):
            positive = plan(args.workload, 1, initial, regime)
            # Exercise every constructor in a separate representative stream.
            varied = deepcopy(positive)
            for index, value in enumerate(varied["entries"].values()):
                kind = ("transaction", "signature", "configuration", "retirement")[index % 4]
                value["kind"] = kind
                value["value"] = value["value"] if kind == "transaction" else 0 if kind == "signature" else index % 4
            streams.extend([positive, varied])
    # Two cycles/operations exercise transition composition; rollback needs room.
    streams.append(plan(args.workload, 2, 4, "symbolic"))
    zero = plan(args.workload, 1, 4, "concrete")
    next(iter(zero["entries"].values()))["value"] = 0
    streams.append(zero)
    if args.workload == "append":
        streams.append(plan("append", 2, 0, "symbolic"))
        for kind in ("transaction", "signature", "configuration", "retirement"):
            item = plan("append", 1, 0, "concrete")
            value = next(iter(item["entries"].values()))
            value.update(kind=kind, value=0 if kind == "signature" else 1)
            streams.append(item)
        equal_values = plan("append", 2, 1, "symbolic")
        for value in equal_values["entries"].values():
            value.update(term=0, kind="transaction", value=0)
        streams.append(equal_values)
        streams.append(plan("append", 2, 1, "symbolic", batch_size=4))
    if args.workload == "rollback":
        for target in (0, 1, 4, 7):
            boundary = plan("rollback", 1, 4, "symbolic")
            boundary["events"][0]["target"] = target
            size = min(target, 4)
            boundary["observations"] = [{"kind": "length", "state": "state_1", "expected": size}]
            if size:
                boundary["observations"].append({
                    "kind": "entry", "state": "state_1", "index": 0,
                    "entry": boundary["initial_states"]["state_0"][0],
                })
            streams.append(boundary)
    if args.workload == "equality":
        for kind in ("equal", "unequal"):
            streams.append(plan("equality", 4, 4, "symbolic", axis="length", equality_kind=kind))
        for position in (0, 2, 3):
            single = plan("equality", 4, 4, "symbolic", axis="length", equality_kind="unequal")
            left, right = list(single["initial_states"])
            replacement = single["initial_states"][right][-1]
            single["initial_states"][right] = list(single["initial_states"][left])
            single["initial_states"][right][position] = replacement
            single["distinct"] = [[single["initial_states"][left][position], replacement]]
            streams.append(single)
        for left_size, right_size in ((0, 0), (0, 1), (1, 0), (1, 2)):
            boundary = plan("equality", 1, 2, "symbolic")
            left, right = list(boundary["initial_states"])
            boundary["initial_states"][left] = boundary["initial_states"][left][:left_size]
            boundary["initial_states"][right] = boundary["initial_states"][right][:right_size]
            boundary["capacity"] = max(left_size, right_size)
            reference = oracle(boundary)
            for observation in boundary["observations"]:
                observation["expected"] = reference["booleans"][observation["result"]]
            streams.append(boundary)
        same_term = plan("equality", 2, 4, "concrete")
        old, new = same_term["distinct"][0]
        same_term["entries"][new]["term"] = same_term["entries"][old]["term"]
        streams.append(same_term)
        constructor = deepcopy(same_term)
        constructor["entries"][new].update(kind="signature", value=0)
        streams.append(constructor)
        streams.append(plan("equality", 6, 4, "symbolic"))
    if args.workload == "mixed":
        for initial in (0, 4):
            for growing in (False, True):
                streams.append(plan("mixed", 2, initial, "symbolic", growing=growing))
    native = subprocess.run(
        ["lake", "env", "lean", "--run", "Prototype/LedgerSuiteOracleMain.lean"],
        cwd=PROJECT, text=True, input=json.dumps(streams), capture_output=True, check=True,
    )
    native_states = json.loads(native.stdout)
    rows = []
    for index, (stream, actual) in enumerate(zip(streams, native_states, strict=True)):
        expected = oracle(stream)
        if actual["states"] != expected["states"] or actual["booleans"] != expected["booleans"]:
            raise ValueError("Python stream reference disagrees with native Model-log operations")
        if not expected["all_match"]:
            raise ValueError("Control stream is not a valid positive witness")
        save(args.output / f"stream-{index}.json", {"stream": stream, "native": actual})
        for frozen in (False, True):
            encoded = encode(stream, args.representation, header, freeze_inputs=frozen)
            result = solve(args.output / f"positive-{index}-{frozen}",
                           [encoded["script"] + operand_tails(stream, args.representation)],
                           FULL_CYCLE, args.z3, 60, False)
            rows.append({"case": index, "kind": "positive", "frozen": frozen, "result": result})
            save(args.output / "summary.json", rows)
            if result["status"] != "sat":
                raise ValueError(f"Positive control did not complete: {rows[-1]}")
        unconstrained_observations = {**stream, "observations": []}
        projected = encode(unconstrained_observations, args.representation, header,
                           freeze_inputs=True, projections=expected)
        result = solve(args.output / f"oracle-difference-{index}",
                       [projected["script"] + operand_tails(stream, args.representation)],
                       FULL_CYCLE, args.z3, 60, False)
        rows.append({"case": index, "kind": "native-successor-difference", "result": result})
        save(args.output / "summary.json", rows)
        if result["status"] != "unsat":
            raise ValueError("Candidate admits a successor different from the Model witness")
    shapes = [(0, False), (4, False), (0, True), (4, True)] if args.workload == "mixed" else [(4, False)]
    for start_length, growing in shapes:
        symbolic = plan(args.workload, 2, start_length, "symbolic", growing=growing)
        symbolic["observations"] = []
        other = "A" if args.representation == "R" else args.representation
        left, right = encode(symbolic, "R", header), encode(symbolic, other, header)
        joined = header + rename(left, header, "l_") + rename(right, header, "r_")
        for index, name in enumerate(symbolic["entries"]):
            joined += f"(assert (! (= l_{name} r_{name}) :named link_{index}))\n"
        initial = next(iter(symbolic["initial_states"]))
        tail_index = symbolic["capacity"] + 3
        joined += f"(assert (! (= (select l_{initial} {tail_index}) (make_transaction (- 3) (- 4))) :named arbitrary_left_tail))\n"
        if other != "C":
            joined += f"(assert (! (= (select r_{initial} {tail_index}) (make_signature 0)) :named different_right_tail))\n"
        for negate in (False, True):
            script = joined
            if negate:
                script += f"(assert (! {difference(symbolic, left, right)} :named backend_difference))\n"
            result = solve(args.output / f"miter-{start_length}-{growing}-{negate}", [script],
                           FULL_CYCLE, args.z3, 60, False)
            rows.append({"kind": "symbolic-backend-miter", "initial": start_length,
                         "growing": growing, "negate": negate, "result": result})
            save(args.output / "summary.json", rows)
            if result["status"] != ("unsat" if negate else "sat"):
                raise ValueError("Symbolic backend miter failed or was inconclusive")
    for name, value, expected in (
        ("negative-term", "(make_transaction (- 1) 0)", "unsat"),
        ("negative-transaction", "(make_transaction 0 (- 1))", "unsat"),
        ("zero-entry", "(make_transaction 0 0)", "sat"),
    ):
        checked = solve(args.output / name,
                        [header + f"(assert (! (entry_valid {value}) :named type_test))\n"],
                        FULL_CYCLE, args.z3, 60, False)
        rows.append({"kind": "entry-validity", "name": name, "expected": expected, "result": checked})
        save(args.output / "summary.json", rows)
        if checked["status"] != expected:
            raise ValueError("Entry validity control failed")
    negative = plan(args.workload, 2, 4, "symbolic", negative=True)
    encoded = encode(negative, args.representation, header)
    result = solve(args.output / "negative", [encoded["script"]], FULL_CYCLE, args.z3, 60, False)
    if result["status"] != "unsat" or not set(result["core"]) <= encoded["groups"].keys():
        raise ValueError("Negative control or source-core names failed")
    selected = closure(encoded, result["core"])
    targets = {}
    for backend in ("R", "C", "A"):
        target = encode(negative, backend, header)
        if not set(selected) <= target["groups"].keys():
            raise ValueError("Cross-backend source labels differ")
        script = target["header"] + "".join(
            f'(assert (! {target["groups"][name]} :named {name}))\n' for name in selected
        )
        replay = solve(args.output / f"core-replay-{backend}", [script], FULL_CYCLE, args.z3, 60, False)
        targets[backend] = replay
        if replay["status"] != "unsat":
            raise ValueError("Source dependency-closed core replay failed")
    rows.append({"kind": "negative-core", "result": result, "dependency_closure": selected, "replays": targets})
    # Removing all transition/comparison assertions must release the contradiction.
    weakened = encoded["header"] + "".join(
        f"(assert (! {expression} :named {name}))\n" for name, expression in encoded["groups"].items()
        if not name.startswith("step_")
    )
    checked = solve(args.output / "negative-without-operations", [weakened], FULL_CYCLE, args.z3, 60, False)
    rows.append({"kind": "negative-operation-dependence", "result": checked})
    if checked["status"] != "sat":
        raise ValueError("Negative case is contradictory without operation constraints")
    if args.workload == "append":
        for position in ("last", "retained"):
            extra = plan("append", 2, 4, "symbolic", negative=True, negative_position=position)
            extra_encoding = encode(extra, args.representation, header)
            result = solve(args.output / f"negative-{position}", [extra_encoding["script"]],
                           FULL_CYCLE, args.z3, 60, False)
            rows.append({"kind": "negative-position", "position": position, "result": result})
            if result["status"] != "unsat":
                raise ValueError("Append-position negative failed")
    if args.workload == "rollback":
        wrong_length = plan("rollback", 2, 4, "symbolic")
        next(o for o in wrong_length["observations"] if o["kind"] == "length")["expected"] += 1
        result = solve(args.output / "negative-length", [encode(wrong_length, args.representation, header)["script"]],
                       FULL_CYCLE, args.z3, 60, False)
        rows.append({"kind": "negative-length", "result": result})
        if result["status"] != "unsat":
            raise ValueError("Rollback length negative failed")
    if args.workload == "mixed":
        for growing in (False, True):
            for target in ("unequal", "regrowth", "retained"):
                extra = plan("mixed", 2, 4, "symbolic", growing=growing, negative=True, mixed_negative=target)
                if oracle(extra)["all_match"]:
                    raise ValueError("Mixed mutation did not contradict the oracle")
                result = solve(args.output / f"negative-{growing}-{target}",
                               [encode(extra, args.representation, header)["script"]],
                               FULL_CYCLE, args.z3, 60, False)
                rows.append({"kind": "mixed-negative", "growing": growing, "target": target, "result": result})
                if result["status"] != "unsat":
                    raise ValueError("Mixed mutation did not return UNSAT")
    save(args.output / "summary.json", rows)


if __name__ == "__main__":
    main()
