#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Small finite transaction-only receive block: bounded Int versus unsigned BV."""

import argparse
import json
from pathlib import Path
import subprocess

from encoding_study import FULL_CYCLE, PROJECT, digest, save, solve


def formula(count, bitvectors=False, prefix="", width=4, goal=True, negative=False):
    if not 1 <= count <= 5:
        raise ValueError("This prototype supports one through five receives")
    bound = 3 + count
    if bitvectors and 2**width <= bound + 1:
        raise ValueError("Bit width cannot represent every intermediate value")
    declarations, constraints, sorts = [], {}, {}
    literal = lambda value: f"(_ bv{value} {width})" if bitvectors else str(value)
    plus = lambda a, b: f"({'bvadd' if bitvectors else '+'} {a} {b})"

    def name(value):
        return prefix + value

    def declare(value, maximum=None):
        symbol = name(value)
        sorts[symbol] = "bool" if maximum is None else "nat"
        sort = "Bool" if maximum is None else f"(_ BitVec {width})" if bitvectors else "Int"
        declarations.append(f"(declare-const {symbol} {sort})\n")
        if maximum is not None:
            constraints[name("domain_" + value)] = (
                f"(bvule {symbol} {literal(maximum)})" if bitvectors else
                f"(and (<= 0 {symbol}) (<= {symbol} {maximum}))"
            )
        return symbol

    length = declare("length_0", 3)
    initial_length = length
    cells = [declare(f"cell_0_{j}", 7) for j in range(bound)]
    inputs = [length] + cells
    outputs = []
    for i in range(count):
        previous = declare(f"previous_{i}", bound + 1)
        transaction = declare(f"transaction_{i}", 7)
        inputs += [previous, transaction]
        accepted = declare(f"accepted_{i}")
        next_length = declare(f"length_{i+1}", bound)
        response_index = declare(f"response_index_{i}", bound)
        constraints[name(f"request_scope_{i}")] = f"(or (= {previous} {length}) (= {previous} {plus(length, literal(1))}))"
        constraints[name(f"accept_{i}")] = f"(= {accepted} (= {previous} {length}))"
        constraints[name(f"length_step_{i}")] = f"(= {next_length} (ite {accepted} {plus(length, literal(1))} {length}))"
        constraints[name(f"response_{i}")] = f"(= {response_index} {next_length})"
        next_cells = []
        for j, old in enumerate(cells):
            cell = declare(f"cell_{i+1}_{j}", 7)
            constraints[name(f"write_{i}_{j}")] = (
                f"(= {cell} (ite (and {accepted} (= {length} {literal(j)})) {transaction} {old}))"
            )
            next_cells.append(cell)
        outputs += [next_length, accepted, response_index] + next_cells
        cells, length = next_cells, next_length
    if goal:
        target = plus(initial_length, literal(count + 1 if negative else (count + 1) // 2))
        constraints[name("observed_length")] = f"(= {length} {target})"
        selected = literal(0)
        for j in reversed(range(bound)):
            selected = f"(ite (= {initial_length} {literal(j)}) {cells[j]} {selected})"
        constraints[name("observed_first_new_value")] = f"(= {selected} {literal(3)})"
    return {
        "declarations": "".join(declarations), "constraints": constraints,
        "inputs": inputs, "outputs": outputs, "sorts": sorts, "bound": bound,
        "logic": "QF_BV" if bitvectors else "QF_LIA",
    }


def render(data, selected=None):
    names = data["constraints"] if selected is None else selected
    return f'(set-logic {data["logic"]})\n' + data["declarations"] + "".join(
        f'(assert (! {data["constraints"][key]} :named {key}))\n' for key in names
    )


def miter(count, difference=True):
    integers = formula(count, prefix="i_", goal=False)
    bits = formula(count, bitvectors=True, prefix="b_", goal=False)
    header = "(set-logic ALL)\n" + integers["declarations"] + bits["declarations"]
    assertions = {**integers["constraints"], **bits["constraints"]}
    for index, (left, right) in enumerate(zip(integers["inputs"], bits["inputs"], strict=True)):
        assertions[f"input_link_{index}"] = f"(= {left} (bv2int {right}))"
    differences = []
    for left, right in zip(integers["outputs"], bits["outputs"], strict=True):
        value = right if integers["sorts"][left] == "bool" else f"(bv2int {right})"
        differences.append(f"(not (= {left} {value}))")
    if difference:
        assertions["successor_difference"] = "(or " + " ".join(differences) + ")"
    return header + "".join(f"(assert (! {value} :named {key}))\n" for key, value in assertions.items())


def validity(count, bitvectors, prefix):
    bound = count + 3
    literal = lambda value: f"(_ bv{value} 4)" if bitvectors else str(value)
    domain = lambda name, limit: (
        f"(bvule {name} {literal(limit)})" if bitvectors else f"(and (<= 0 {name}) (<= {name} {limit}))")
    length = prefix + "length_0"
    clauses = [domain(length, 3)] + [domain(f"{prefix}cell_0_{j}", 7) for j in range(bound)]
    for i in range(count):
        previous = f"{prefix}previous_{i}"
        plus = f"({'bvadd' if bitvectors else '+'} {length} {literal(1)})"
        clauses += [domain(previous, bound + 1), domain(f"{prefix}transaction_{i}", 7),
                    f"(or (= {previous} {length}) (= {previous} {plus}))"]
        length = f"(ite (= {previous} {length}) {plus} {length})"
        clauses.append(domain(length, bound))
    return "(and " + " ".join(clauses) + ")"


def domain_miter(count):
    integers = formula(count, prefix="i_", goal=False)
    bits = formula(count, bitvectors=True, prefix="b_", goal=False)
    script = "(set-logic ALL)\n" + integers["declarations"] + bits["declarations"]
    for i, (left, right) in enumerate(zip(integers["inputs"], bits["inputs"], strict=True)):
        script += f"(assert (! (= {left} (bv2int {right})) :named link_{i}))\n"
    script += f"(assert (! (not (= {validity(count, False, 'i_')} {validity(count, True, 'b_')})) :named domain_difference))\n"
    return script


def oracle_query(row, bitvectors, negate=False):
    count = row["receives"]
    data = formula(count, bitvectors=bitvectors, goal=False)
    literal = lambda value: f"(_ bv{value} 4)" if bitvectors else str(value)
    script = render(data)
    assignments = {"length_0": row["initialLength"]}
    for j in range(data["bound"]):
        assignments[f"cell_0_{j}"] = (
            row["initialLog"][j]["content"]["transaction"] if j < row["initialLength"] else 0)
    for i, request in enumerate(row["requests"]):
        assignments[f"previous_{i}"] = request["prevLogIndex"]
        assignments[f"transaction_{i}"] = request["entries"][0]["content"]["transaction"]
    for name, value in assignments.items():
        script += f"(assert (! (= {name} {literal(value)}) :named fixed_{name}))\n"
    expected = [f'(= length_{count} {literal(row["finalLength"])})']
    expected += [f"(= cell_{count}_{j} {literal(value)})" for j, value in enumerate(row["finalValues"])]
    for i, response in enumerate(row["responses"]):
        expected += [
            f'(= accepted_{i} {str(response["success"]).lower()})',
            f'(= response_index_{i} {literal(response["lastLogIndex"])})',
        ]
    combined = "(and " + " ".join(expected) + ")"
    script += f'(assert (! {"(not " + combined + ")" if negate else combined} :named model_successor))\n'
    return script


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    oracle = subprocess.run(
        ["lake", "env", "lean", "--run", "Prototype/FiniteBlockOracleMain.lean"],
        cwd=PROJECT, text=True, capture_output=True, check=True,
    )
    checked = json.loads(oracle.stdout)
    if len(checked) != 1984:
        raise ValueError("Unexpected Model-oracle coverage")
    keys = {(r["receives"], r["initialLength"], r["offset"], r["mask"]) for r in checked}
    expected_keys = {(n, length, offset, mask) for n in range(1, 6) for length in range(4)
                     for offset in range(8) for mask in range(2**n)}
    if keys != expected_keys or len(keys) != len(checked):
        raise ValueError("Duplicate or missing Model-oracle schedules")
    save(args.output / "model-oracle.json", checked)
    save(args.output / "provenance.json", {
        "scope": "finite Model-derived fragment, not captured full traces",
        "generator_sha256": digest(Path(__file__).read_bytes()),
        "oracle_sha256": digest((PROJECT / "Prototype/FiniteBlockOracleMain.lean").read_bytes()),
        "model_sha256": digest((PROJECT / "Model.lean").read_bytes()),
        "observation_projection_sha256": digest((PROJECT / "Sparse/NativeArrayFixtureJson.lean").read_bytes()),
        "z3": subprocess.run([args.z3, "--version"], capture_output=True, text=True, check=True).stdout.strip(),
    })
    rows = []
    for count in range(1, 6):
        feasible = solve(args.output / f"miter-feasible-{count}", [miter(count, False)], FULL_CYCLE, args.z3, 60, False)
        if feasible["status"] != "sat":
            raise ValueError("Cannot establish shared-input miter feasibility")
        domains = solve(args.output / f"domain-miter-{count}", [domain_miter(count)], FULL_CYCLE, args.z3, 60, False)
        if domains["status"] != "unsat":
            raise ValueError("Int/BV legal-input domains differ")
        result = solve(args.output / f"miter-{count}", [miter(count)], FULL_CYCLE, args.z3, 60, False)
        if result["status"] != "unsat":
            save(args.output / "miter-failure.json", result)
            raise ValueError(f"Integer/BV successor miter failed: {count}")
        save(args.output / f"miter-{count}/expected.json", {"expected": "unsat"})
    selected = [r for r in checked if r["receives"] == 5 and r["initialLength"] in (0, 3)
                and r["offset"] in (0, 7) and r["mask"] in (0, 10, 21, 31)]
    oracle_checks = []
    for index, row in enumerate(selected):
        for bitvectors in (False, True):
            for negate in (False, True):
                result = solve(args.output / f"oracle-{index}-{bitvectors}-{negate}",
                               [oracle_query(row, bitvectors, negate)], FULL_CYCLE, args.z3, 60, False)
                expected = "unsat" if negate else "sat"
                oracle_checks.append({"oracle": {k: row[k] for k in ("receives", "initialLength", "offset", "mask")},
                                      "bitvectors": bitvectors, "negate": negate, "expected": expected, "result": result})
                save(args.output / "oracle-checks.json", oracle_checks)
                if result["status"] != expected:
                    raise ValueError("SMT successor disagrees with the actual Model oracle")
    for sample in range(3):
        modes = ["integer", "bv-smt", "bv-sat"] if sample % 2 == 0 else ["bv-sat", "bv-smt", "integer"]
        for count in range(1, 6):
            for negative in (False, True):
                for mode in modes:
                    data = formula(count, bitvectors=mode != "integer", negative=negative)
                    query = "(check-sat-using (then simplify bit-blast sat))\n" if mode == "bv-sat" else FULL_CYCLE
                    result = solve(
                        args.output / f"{count}-{negative}-{mode}-{sample}",
                        [render(data)], query, args.z3, 60, False,
                    )
                    expected = "unsat" if negative else "sat"
                    rows.append({"receives": count, "negative": negative, "mode": mode,
                                 "sample": sample, "expected": expected, "result": result})
                    save(args.output / "summary.json", rows)
                    if result["status"] != expected:
                        raise ValueError(f"Finite trial failed: {rows[-1]}")
                    if negative and sample == 0:
                        core = result["core"]
                        if not core or not set(core) <= data["constraints"].keys():
                            raise ValueError("Invalid finite-trial source core")
                        if not any(name.startswith("length_step_") for name in core):
                            raise ValueError("Negative core does not involve the transition")
                        # Replay the corresponding source-level integer constraints.
                        integer_data = formula(count, negative=True)
                        replay_names = sorted(set(core) | {
                            name for name in integer_data["constraints"] if name.startswith("domain_")})
                        replay = solve(args.output / f"core-{count}-{mode}", [render(integer_data, replay_names)],
                                       FULL_CYCLE, args.z3, 60, False)
                        if replay["status"] != "unsat":
                            raise ValueError("Finite source-core replay failed")
                        save(args.output / f"core-{count}-{mode}/mapping.json", {
                            "core": core, "integer_replay_labels": replay_names,
                            "note": "Integer counterparts plus explicit representation-domain assumptions",
                        })
    for mode in ("integer", "bv-smt", "bv-sat"):
        data = formula(5, bitvectors=mode != "integer")
        query = "(check-sat-using (then simplify bit-blast sat))\n" if mode == "bv-sat" else FULL_CYCLE
        result = solve(args.output / f"profile-{mode}", [render(data)], query, args.z3, 60, True)
        save(args.output / f"profile-{mode}/expected.json", {"expected": "sat", "result": result})
        if result["status"] != "sat":
            raise ValueError("Profile did not complete SAT")


if __name__ == "__main__":
    main()
