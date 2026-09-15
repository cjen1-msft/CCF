#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Counterexample checks for finite live-range grounding and store witnesses."""

import argparse
from pathlib import Path

from encoding_study import FULL_CYCLE, save, solve

HEAD = """(set-logic ALL)
(declare-sort Entry 0)
(declare-const old (Array Int Entry))
(declare-const payload (Array Int Entry))
(declare-const output (Array Int Entry))
(declare-const oldLength Int)
(declare-const payloadLength Int)
(declare-const previous Int)
(assert (! (and (>= oldLength 0) (>= payloadLength 0) (>= previous 0)) :named domains))
(define-fun keep () Int (ite (<= previous oldLength) previous oldLength))
(define-fun resultLength () Int (+ keep payloadLength))
"""


def cell(index):
    return f"(= (select output {index}) (ite (< {index} keep) (select old {index}) (select payload (- {index} keep))))"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    relational = f"(forall ((i Int)) (=> (and (<= 0 i) (< i resultLength)) {cell('i')}))"
    cases = []
    for bound in (0, 1, 4, 16):
        finite = "(and true " + " ".join(
            f"(=> (< {i} resultLength) {cell(str(i))})" for i in range(bound)
        ) + ")"
        script = HEAD + f"(assert (! (<= resultLength {bound}) :named bound))\n"
        script += f"(assert (! (not (= {relational} {finite})) :named difference))\n"
        cases.append((f"equivalent-under-{bound}", "unsat", script))
    cases.append((
        "omitted-bound-is-unsound", "sat",
        HEAD + "(assert (! (and (= oldLength 0) (= previous 0) (= payloadLength 2)) :named lengths))\n"
        + f"(assert (! {cell('0')} :named finite_one_cell))\n"
        + f"(assert (! (not {relational}) :named missing_second_cell))\n",
    ))
    stored = "old"
    for index in range(16):
        stored = f"(store {stored} {index} (select old {index}))"
    cases.append(("arbitrary-tail-witness", "unsat",
                  HEAD + f"(assert (! (not (= old {stored})) :named witness_difference))\n"))
    rows = []
    for name, expected, script in cases:
        result = solve(args.output / name, [script], FULL_CYCLE, args.z3, 60, False)
        rows.append({"name": name, "expected": expected, "result": result})
        save(args.output / "summary.json", rows)
        if result["status"] != expected:
            raise ValueError(f"Finite law check failed: {name}: {result}")


if __name__ == "__main__":
    main()
