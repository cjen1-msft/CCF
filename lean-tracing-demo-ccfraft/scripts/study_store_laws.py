#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Check the symbolic live-cell law and expose the deliberate tail difference."""

import argparse
from pathlib import Path

from encoding_study import FULL_CYCLE, save, solve

HEAD = """(set-logic ALL)
(declare-sort Entry 0)
(declare-const old (Array Int Entry))
(declare-const payload Entry)
(declare-const output (Array Int Entry))
(declare-const n Int)
(declare-const probe Int)
(assert (! (>= n 0) :named length_domain))
(define-fun stored () (Array Int Entry) (store old n payload))
"""


def relation(array):
    return (
        "(forall ((i Int)) (=> (and (<= 0 i) (< i (+ n 1))) "
        f"(= (select {array} i) (ite (< i n) (select old i) payload))))"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cases = [
        ("stored-satisfies-relation", "unsat",
         f"(assert (! (not {relation('stored')}) :named violation))\n"),
        ("relation-agrees-on-live-cell", "unsat",
         f"(assert (! {relation('output')} :named splice))\n"
         "(assert (! (and (<= 0 probe) (<= probe n)) :named live))\n"
         "(assert (! (not (= (select output probe) (select stored probe))) :named difference))\n"),
        ("whole-array-tails-can-differ", "sat",
         f"(assert (! {relation('output')} :named splice))\n"
         "(assert (! (not (= (select output (+ n 10)) (select stored (+ n 10)))) :named tail_difference))\n"),
    ]
    rows = []
    for name, expected, body in cases:
        result = solve(args.output / name, [HEAD + body], FULL_CYCLE, args.z3, 60, False)
        rows.append({"name": name, "expected": expected, "result": result})
        save(args.output / "summary.json", rows)
        if result["status"] != expected:
            raise ValueError(f"Store law check failed: {name}: {result}")


if __name__ == "__main__":
    main()
