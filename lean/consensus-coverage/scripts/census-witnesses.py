#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Regenerate CaseWitnesses from real-history-replayable positive case TSVs."""

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("tables", nargs="+", type=Path)
    p.add_argument("--write", action="store_true", help="otherwise check the existing module")
    args = p.parse_args()
    file = Path(__file__).resolve().parents[1] / "ConsensusCoverage/CaseWitnesses.lean"
    src = file.read_text()
    start = "-- BEGIN BOUNDED CENSUS\n"
    end = "-- END GENERATED CERTIFICATES"
    a = src[:src.index(start if start in src else "private def certificates :")]
    b = src[src.index(end):]
    old = set(re.findall(r"\.(\w+)", " ".join(re.findall(r"caseAt \d+ \[([^]]+)\]", a))))
    best = {}
    for path in args.tables:
        with path.open() as f:
            rows = list(csv.DictReader(f, delimiter="\t"))
        if [int(row["index"]) for row in rows] != list(range(516)):
            raise ValueError(f"incomplete case table: {path}")
        for row in rows:
            q = row["question"]
            if q in old or not int(row["known_true"]):
                continue
            if not re.fullmatch(r"\w+", q, re.ASCII):
                raise ValueError(f"invalid case name: {q}")
            w = (int(row["depth"]), row["schedule"], row["queue_choices"])
            if not w[0] or not w[1] or not w[2]:
                raise ValueError(f"positive without a replay: {path}, {q}")
            best[q] = min(w, best.get(q, w))
    groups = defaultdict(list)
    for q, w in sorted(best.items()):
        groups[w].append(q)
    text = [start.rstrip()]
    certs = ["cert0", "cert1"]
    for i, ((depth, schedule, choices), qs) in enumerate(sorted(groups.items())):
        run = f"bounded{i}"
        cert = f"{run}Cert"
        certs.append(cert)
        text += [f"private def {run} : Run :=", "  " + schedule,
                 f"private theorem {run}Valid : {run}.valid := by decide",
                 f"private def {cert} : Certificate := certify {run} {choices} {run}Valid",
                 f"  [caseAt {depth - 1} [" + ",\n    ".join("." + q for q in qs) + "]]", ""]
    text += ["private def certificates : List Certificate := [" + ", ".join(certs) + "]\n"]
    count = len(old) + len(best)
    b, n = re.subn(r"witnessed\.length = \d+", f"witnessed.length = {count}", b)
    if n != 1:
        raise ValueError("count theorem not found")
    result = a + "\n".join(text) + b
    if args.write:
        file.write_text(result)
    elif result != src:
        raise SystemExit("CaseWitnesses differs; rerun with --write")
    print(f"{len(old)} original + {len(best)} additional = {count} cases; {len(groups)} bounded schedules")


if __name__ == "__main__":
    main()
