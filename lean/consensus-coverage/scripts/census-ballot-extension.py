#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Extend completed total-only tables by the two proved-false ballot columns.

This is not a rerun of either reader and never evaluates the one-sided pools.
Verify ConsensusCoverage.CensusBallots.{label_false,same_projection} with
leanchecker first. Source tables and the completed-model inventory stay intact.
"""

import argparse
import csv
import re
from pathlib import Path


BALLOTS = {"ballot_step_mem_after_inl", "ballot_step_mem_after_inr"}
CONFIG = ("voters", "nodes", "max_log", "max_term", "copies", "network", "palette")
COUNTS = ("known_true", "known_false", "unknown")


def table(path):
    with path.open() as f:
        return list(csv.DictReader(f, delimiter="\t"))


def write(path, rows):
    with path.open("w") as f:
        w = csv.DictWriter(f, fieldnames=rows[0], delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def load(directory, cfg):
    name = cfg["representative"]
    log = (directory / (name + ".log")).read_text()
    frames, steps = int(cfg["frames"]), int(cfg["steps"])
    if not (re.search(rf"^frames: {frames}; expanded: {frames}; frontier: 0; fixpoint: true$", log, re.M)
            and re.search(rf"^steps: {steps};", log, re.M)):
        raise ValueError(f"{name}: source was not a matching fixpoint")
    rows = table(directory / (name + ".cases.tsv"))
    if [int(r["index"]) for r in rows] != list(range(516)) or len({r["question"] for r in rows}) != 516:
        raise ValueError(f"{name}: incomplete or repeated coordinates")
    for r in rows:
        counts = [int(r[k]) for k in COUNTS]
        if min(counts) < 0 or sum(counts) != steps:
            raise ValueError(f"{name}: invalid counts at {r['question']}")
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("revisions", type=Path, help="completed revision TSV, next to its raw logs and case tables")
    p.add_argument("old_columns", type=Path)
    p.add_argument("new_columns", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()

    def names(path):
        return {s.rsplit(".", 1)[-1] for s in path.read_text().splitlines() if s}

    before, after = names(args.old_columns), names(args.new_columns)
    if not before <= after or after-before != BALLOTS:
        raise ValueError("the exact schema change is not precisely the two universally false ballot coordinates")
    models = {}
    for r in table(args.revisions):
        key = tuple(r[k] for k in CONFIG)
        group = models.setdefault(key, {})
        if r["reader_snapshot"] in group:
            raise ValueError(f"duplicate revision: {key}")
        group[r["reader_snapshot"]] = r
    args.output.mkdir(exist_ok=True, parents=True)
    results = []
    for group in models.values():
        cfg = group["prepolar186"]
        rows = load(args.revisions.parent, cfg)
        steps = int(cfg["steps"])
        if not after <= {r["question"] for r in rows}:
            raise ValueError(f"{cfg['representative']}: exact columns missing")
        for r in rows:
            if r["question"] in before and int(r["unknown"]):
                raise ValueError(f"{r['question']}: old total coordinate is unknown")
            if r["question"] in BALLOTS:
                if int(r["known_true"]) or r["schedule"]:
                    raise ValueError(f"{r['question']}: positive contradicts the universal refutation")
                r.update(known_false=str(steps), unknown="0")
        other = group.get("total188")
        if other:
            actual = load(args.revisions.parent, other)
            for k in ("frames", "steps", "wider_keys", "legacy_keys"):
                if other[k] != cfg[k]:
                    raise ValueError(f"direct total-only run disagrees on {k}: {other['representative']}")
            for predicted, measured in zip(rows, actual, strict=True):
                for k in ("question", *COUNTS, "depth"):
                    if predicted[k] != measured[k]:
                        raise ValueError(f"{other['representative']}: disagrees on {predicted['question']} {k}")
        dest = cfg["representative"]+".certified.cases.tsv"
        write(args.output / dest, rows)
        yes = sum(int(r["known_true"]) > 0 for r in rows)
        no = sum(int(r["known_false"]) == steps for r in rows)
        results.append(dict(cfg, yes=yes, no=no, unknown=516-yes-no, case_table=dest,
                            reader_snapshot="prepolar186 + two certified false (no pools)",
                            direct_total188_overlap=other["representative"] if other else ""))
    write(args.output / "models.tsv", results)
    overlaps = sum(bool(r["direct_total188_overlap"]) for r in results)
    print(f"{len(results)} theorem-extended models, {overlaps} independently measured total188 overlaps; not a polar run.")


if __name__ == "__main__":
    main()
