#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Intersect exact false rows across completed merged models; reject partial input."""

import argparse
import csv
import re
from collections import Counter
from pathlib import Path


def settings(prefix):
    text = Path(str(prefix) + ".log").read_text()
    config = re.search(r"voters=(\[[^]]*\]) nodes=(\[[^]]*\]) log=(\d+) term=(\d+) "
                       r"copies=(\d+) network=(none|some \d+) palette=(\w+)", text)
    if not config:
        raise ValueError(f"{prefix}: no bounded configuration")
    return dict(zip(("voters", "nodes", "log", "term", "copies", "network", "palette"),
                    config.groups(), strict=True))


def completed(prefix):
    text = Path(str(prefix) + ".log").read_text()
    fix = re.search(r"^frames: (\d+); expanded: (\d+); frontier: 0; fixpoint: true$", text, re.M)
    steps = re.search(r"^steps: (\d+);", text, re.M)
    if not fix or fix[1] != fix[2] or not steps:
        raise ValueError(f"{prefix}: not a completed fixpoint")
    steps = int(steps[1])
    if steps == 0:
        raise ValueError(f"{prefix}: empty graph")
    with Path(str(prefix) + ".cases.tsv").open() as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    if [int(r["index"]) for r in rows] != list(range(516)) or len({r["question"] for r in rows}) != len(rows):
        raise ValueError(f"{prefix}: missing or duplicated questions")
    counts = {}
    for r in rows:
        yes, no, unknown = (int(r[k]) for k in ("known_true", "known_false", "unknown"))
        if min(yes, no, unknown) < 0 or yes + no + unknown != steps or bool(yes) != bool(r["schedule"]):
            raise ValueError(f"{prefix}: invalid totals or witness at {r['question']}")
        counts[r["question"]] = yes, no, unknown
    return steps, counts


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--columns", nargs="+", required=True, type=Path,
                   help="newline-separated total columns (generated plus baseline)")
    p.add_argument("--dag", type=Path, required=True, help="reader generator's direct reach DAG TSV")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--differential", type=Path, required=True)
    p.add_argument("--contrasts", type=Path,
                   help="total questions changing from absent to present between one-setting controls")
    p.add_argument("--positive-witnesses", action="append", type=Path, default=[],
                   help="positive-only evidence (a .cases.tsv), never included in fixpoint denominators")
    p.add_argument("models", nargs="+", type=Path, help="prefix of .cases.tsv and .log; baseline first")
    a = p.parse_args()
    if len({m.name for m in a.models}) != len(a.models):
        raise ValueError("model names must be unique")
    exact = {s.rsplit(".", 1)[-1] for f in a.columns for s in f.read_text().splitlines() if s}
    reaches = dict(s.split("\t", 1) for s in a.dag.read_text().splitlines())
    models = {p.name: completed(p) for p in a.models}
    for name, (steps, rows) in models.items():
        if not exact <= rows.keys() or any(rows[q][2] for q in exact):
            raise ValueError(f"{name}: total-reader coverage not satisfied (wrong snapshot or partial census)")
        stats = Counter("yes" if y else "unknown" if u else "no" for y, _, u in rows.values())
        print(name, steps, f"true={stats['yes']} false={stats['no']} unknown={stats['unknown']}")
    baseline = next(iter(models))
    witnessed = {q: [] for q in exact}
    for path in a.positive_witnesses:
        with path.open() as f:
            rows = list(csv.DictReader(f, delimiter="\t"))
        if [r["question"] for r in rows] != list(models[baseline][1]):
            raise ValueError(f"{path}: wrong question set/order")
        for r in rows:
            if r["question"] in exact and int(r["known_true"]) > 0:
                if not r["schedule"] or not r["queue_choices"] or int(r["depth"]) < 1:
                    raise ValueError(f"{path}: positive without concrete witness: {r['question']}")
                witnessed[r["question"]].append(path.name)
    candidates = []
    differential = []
    for q in sorted(exact):
        positive = [n for n, (_, rows) in models.items() if rows[q][0]]
        if not positive:
            arm = "step_" + q
            direct = sorted(filter(None, reaches[arm].split(",")), key=lambda r: int(r.split("_")[-1]))
            # Group by identical direct shared predicates, not an inferred reason for impossibility.
            candidates.append((",".join(direct), q, ",".join(models),
                               sum(rows[q][1] for _, rows in models.values()),
                               f"ConsensusCoverage.SolvedWitnesses.{arm} s.frame s.after s.context",
                               ",".join(witnessed[q])))
        if baseline not in positive and (positive or witnessed[q]):
            differential.append((q, baseline, ",".join(positive), ",".join(witnessed[q])))
    for path, header, rows in [
        (a.out, ("direct_reaches", "question", "completed_models", "false_model_edge_incidences", "formula",
                 "witnessed_outside_models"),
         sorted(candidates)),
        (a.differential, ("question", "absent_in_baseline", "true_in_models", "positive_witness_tables"), differential)
    ]:
        with path.open("w") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            writer.writerow(header)
            writer.writerows(rows)
    if a.contrasts:
        configs = {m.name: settings(m) for m in a.models}
        with a.contrasts.open("w") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            writer.writerow(("changed_setting", "from", "to", "absent_in", "present_in", "question",
                             "false_edges_before", "true_edges_after"))
            for left, lc in configs.items():
                for right, rc in configs.items():
                    diff = [k for k in lc if lc[k] != rc[k]]
                    if len(diff) != 1:
                        continue
                    k = diff[0]
                    before, after = models[left][1], models[right][1]
                    for q in sorted(exact):
                        if not before[q][0] and after[q][0]:
                            writer.writerow((k, lc[k], rc[k], left, right, q, before[q][1], after[q][0]))
    print(f"{len(candidates)} bounded negatives in {len({r[0] for r in candidates})} direct-reach groups;"
          f" {sum(bool(r[-1]) for r in candidates)} witnessed outside completed models;"
          f" {len(differential)} positive outside baseline only; {len(exact)} total coordinates.")


if __name__ == "__main__":
    main()
