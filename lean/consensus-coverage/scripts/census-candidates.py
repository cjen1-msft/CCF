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


def completed(prefix, case_file=None):
    text = Path(str(prefix) + ".log").read_text()
    fix = re.search(r"^frames: (\d+); expanded: (\d+); frontier: 0; fixpoint: true$", text, re.M)
    steps = re.search(r"^steps: (\d+);", text, re.M)
    if not fix or fix[1] != fix[2] or not steps:
        raise ValueError(f"{prefix}: not a completed fixpoint")
    steps = int(steps[1])
    if steps == 0:
        raise ValueError(f"{prefix}: empty graph")
    with (case_file or Path(str(prefix) + ".cases.tsv")).open() as f:
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
    p.add_argument("--prior-columns", nargs="+", type=Path,
                   help="total columns of a prior reader snapshot, for explicitly marked models")
    p.add_argument("--prior-model", action="append", default=[],
                   help="completed model read with --prior-columns instead of --columns")
    p.add_argument("--dag", type=Path, required=True, help="reader generator's direct reach DAG TSV")
    p.add_argument("--formulas", type=Path, help="normalized bodies from census-formulas.lean")
    p.add_argument("--reach-out", type=Path, help="write the direct reach predicates used by the candidates")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--differential", type=Path, required=True)
    p.add_argument("--contrasts", type=Path,
                   help="total questions changing from absent to present between one-setting controls")
    p.add_argument("--positive-witnesses", action="append", type=Path, default=[],
                   help="positive-only evidence (a .cases.tsv), never included in fixpoint denominators")
    p.add_argument("--certified-models", type=Path,
                   help="models.tsv from census-ballot-extension.py; replace these raw counts with its theorem extension")
    p.add_argument("models", nargs="+", type=Path, help="prefix of .cases.tsv and .log; baseline first")
    a = p.parse_args()
    if len({m.name for m in a.models}) != len(a.models):
        raise ValueError("model names must be unique")
    def columns(files):
        return {s.rsplit(".", 1)[-1] for f in files for s in f.read_text().splitlines() if s}
    exact = columns(a.columns)
    prior_exact = columns(a.prior_columns or [])
    reaches = dict(s.split("\t", 1) for s in a.dag.read_text().splitlines())
    bodies = {}
    if a.formulas:
        with a.formulas.open() as f:
            bodies = {r["name"]: r["normalized_body"] for r in csv.DictReader(f, delimiter="\t")}
    if a.reach_out and not bodies:
        p.error("--reach-out requires --formulas")
    overrides = {}
    if a.certified_models:
        with a.certified_models.open() as f:
            for r in csv.DictReader(f, delimiter="\t"):
                name = r["representative"]
                if name in overrides or r["reader_snapshot"] != "prepolar186 + two certified false (no pools)":
                    raise ValueError("unexpected or duplicate theorem-backed model")
                overrides[name] = a.certified_models.parent / r["case_table"]
        if not overrides.keys() <= {p.name for p in a.models}:
            raise ValueError("theorem-backed table is not a named input model")
    models = {p.name: completed(p, overrides.get(p.name)) for p in a.models}
    derived = {}
    for model in a.models:
        if model.name not in overrides:
            continue
        steps, raw = completed(model)
        for q, new in models[model.name][1].items():
            if raw[q] != new:
                if q not in {"ballot_step_mem_after_inl", "ballot_step_mem_after_inr"} or raw[q][0] or new != (0, steps, 0):
                    raise ValueError(f"unexpected change in theorem-backed table: {model.name} {q}")
                derived.setdefault(q, []).append(model.name)
    if (set(a.prior_model) - models.keys() or bool(a.prior_model) != bool(prior_exact)
            or not prior_exact <= exact):
        raise ValueError("prior models must be named inputs with an explicit subset of total columns")
    for name, (steps, rows) in models.items():
        required = prior_exact if name in a.prior_model else exact
        if not exact <= rows.keys() or any(rows[q][2] for q in required):
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
        if not positive and all(rows[q][2] == 0 for _, rows in models.values()):
            arm = "step_" + q
            direct = sorted(filter(None, reaches[arm].split(",")), key=lambda r: int(r.split("_")[-1]))
            # Group by identical direct shared predicates, not an inferred reason for impossibility.
            candidates.append((",".join(direct), q, ",".join(models),
                               sum(rows[q][1] for _, rows in models.values()),
                               f"ConsensusCoverage.SolvedWitnesses.{arm} s.frame s.after s.context",
                               ",".join(witnessed[q]), *((bodies[arm],) if a.formulas else ()),
                               *((",".join(derived.get(q, [])),) if a.certified_models else ())))
        if baseline not in positive and not models[baseline][1][q][2] and (positive or witnessed[q]):
            differential.append((q, baseline, ",".join(positive), ",".join(witnessed[q])))
    for path, header, rows in [
        (a.out, ("direct_reaches", "question", "completed_models", "false_model_edge_incidences", "formula",
                 "witnessed_outside_models", *(("normalized_body",) if a.formulas else ()),
                 *(("proof_extended_models",) if a.certified_models else ())),
         sorted(candidates)),
        (a.differential, ("question", "absent_in_baseline", "true_in_models", "positive_witness_tables"), differential)
    ]:
        with path.open("w") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            writer.writerow(header)
            writer.writerows(rows)
    if a.reach_out:
        direct = {n for row in candidates for n in row[0].split(",") if n}
        with a.reach_out.open("w") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            writer.writerow(("direct_reach", "normalized_body"))
            writer.writerows((n, bodies[n]) for n in sorted(direct, key=lambda n: int(n.split("_")[-1])))
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
                        if not before[q][0] and not before[q][2] and after[q][0]:
                            writer.writerow((k, lc[k], rc[k], left, right, q, before[q][1], after[q][0]))
    print(f"{len(candidates)} bounded negatives in {len({r[0] for r in candidates})} direct-reach groups;"
          f" {sum(bool(r[5]) for r in candidates)} witnessed outside completed models;"
          f" {len(differential)} positive outside baseline only; {len(exact)} total coordinates.")


if __name__ == "__main__":
    main()
