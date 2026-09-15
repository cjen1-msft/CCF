#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Summarize completed matched-suite samples without pooling different workloads."""

import argparse
import csv
import html
import json
import math
from pathlib import Path
import re
from statistics import median

from encoding_study import digest, save


def graph(rows, path, regime, title, axis="count"):
    selected = [r for r in rows if r["regime"] == regime]
    if not selected:
        return
    def xvalue(row):
        if axis == "operations":
            return sum(row["operations"].values())
        if axis == "appends":
            return row["appended_entries"]
        return row["count"]
    counts = sorted({xvalue(r) for r in selected})
    times = [r["median_seconds"] for r in selected if r["median_seconds"] is not None]
    low, high = math.floor(math.log10(min(times or [.01]))), math.ceil(math.log10(max(times + [60])))
    colors = {"R": "#b73b2a", "C": "#1768ac", "A": "#24813f"}
    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="500">',
        '<rect width="1100" height="500" fill="white"/>',
        f'<text x="70" y="25" font-family="sans-serif" font-size="18">{html.escape(title)}: {regime}</text>',
        '<text x="70" y="48" font-family="sans-serif" font-size="12">Log axes. Z3 process seconds. Triangles: cutoff/unknown, not completed timings.</text>',
    ]
    for panel, negative in enumerate((False, True)):
        left = 85 + 535 * panel
        svg.append(f'<path d="M{left} 85V385H{left+420}" fill="none" stroke="black"/>')
        svg.append(f'<text x="{left}" y="75" font-family="sans-serif">{"UNSAT cases" if negative else "SAT cases"}</text>')
        for power in range(low, high + 1):
            y = 385 - (power - low) / max(1, high - low) * 285
            svg.append(f'<text x="{left-67}" y="{y}" font-family="sans-serif" font-size="12">{10**power:g}s</text>')
        for count in counts:
            x = left + 10 + math.log2(count / min(counts)) / max(1, math.log2(max(counts) / min(counts))) * 400
            svg.append(f'<text x="{x-8}" y="407" font-family="sans-serif" font-size="11">{count}</text>')
        for representation, color in colors.items():
            points = []
            for row in selected:
                if row["representation"] != representation or row["negative"] != negative:
                    continue
                seconds = row["median_seconds"]
                x = left + 10 + math.log2(xvalue(row) / min(counts)) / max(1, math.log2(max(counts) / min(counts))) * 400
                y = 385 - (math.log10(seconds if seconds is not None else 60) - low) / max(1, high - low) * 285
                tip = html.escape(f'{representation} {row["count"]}: {seconds if seconds is not None else row["statuses"]}')
                if seconds is None:
                    svg.append(f'<path d="M{x} {y-5}l-5 9h10z" fill="{color}"><title>{tip}</title></path>')
                else:
                    points.append(f"{x},{y}")
                    svg.append(f'<circle cx="{x}" cy="{y}" r="3" fill="{color}"><title>{tip}</title></circle>')
            svg.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="{color}"/>')
    for i, (rep, color) in enumerate(colors.items()):
        label = {"R": "R: typed relational arrays", "C": "C: canonical per-state cells", "A": "A: direct SMT arrays"}[rep]
        svg.append(f'<text x="{80+i*335}" y="447" font-family="sans-serif" fill="{color}">{label}</text>')
    xlabel = {"count": "workload parameter", "operations": "total ledger operations", "appends": "appended entries"}[axis]
    svg.append(f'<text x="80" y="479" font-family="sans-serif">X: {xlabel}. See the report for live-length counts.</text></svg>')
    path.write_text("\n".join(svg))


def summarize(root, workload):
    base = root / workload
    rows, grouped, semantic = [], {}, {}
    for directory in sorted(base.iterdir()):
        if not directory.is_dir() or not (directory / "samples.json").exists():
            continue
        config = json.loads((directory / "configuration.json").read_text())["arguments"]
        pattern = r"[RCA]-single-(concrete|symbolic)" if workload == "equality" else r"[RCA]-(concrete|symbolic)"
        primary = re.fullmatch(pattern, directory.name) or re.fullmatch(
            r"[RCA]-repeat-\d+-(concrete|symbolic)", directory.name)
        family = ("growing" if config.get("growing") else "fixed") if workload == "mixed" else "primary"
        if workload == "mixed" and (re.fullmatch(r"[RCA]-growing-(concrete|symbolic)", directory.name)
                                   or re.fullmatch(r"[RCA]-growing-repeat-\d+-(concrete|symbolic)", directory.name)):
            primary, family = True, "growing"
        if workload == "mixed" and primary:
            named_growing = "-growing-" in directory.name
            if bool(config["growing"]) != named_growing:
                raise ValueError("Mixed series label disagrees with its configured growth regime")
        for row in json.loads((directory / "samples.json").read_text()):
            stream = json.loads((directory / f'case-{row["count"]}-{row["negative"]}' / "stream.json").read_text())
            semantics = {key: stream[key] for key in
                         ("entries", "initial_states", "events", "observations", "distinct", "capacity", "regime")}
            semantic_hash = digest(json.dumps(semantics, sort_keys=True).encode())
            key = (family, row["regime"], row["count"], row["negative"])
            if primary:
                if key in semantic and semantic[key] != semantic_hash:
                    raise ValueError(f"Primary cases are not semantically matched: {workload}/{key}/{directory.name}")
                semantic[key] = semantic_hash
                grouped.setdefault((row["representation"], *key), []).append(row)
            result = row["result"]
            stats = result.get("stats", {})
            rows.append({
                "phase": directory.name, "workload": workload, "representation": row["representation"],
                "family": family,
                "regime": row["regime"], "axis": row["axis"], "growing": row["growing"],
                "count": row["count"], "negative": row["negative"], "sample": row["sample"],
                "primary": bool(primary), "profile": row["profile"],
                "status": result["status"], "seconds": result.get("solver_seconds"),
                "worker_wall_seconds": result["wall_seconds"], "emission_seconds": row["emission_seconds"],
                "planning_seconds": row.get("planning_seconds"),
                "first_sample_case_wall_seconds": row.get("first_sample_case_wall_seconds"),
                "capacity": row["capacity"], "operations": json.dumps(row["operations"], sort_keys=True),
                "total_operations": sum(row["operations"].values()), "smt_bytes": row["smt_bytes"],
                "appended_entries": sum(len(e["entries"]) if "entries" in e else 1
                                        for e in stream["events"] if e["kind"] == "append"),
                "final_live_lengths": json.dumps(row.get("final_live_lengths"), sort_keys=True),
                "groups": row["groups"], "ledger_states": row["ledger_states"],
                "live_cells_across_states": row["live_cells_across_states"],
                "rlimit": stats.get("rlimit-count"), "decisions": stats.get("decisions"),
                "quantifier_instances": stats.get("quant-instantiations"), "max_memory": stats.get("max-memory"),
                "semantic_sha256": semantic_hash, "solver_seed": config["solver_seed"],
                "order_seed": config["order_seed"], "source_directory": str(directory.relative_to(root)),
            })
    output = []
    for (rep, family, regime, count, negative), samples in sorted(grouped.items()):
        times = [r["result"].get("solver_seconds") for r in samples]
        complete = all(t is not None for t in times)
        output.append({
            "representation": rep, "family": family, "regime": regime, "count": count, "negative": negative,
            "samples": len(samples), "statuses": [r["result"]["status"] for r in samples],
            "median_seconds": median(times) if complete else None,
            "min_seconds": min(times) if complete else None, "max_seconds": max(times) if complete else None,
            "operations": samples[0]["operations"], "capacity": samples[0]["capacity"],
            "appended_entries": samples[0].get("appended_entries"),
        })
    save(base / "primary-summary.json", [row for row in output if row["family"] != "growing"])
    if workload == "mixed":
        save(base / "growing-summary.json", [row for row in output if row["family"] == "growing"])
    with (base / "measurements.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for regime in ("concrete", "symbolic"):
        if workload == "mixed":
            for family in ("fixed", "growing"):
                data = [row for row in output if row["family"] == family]
                prefix = "" if family == "fixed" else "growing-"
                graph(data, base / f"{prefix}{regime}.svg", regime, f"mixed, {family} live size", "operations")
                graph(data, base / f"{prefix}{regime}-appends.svg", regime, f"mixed, {family} live size", "appends")
        else:
            graph(output, base / f"{regime}.svg", regime, workload)
    print(workload, len(rows), "samples; all primary streams match across backends")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--workload", choices=["append", "rollback", "equality", "mixed"], required=True)
    args = parser.parse_args()
    summarize(args.root, args.workload)


if __name__ == "__main__":
    main()
