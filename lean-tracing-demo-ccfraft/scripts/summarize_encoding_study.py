#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Export the recorded experiment samples and draw the small bit-vector comparison."""

import argparse
import csv
import json
import math
from pathlib import Path
from statistics import median


def bitvector_plot(rows, path):
    modes = {"integer": "#1768ac", "bv-smt": "#178047", "bv-sat": "#a14b12"}
    peak = max(1000 * row["result"]["solver_seconds"] for row in rows)
    step = max(1, math.ceil(peak / 30)) * 10
    scale = 220 / (3 * step)
    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="980" height="410">',
        '<rect width="980" height="410" fill="white"/>',
        '<text x="50" y="25" font-family="sans-serif" font-size="17">F: finite fragment, Z3 process milliseconds, three-run medians</text>',
    ]
    for panel, negative in enumerate((False, True)):
        left = 65 + panel * 470
        svg.append(f'<path d="M{left} 65V300H{left+370}" fill="none" stroke="black"/>')
        title = "SAT" if not negative else "Transition-dependent UNSAT"
        svg.append(f'<text x="{left}" y="55" font-family="sans-serif">{title}</text>')
        for value in (0, step, 2 * step, 3 * step):
            y = 300 - value * scale
            svg.append(f'<text x="{left-40}" y="{y}" font-family="sans-serif">{value}</text>')
        for count in range(1, 6):
            x = left + (count - 1) * 80 + 20
            svg.append(f'<text x="{x}" y="322" font-family="sans-serif">{count}</text>')
        for mode, color in modes.items():
            points = []
            for count in range(1, 6):
                values = [1000 * r["result"]["solver_seconds"] for r in rows
                          if r["mode"] == mode and r["receives"] == count and r["negative"] == negative]
                value = median(values)
                x, y = left + (count - 1) * 80 + 20, 300 - value * scale
                points.append(f"{x},{y}")
                svg.append(f'<circle cx="{x}" cy="{y}" r="3" fill="{color}"><title>{mode}: {value:.3f} ms</title></circle>')
            svg.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="{color}" stroke-width="2"/>')
    for index, (mode, color) in enumerate(modes.items()):
        svg.append(f'<text x="{150 + index*240}" y="355" fill="{color}" font-family="sans-serif">{mode}</text>')
    svg.append('<text x="160" y="388" font-family="sans-serif">X: receives. Startup included; this is not full-trace performance.</text>')
    svg.append("</svg>")
    path.write_text("\n".join(svg))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    manifest = {case["name"]: case for case in json.loads((args.results / "manifest.json").read_text())}
    records = []
    for experiment, phases in {
        "a": ["screen", "repeat", "profile"],
        "e1": ["screen", "repeat", "profile"],
        "d-entry": ["lambda-screen", "bridge-pilot", "profile"],
        "d-packet": ["bridge-pilot", "profile"],
        "e2": ["screen", "repeat", "middle-repeat", "bound32", "grounded-pilot", "profile"],
        "c": ["screen", "repeat", "profile"],
    }.items():
        for phase in phases:
            path = args.results / experiment / phase / "summary.json"
            for row in json.loads(path.read_text()):
                result = row["result"]
                case = manifest[row["case"]]
                stats = result.get("stats", {})
                records.append({
                    "experiment": experiment, "phase": phase, "case": row["case"],
                    "mode": row["mode"], "sample": row["sample"], "profile": row["profile"],
                    "receives": row["receives"], "actions": case["actions_total"],
                    "instructions": case["instructions"], "status": result["status"],
                    "z3_process_seconds": result.get("solver_seconds"),
                    "worker_wall_seconds": result["wall_seconds"],
                    "limit_seconds": result["limit_seconds"],
                    "decisions": stats.get("decisions"), "array_splits": stats.get("array-splits"),
                    "datatype_splits": stats.get("datatype-splits"),
                    "quantifier_instances": stats.get("quant-instantiations"),
                    "max_memory": stats.get("max-memory"),
                    "source_summary": str(path.relative_to(args.results)),
                    "action_counts": json.dumps(case["actions"], sort_keys=True),
                })
    with (args.results / "measurements.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    path = args.results / "f/trial-v2/summary.json"
    finite = json.loads(path.read_text())
    bitvector_plot(finite, path.parent / "scaling.svg")
    with (path.parent / "measurements.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["receives", "negative", "mode", "sample", "status", "z3_process_seconds", "worker_wall_seconds"])
        for row in finite:
            result = row["result"]
            writer.writerow([row["receives"], row["negative"], row["mode"], row["sample"],
                             result["status"], result["solver_seconds"], result["wall_seconds"]])
    print(f"Exported {len(records)} native-trace samples and {len(finite)} finite-fragment samples")


if __name__ == "__main__":
    main()
