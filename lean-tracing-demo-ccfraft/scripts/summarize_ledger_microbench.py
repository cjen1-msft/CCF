#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Export all ledger microbenchmark samples and compare SAT and UNSAT curves."""

import argparse
import csv
import html
import json
import math
from pathlib import Path

from ledger_microbench import summary


def chart(root, series, path, title):
    colors = ["#1768ac", "#bb3c29", "#268341", "#8750a1", "#a57413"]
    datasets = []
    for name, label in series:
        data = json.loads((root / name / "summary.json").read_text())
        datasets.append((label, data))
    xmax = max(r["count"] for _, data in datasets for r in data)
    xmin = min(r["count"] for _, data in datasets for r in data)
    values = [r["median_seconds"] for _, data in datasets for r in data if r["median_seconds"] is not None]
    low = math.floor(math.log10(min(values)))
    high = math.ceil(math.log10(max(values + [60])))
    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="570">',
        '<rect width="1100" height="570" fill="white"/>',
        f'<text x="65" y="25" font-family="sans-serif" font-size="18">{html.escape(title)}</text>',
        '<text x="65" y="48" font-family="sans-serif" font-size="12">Log axes. Z3 process seconds; startup included. Triangles are censored, not completed times.</text>',
    ]
    for panel, negative in enumerate((False, True)):
        left = 80 + panel * 535
        svg.append(f'<path d="M{left} 80V410H{left+435}" fill="none" stroke="black"/>')
        svg.append(f'<text x="{left}" y="70" font-family="sans-serif">{"UNSAT controls" if negative else "SAT"}</text>')
        for power in range(low, high + 1):
            y = 410 - (power - low) / (high - low) * 315
            svg.append(f'<text x="{left-65}" y="{y}" font-family="sans-serif" font-size="12">{10**power:g}s</text>')
        ticks = sorted({r["count"] for _, data in datasets for r in data})
        for count in ticks:
            x = left + 10 + (math.log2(count / xmin) / max(1, math.log2(xmax / xmin))) * 410
            svg.append(f'<text x="{x-9}" y="430" font-family="sans-serif" font-size="11">{count}</text>')
        for color, (label, data) in zip(colors, datasets, strict=False):
            points = []
            for row in data:
                if row["negative"] != negative:
                    continue
                seconds = row["median_seconds"]
                external = any(status == "external_cutoff" for status in row["statuses"])
                if seconds is None and not external:
                    continue
                x = left + 10 + math.log2(row["count"] / xmin) / max(1, math.log2(xmax / xmin)) * 410
                y = 410 - (math.log10(seconds if seconds is not None else 60) - low) / (high - low) * 315
                tip = html.escape(f'{label}, N={row["count"]}, {seconds if seconds is not None else "external cutoff"}')
                if seconds is None:
                    svg.append(f'<path d="M{x} {y-5}l-5 9h10z" fill="{color}"><title>{tip}</title></path>')
                else:
                    points.append(f"{x},{y}")
                    svg.append(f'<circle cx="{x}" cy="{y}" r="3.5" fill="{color}"><title>{tip}</title></circle>')
            svg.append(f'<polyline points="{" ".join(points)}" stroke="{color}" fill="none"/>')
    for index, (label, _) in enumerate(datasets):
        svg.append(f'<text x="85" y="{462+index*19}" fill="{colors[index]}" font-family="sans-serif" font-size="13">{html.escape(label)}</text>')
    svg.append("</svg>")
    path.write_text("\n".join(svg))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--typed-equality", action="store_true")
    args = parser.parse_args()
    rows = []
    for directory in sorted(args.root.iterdir()):
        if not directory.is_dir() or not (directory / "samples.json").exists():
            continue
        if args.typed_equality and directory.name not in (
            "equality-typed-normalized-fixed16", "equality-typed-direct-fixed16"
        ):
            continue
        environment = json.loads((directory / "environment.json").read_text())
        if "arguments" not in environment:
            continue
        summary(directory)
        for item in json.loads((directory / "samples.json").read_text()):
            result, metadata = item["result"], item["metadata"]
            stats = result.get("stats", {})
            rows.append({
                "series": directory.name, "operation": metadata["operation"], "variant": metadata["variant"],
                "count": item["count"], "initial_length": metadata["initial_length"],
                "final_length": metadata["final_length"], "observation": metadata["observation"],
                "negative": item["negative"], "sample": item["sample"], "status": result["status"],
                "z3_process_seconds": result.get("solver_seconds"), "worker_wall_seconds": result["wall_seconds"],
                "smt_bytes": item["smt_bytes"], "clauses": item["clauses"], "rlimit": stats.get("rlimit-count"),
                "decisions": stats.get("decisions"), "quantifier_instances": stats.get("quant-instantiations"),
                "max_memory": stats.get("max-memory"), "solver_version": environment["solver_version"],
            })
    filename = "typed-equality-measurements.csv" if args.typed_equality else "measurements.csv"
    with (args.root / filename).open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    if args.typed_equality:
        chart(args.root, [
            ("equality-native-fixed16", "Original normalized equality, no extra type predicates"),
            ("equality-typed-normalized-fixed16", "Normalized equality plus live-entry type predicates"),
            ("equality-typed-direct-fixed16", "Direct equality plus identical live-entry type predicates"),
        ], args.root / "typed-equality-comparison.svg", "Live-array equality chains, fixed 16-entry ledger")
        print(f"Exported {len(rows)} typed-equality samples and comparison plot")
        return
    chart(args.root, [
        ("append-native-final", "Native quantified splice"),
        ("append-store-final", "Direct stores"),
        ("append-cells-final", "Explicit per-state cell copies"),
        ("append-ssa-final", "Reused entry versions"),
    ], args.root / "append-comparison.svg", "Append-only state/update chains, empty initial ledger")
    chart(args.root, [
        ("rollback-native-growing", "Native rollback, initial length N+1"),
        ("rollback-relational-control", "Deliberately relational rollback, initial length N+1"),
        ("rollback-native-fixed1024-last", "Native rollback, initial length 1024, one final read"),
    ], args.root / "rollback-comparison.svg", "Rollback: retained array versus fresh-array relations")
    chart(args.root, [
        ("equality-native-fixed16", "Native quantified equality"),
        ("equality-ground-fixed16", "Ground normalized equality, arrays"),
        ("equality-cells-fixed16", "Ground normalized equality, scalar cells"),
        ("equality-canonical-fixed16", "Direct equality, canonical scalar entries"),
        ("equality-ssa-fixed16", "Reused equal entry representatives"),
    ], args.root / "equality-comparison.svg", "Equality chains over a fixed 16-entry ledger")
    print(f"Exported {len(rows)} samples and three paired-polarity plots")


if __name__ == "__main__":
    main()
