#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Serial native ledger microbenchmarks; preserve sources, SMT, timings, and profiles."""

import argparse
import csv
import json
import math
from pathlib import Path
from statistics import median
import subprocess
import time

from encoding_study import FULL_CYCLE, PROJECT, digest, save, solve


def generate(requests):
    started = time.perf_counter()
    process = subprocess.run(
        ["lake", "env", "lean", "--run", "Prototype/LedgerMicroMain.lean"],
        cwd=PROJECT, input=json.dumps(requests), text=True, capture_output=True, check=True,
    )
    return json.loads(process.stdout), time.perf_counter() - started


def summary(output):
    rows = json.loads((output / "samples.json").read_text())
    arguments = json.loads((output / "environment.json").read_text())["arguments"]
    grouped = {}
    for row in rows:
        key = (row["count"], row["negative"])
        grouped.setdefault(key, []).append(row)
    report = []
    for (count, negative), values in sorted(grouped.items()):
        sat = [row["result"]["solver_seconds"] for row in values if row["result"]["status"] in ("sat", "unsat")]
        rlimits = [row["result"].get("stats", {}).get("rlimit-count") for row in values]
        first = values[0]
        requested = arguments.get("negative_samples", 1) if negative else arguments["samples"]
        complete = len(values) == requested and len(sat) == requested
        report.append({
            "count": count, "negative": negative, "statuses": [r["result"]["status"] for r in values],
            "requested_samples": requested, "complete": complete,
            "completed_samples": len(sat), "median_seconds": median(sat) if complete else None,
            "min_seconds": min(sat) if sat else None, "max_seconds": max(sat) if sat else None,
            "median_rlimit": median(rlimits) if all(v is not None for v in rlimits) else None,
            "smt_bytes": first["smt_bytes"], "clauses": first["clauses"],
            "metadata": first["metadata"],
        })
    save(output / "summary.json", report)
    with (output / "samples.csv").open("w", newline="") as stream:
        columns = ["count", "negative", "sample", "status", "seconds", "rlimit", "decisions",
                   "quant_instances", "smt_bytes", "clauses"]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            result = row["result"]
            stats = result.get("stats", {})
            writer.writerow({
                "count": row["count"], "negative": row["negative"], "sample": row["sample"],
                "status": result["status"], "seconds": result.get("solver_seconds"),
                "rlimit": stats.get("rlimit-count"), "decisions": stats.get("decisions"),
                "quant_instances": stats.get("quant-instantiations"),
                "smt_bytes": row["smt_bytes"], "clauses": row["clauses"],
            })
    ratios = []
    for negative in (False, True):
        selected = [r for r in report if r["negative"] == negative]
        for a, b in zip(selected, selected[1:]):
            if a["median_seconds"] is not None and b["median_seconds"] is not None:
                ratio = b["median_seconds"] / a["median_seconds"]
                ratios.append({
                    "negative": negative, "from": a["count"], "to": b["count"], "time_ratio": ratio,
                    "local_log_slope": math.log(ratio) / math.log(b["count"] / a["count"]),
                    "rlimit_ratio": b["median_rlimit"] / a["median_rlimit"] if a["median_rlimit"] and b["median_rlimit"] else None,
                })
    save(output / "growth.json", ratios)
    plot(report, output / "curve.svg", False)
    plot(report, output / "negative-curve.svg", True)
    return report


def plot(rows, path, negative=False):
    positive = [row for row in rows if row["negative"] == negative]
    if not positive:
        return
    lo, hi = math.log2(min(r["count"] for r in positive)), math.log2(max(r["count"] for r in positive))
    top = max([0.1] + [r["median_seconds"] or 60 for r in positive])
    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="820" height="460">',
        '<rect width="820" height="460" fill="white"/>',
        f'<text x="70" y="25" font-family="sans-serif" font-size="16">Ledger microbenchmark: {"negative" if negative else "positive"} query, Z3 process seconds</text>',
        '<path d="M70 45V380H775" fill="none" stroke="black"/>',
    ]
    points = []
    for row in positive:
        x = 80 + 675 * (math.log2(row["count"]) - lo) / max(1, hi - lo)
        value = row["median_seconds"]
        y = 380 - 300 * (value if value is not None else top) / top
        svg.append(f'<text x="{x-10}" y="400" font-family="sans-serif">{row["count"]}</text>')
        title = f'{row["count"]}: {value if value is not None else row["statuses"]}'
        if value is None:
            svg.append(f'<path d="M{x} {y-5}l-5 10h10z" fill="#b43b20"><title>{title}</title></path>')
        else:
            points.append(f"{x},{y}")
            svg.append(f'<circle cx="{x}" cy="{y}" r="4" fill="#1768ac"><title>{title}</title></circle>')
    svg.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="#1768ac"/>')
    for fraction in (0, .25, .5, .75, 1):
        svg.append(f'<text x="5" y="{380-300*fraction}" font-family="sans-serif">{top*fraction:.3g}s</text>')
    svg.append('<text x="95" y="440" font-family="sans-serif">X: operation count, log2 spacing. Triangles: no completed verdict.</text></svg>')
    path.write_text("\n".join(svg))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    parser.add_argument("--operation", choices=["append", "rollback", "equality"], default="append")
    parser.add_argument("--variant", default="native")
    parser.add_argument("--initial", type=int, default=0)
    parser.add_argument("--fixed-final-length", type=int)
    parser.add_argument("--observation", choices=["final", "each", "last"], default="final")
    parser.add_argument("--counts", nargs="+", type=int, default=[8, 16, 32, 64, 128, 256, 512])
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--negative-samples", type=int, default=1)
    parser.add_argument("--only", choices=["both", "positive", "negative"], default="both")
    parser.add_argument("--limit", type=float, default=60)
    parser.add_argument("--profile-count", type=int)
    parser.add_argument("--profile-negative", action="store_true")
    parser.add_argument("--summarize-only", action="store_true")
    parser.add_argument("--profile-only", action="store_true")
    args = parser.parse_args()
    if args.initial < 0 or min(args.samples, args.negative_samples) < 1 or args.limit <= 1 or any(n < 1 for n in args.counts):
        parser.error("Invalid count, sample, initial size, or limit")
    if args.summarize_only:
        summary(args.output)
        return
    if args.profile_only:
        if args.profile_count is None:
            parser.error("--profile-only requires --profile-count")
        data = json.loads((args.output / f"encoding-{args.profile_count}-{args.profile_negative}.json").read_text())
        result = solve(args.output / f"profile-{args.profile_count}-{args.profile_negative}",
                       [data["encoding"]["script"].removesuffix("(check-sat)\n")],
                       FULL_CYCLE, args.z3, args.limit, True)
        if result["status"] in {"error", "sat", "unsat"} and result["status"] != data["metadata"]["expected"]:
            raise ValueError("Unexpected profile verdict")
        return
    if args.fixed_final_length is not None and (
        args.operation != "append" or args.fixed_final_length < max(args.counts)
    ):
        parser.error("Fixed final length requires append counts no larger than that length")
    args.output.mkdir(parents=True, exist_ok=False)
    sources = ["Prototype/LedgerMicroMain.lean", "Sparse/NativeLogSpliceEncoding.lean",
               "Sparse/NativeLogRangeEncoding.lean", "Sparse/NativeBecomeLeader.lean",
               "Sparse/NativeArrayLogWrite.lean", "Sparse/NativeAppendReceive.lean",
               "Sparse/NativeValues.lean", "Sparse/NativeEntryNormalize.lean",
               "Sparse/NativeSmt.lean", "Sparse/NativeEncode.lean",
               "scripts/ledger_microbench.py", "scripts/encoding_study.py"]
    save(args.output / "environment.json", {
        "arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "solver_version": subprocess.run([args.z3, "--version"], text=True, capture_output=True, check=True).stdout.strip(),
        "source_hashes": {name: digest((PROJECT / name).read_bytes()) for name in sources},
    })
    for source in sources:
        target = args.output / "sources" / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((PROJECT / source).read_bytes())
    rows = []
    for count in sorted(set(args.counts)):
        requests = [
            {"operation": args.operation, "variant": args.variant, "count": count,
             "initialLength": args.fixed_final_length - count if args.fixed_final_length is not None else args.initial,
             "observation": args.observation, "negative": negative}
            for negative in (False, True)
        ]
        generated, emission = generate(requests)
        for request, data in zip(requests, generated, strict=True):
            save(args.output / f"input-{count}-{request['negative']}.json", request)
            save(args.output / f"encoding-{count}-{request['negative']}.json", data)
        save(args.output / f"emission-{count}.json", {"seconds": emission, "scripts": 2})
        for index, data in enumerate(generated):
            if (args.only == "positive" and index == 1) or (args.only == "negative" and index == 0):
                continue
            metadata, details = data["metadata"], data["encoding"]
            script = details["script"]
            if not script.endswith("(check-sat)\n"):
                raise ValueError("Unexpected native query")
            body = script.removesuffix("(check-sat)\n")
            for sample in range(args.samples if index == 0 else args.negative_samples):
                result = solve(args.output / f"run-{count}-{index}-{sample}", [body],
                               FULL_CYCLE, args.z3, args.limit, False)
                row = {"count": count, "negative": index == 1, "sample": sample, "metadata": metadata,
                       "smt_bytes": len(script.encode()), "clauses": len(details["clauses"]), "result": result}
                rows.append(row)
                save(args.output / "samples.json", rows)
                print(args.operation, args.variant, args.initial, args.observation,
                      count, index, sample, result["status"], result.get("solver_seconds"), flush=True)
                if result["status"] in {"sat", "unsat"} and result["status"] != metadata["expected"]:
                    raise ValueError("Unexpected microbenchmark verdict")
                if result["status"] == "error":
                    raise ValueError("Solver protocol error")
                if result["status"] not in {"sat", "unsat"}:
                    break
        report = summary(args.output)
        if any(r["count"] == count and not r["negative"] and r["median_seconds"] is None for r in report):
            break
    if args.profile_count is not None:
        path = args.output / f"encoding-{args.profile_count}-{args.profile_negative}.json"
        if not path.exists():
            raise ValueError("Profile count was not reached in the screen")
        data = json.loads(path.read_text())
        result = solve(args.output / "profile", [data["encoding"]["script"].removesuffix("(check-sat)\n")],
                       FULL_CYCLE, args.z3, args.limit, True)
        save(args.output / "profile-status.json", {
            "count": args.profile_count, "negative": args.profile_negative, "result": result,
        })
        if result["status"] in {"error", "sat", "unsat"} and result["status"] != data["metadata"]["expected"]:
            raise ValueError("Unexpected profile verdict")


if __name__ == "__main__":
    main()
