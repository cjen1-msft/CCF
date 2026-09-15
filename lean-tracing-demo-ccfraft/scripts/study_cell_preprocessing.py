#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Recheck saved explicit-cell formulas with isolated preprocessing pipelines."""

import argparse
import json
from pathlib import Path
from statistics import median
import subprocess

from encoding_study import FULL_CYCLE, digest, save, solve

PIPELINES = {
    "bare-smt": "(check-sat-using smt)\n",
    "simp-eqs": "(check-sat-using (then simplify solve-eqs simplify smt))\n",
    "full-cycle": FULL_CYCLE,
    "extra-round": (
        "(check-sat-using (then simplify solve-eqs simplify "
        "simplify propagate-values solve-eqs simplify smt))\n"
    ),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--microbench", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--z3", required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    save(args.output / "environment.json", {
        "z3": subprocess.run([args.z3, "--version"], text=True, capture_output=True, check=True).stdout.strip(),
        "pipelines": PIPELINES, "source_sha256": digest(Path(__file__).read_bytes()),
        "note": "All runs retain named-core support and MBQI-only; no formulas rewritten.",
    })
    cases = [
        ("append-cells-final", "explicit-append"), ("append-ssa-final", "reused-append"),
        ("equality-canonical-fixed16", "explicit-equality"), ("equality-ssa-fixed16", "reused-equality"),
    ]
    rows = []
    for source, label in cases:
        for count in (32, 64, 128):
            pipelines = list(PIPELINES) if label.startswith("explicit") else ["full-cycle"]
            for negative in (False, True):
                path = args.microbench / source / f"encoding-{count}-{negative}.json"
                data = json.loads(path.read_text())
                script = data["encoding"]["script"]
                if not script.endswith("(check-sat)\n"):
                    raise ValueError("Expected native script ending in one query")
                body = script.removesuffix("(check-sat)\n")
                for sample in range(1 if negative else 3):
                    order = pipelines if sample % 2 == 0 else list(reversed(pipelines))
                    for pipeline in order:
                        directory = args.output / f"{label}-{count}-{negative}-{pipeline}-{sample}"
                        result = solve(directory, [body], PIPELINES[pipeline], args.z3, 60, False)
                        row = {
                            "case": label, "count": count, "negative": negative, "sample": sample,
                            "pipeline": pipeline, "source": str(path), "script_sha256": digest(script.encode()),
                            "result": result,
                        }
                        rows.append(row)
                        save(args.output / "samples.json", rows)
                        if result["status"] != data["metadata"]["expected"]:
                            raise ValueError(f"Preprocessing case did not preserve verdict: {row}")
            if label.startswith("explicit") and count == 128:
                script = json.loads(
                    (args.microbench / source / f"encoding-{count}-False.json").read_text()
                )["encoding"]["script"]
                for pipeline, tactic in (
                    ("simp-eqs", "(then simplify solve-eqs simplify)"),
                    ("full-cycle", "(then simplify propagate-values solve-eqs simplify)"),
                ):
                    diagnostic = script.removesuffix("(check-sat)\n") + f"(apply {tactic})\n"
                    completed = subprocess.run(
                        [args.z3, "-in", "unsat_core=true", "smt.ematching=false", "smt.mbqi=true"],
                        input=diagnostic, capture_output=True, text=True, timeout=60, check=True,
                    )
                    (args.output / f"{label}-{pipeline}-preprocessed.txt").write_text(completed.stdout)
                    (args.output / f"{label}-{pipeline}-preprocessed.stderr").write_text(completed.stderr)
                    if "(error" in completed.stdout:
                        raise ValueError("Preprocessing diagnostic failed")
    summary = []
    for source, label in cases:
        for count in (32, 64, 128):
            for pipeline in PIPELINES:
                selected = [row for row in rows if row["case"] == label and row["count"] == count
                            and row["pipeline"] == pipeline and not row["negative"]]
                if not selected:
                    continue
                summary.append({
                    "case": label, "count": count, "pipeline": pipeline,
                    "median_seconds": median(row["result"]["solver_seconds"] for row in selected),
                    "min_seconds": min(row["result"]["solver_seconds"] for row in selected),
                    "max_seconds": max(row["result"]["solver_seconds"] for row in selected),
                    "eliminated_variables": selected[0]["result"]["stats"].get("solve-eqs-elim-vars"),
                    "solver_reported_time": selected[0]["result"]["stats"].get("time"),
                    "solver_reported_total_time": selected[0]["result"]["stats"].get("total-time"),
                })
    save(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
