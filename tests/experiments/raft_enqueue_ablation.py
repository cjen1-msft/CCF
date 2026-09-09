# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Execute the preregistered, three-repeat single-factor enqueue study."""

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import types
from pathlib import Path

from raft_trace_sweep import run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    args = parser.parse_args()
    for field in vars(args):
        setattr(args, field, getattr(args, field).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    args.workspace_root.mkdir(parents=True, exist_ok=True)
    assert (
        subprocess.check_output(
            ["stat", "-f", "-c", "%T", str(args.workspace_root)], text=True
        ).strip()
        == "tmpfs"
    )
    preregistration = json.loads(args.preregistration.read_text())
    with (args.build / "samples/apps/basic/basic").open("rb") as binary:
        sha = hashlib.file_digest(binary, "sha256").hexdigest()
    (args.output / "metadata.json").write_text(
        json.dumps(
            {
                "binary_sha256": sha,
                "preregistration_sha256": hashlib.sha256(
                    args.preregistration.read_bytes()
                ).hexdigest(),
                "preregistration": preregistration,
                "storage": "tmpfs",
                "command": sys.argv,
            },
            indent=2,
        )
    )
    results = []
    for index, order in enumerate(preregistration["design"]["order"], start=1):
        for variant in order:
            name = f"{index}-{variant}"
            trial = args.output / name
            trial.mkdir()
            options = types.SimpleNamespace(
                repo=args.repo,
                build=args.build,
                output=trial,
                workspace_root=args.workspace_root / name,
                seconds=30,
                settle=5,
                rates=[10000],
                profile=False,
                thread_stats=True,
                ring_size="1MB",
                benchmark_variant=variant,
            )
            result = run(options, "ring_discard")[0]
            assert result["failures"] == 0
            assert not result["run_transport_drop_warnings"]
            assert not result["run_slow_storage_warnings"]
            stats = []
            for node in range(2):
                path = (
                    trial
                    / "ring_discard"
                    / f"ring_discard_{node}"
                    / "trace_ablation.json"
                )
                data = json.loads(path.read_text())
                assert data["variant"] == variant
                assert data["enqueued"] == data["consumed"] == data["consumed_records"]
                assert data["drop_totals"]["total"] == 0
                stats.append(data)
            scalar = {
                key: sum(s[key] for s in stats)
                for key in (
                    "enqueued",
                    "consumer_wakeups",
                    "scan_rounds",
                    "empty_reads",
                    "nonempty_reads",
                )
            }
            scalar["notifications"] = sum(
                sum(s["producer_actual_notifications"]) for s in stats
            )
            scalar["records_per_nonempty_read"] = (
                scalar["enqueued"] / scalar["nonempty_reads"]
            )
            result.update({"variant": variant, "repeat": index, "mechanism": scalar})
            results.append(result)
            (args.output / "results.json").write_text(json.dumps(results, indent=2))
            print(variant, index, result["completed_rps"], scalar, flush=True)
    summary = {}
    for variant in preregistration["design"]["order"][0]:
        rows = [r for r in results if r["variant"] == variant]
        assert len(rows) == 3
        summary[variant] = {
            "median_completed_rps": statistics.median(r["completed_rps"] for r in rows),
            "min_completed_rps": min(r["completed_rps"] for r in rows),
            "max_completed_rps": max(r["completed_rps"] for r in rows),
            "median_node_cpu_percent": statistics.median(
                r["node_cpu_p50_percent"] for r in rows
            ),
            "median_notifications": statistics.median(
                r["mechanism"]["notifications"] for r in rows
            ),
            "median_wakeups": statistics.median(
                r["mechanism"]["consumer_wakeups"] for r in rows
            ),
            "median_records_per_read": statistics.median(
                r["mechanism"]["records_per_nonempty_read"] for r in rows
            ),
        }
    for data in summary.values():
        data["loss_percent"] = 100 * (
            1
            - data["median_completed_rps"] / summary["baseline"]["median_completed_rps"]
        )
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
