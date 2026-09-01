#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Capture raw raft_driver events without semantic preprocessing."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCENARIOS = ("bad_network", "soft_rollback")


def find_repo_root() -> Path:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "build" / "raft_driver").is_file():
            return candidate
    raise RuntimeError("could not locate repo-root build/raft_driver")


def capture(driver: Path, scenario: Path) -> bytes:
    proc = subprocess.run(
        [driver, scenario],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise RuntimeError(f"{driver} {scenario} exited with status {proc.returncode}")

    lines = []
    for emitted_line in proc.stdout.splitlines():
        try:
            record = json.loads(emitted_line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("tag") == "raft_trace":
            lines.append(emitted_line)

    if not lines:
        raise RuntimeError(f"{scenario} emitted no raft_trace records")

    output = "".join(f"{line}\n" for line in lines).encode("utf-8")
    for line_number, line in enumerate(output.splitlines(), start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"{scenario}: invalid JSON on captured line {line_number}: {exc}"
            ) from exc
        if not isinstance(record, dict) or record.get("tag") != "raft_trace":
            raise RuntimeError(
                f"{scenario}: captured line {line_number} is not tagged raft_trace"
            )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture raw raft_driver traces for the Lean tracing demo."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare fresh captures with fixtures without replacing them",
    )
    args = parser.parse_args()

    repo_root = find_repo_root()
    driver = repo_root / "build" / "raft_driver"
    scenarios_dir = repo_root / "tests" / "raft_scenarios"
    captured_dir = repo_root / "lean-tracing-demo-ccfraft" / "Traces" / "Captured"

    captures = {name: capture(driver, scenarios_dir / name) for name in SCENARIOS}

    if args.check:
        matches = True
        for name, fresh in captures.items():
            fixture = captured_dir / f"{name}.ndjson"
            if not fixture.is_file():
                print(f"missing fixture: {fixture}", file=sys.stderr)
                matches = False
            elif fixture.read_bytes() != fresh:
                print(f"fixture differs: {fixture}", file=sys.stderr)
                matches = False
        if not matches:
            return 1
        print("Captured traces match checked-in fixtures.")
        return 0

    captured_dir.mkdir(parents=True, exist_ok=True)
    for name, output in captures.items():
        fixture = captured_dir / f"{name}.ndjson"
        fixture.write_bytes(output)
        print(f"Wrote {len(output.splitlines())} records to {fixture}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
