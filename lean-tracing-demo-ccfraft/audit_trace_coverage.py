#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Audit every raft scenario against the current reduction and SMT pipeline."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from reduction import ReductionError, build_certificate
from Shared.capture_traces import capture, find_repo_root
from Shared.smt import SmtEncodingError, build_formula
from Shared.trace_io import NDJSONError, loads_ndjson

ROOT = Path(__file__).resolve().parent
EXPECTED_SCENARIOS = 50


def inventory(output: bytes) -> dict[str, Any]:
    functions: Counter[str] = Counter()
    packets: Counter[str] = Counter()
    roles: Counter[str] = Counter()
    membership: Counter[str] = Counter()
    for line in output.splitlines():
        record = json.loads(line)
        message = record.get("msg")
        if not isinstance(message, dict):
            continue
        function = message.get("function")
        if isinstance(function, str):
            functions[function] += 1
        packet = message.get("packet")
        if isinstance(packet, dict) and isinstance(packet.get("msg"), str):
            packets[packet["msg"]] += 1
        state = message.get("state")
        if isinstance(state, dict):
            if isinstance(state.get("leadership_state"), str):
                roles[state["leadership_state"]] += 1
            if isinstance(state.get("membership_state"), str):
                membership[state["membership_state"]] += 1
    return {
        "functions": dict(sorted(functions.items())),
        "membership_states": dict(sorted(membership.items())),
        "packet_families": dict(sorted(packets.items())),
        "roles": dict(sorted(roles.items())),
    }


def solver_status(cvc5: Path, formula: str, timeout_seconds: float) -> str:
    try:
        completed = subprocess.run(
            [str(cvc5), "--lang=smt2", "-"],
            input=formula,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return "timeout"
    if completed.returncode != 0:
        return "error"
    for line in completed.stdout.splitlines():
        if line.strip() in {"sat", "unsat", "unknown"}:
            return line.strip()
    return "error"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "Measurements/corpus-coverage.json",
    )
    parser.add_argument("--cvc5", type=Path)
    parser.add_argument("--solve", action="store_true")
    parser.add_argument("--solver-timeout-seconds", type=float, default=10)
    parser.add_argument("--require-all", action="store_true")
    args = parser.parse_args()

    if args.solve and args.cvc5 is None:
        located = shutil.which("cvc5")
        if located is None:
            parser.error("--solve requires --cvc5 or cvc5 on PATH")
        args.cvc5 = Path(located)

    repo_root = find_repo_root()
    driver = repo_root / "build/raft_driver"
    scenario_root = repo_root / "tests/raft_scenarios"
    scenarios = sorted(path for path in scenario_root.iterdir() if path.is_file())
    if len(scenarios) != EXPECTED_SCENARIOS:
        raise RuntimeError(
            f"expected {EXPECTED_SCENARIOS} scenarios, found {len(scenarios)}"
        )

    aggregate_functions: Counter[str] = Counter()
    aggregate_packets: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    for scenario in scenarios:
        row: dict[str, Any] = {"scenario": scenario.name}
        try:
            output, capture_wall_ms = capture(driver, scenario)
            row["capture_wall_ms"] = capture_wall_ms
            row["raw_records"] = len(output.splitlines())
            observed = inventory(output)
            row["inventory"] = observed
            aggregate_functions.update(observed["functions"])
            aggregate_packets.update(observed["packet_families"])

            certificate = build_certificate(
                loads_ndjson(output.decode("utf-8"), source=scenario.name)
            )
            row["reduction"] = {
                "accepted": True,
                **certificate["counts"],
            }
            formula = build_formula(certificate)
            row["smt"] = {
                "accepted": True,
                "bytes": len(formula.text.encode("utf-8")),
                "named_assertions": formula.text.count("(assert (!"),
            }
            if args.solve:
                row["solver"] = solver_status(
                    args.cvc5,
                    formula.text,
                    args.solver_timeout_seconds,
                )
        except (NDJSONError, ReductionError, SmtEncodingError, RuntimeError) as error:
            row["reduction"] = {
                "accepted": False,
                "error": str(error),
            }
        rows.append(row)

    accepted = [row["scenario"] for row in rows if row["reduction"]["accepted"]]
    solved = [row["scenario"] for row in rows if row.get("solver") == "sat"]
    result = {
        "aggregate": {
            "accepted_scenarios": len(accepted),
            "emitted_events": sum(row.get("raw_records", 0) for row in rows),
            "function_counts": dict(sorted(aggregate_functions.items())),
            "packet_family_counts": dict(sorted(aggregate_packets.items())),
            "scenario_count": len(rows),
            "sat_scenarios": len(solved),
        },
        "accepted": accepted,
        "sat": solved,
        "scenarios": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"scenarios={len(rows)} accepted={len(accepted)} "
        f"sat={len(solved) if args.solve else 'not-run'}"
    )
    if args.require_all and (
        len(accepted) != len(rows) or (args.solve and len(solved) != len(rows))
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
