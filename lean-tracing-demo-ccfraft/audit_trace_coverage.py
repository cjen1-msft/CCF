#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Audit every raft scenario against the current reduction and SMT pipeline."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import contextlib
import io
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from reduction import build_certificate, write_certificate
from Shared.trace_io import loads_ndjson, read_ndjson
from Shared.capture_traces import capture, find_repo_root
from Shared.solver import find_cvc5
from validate import (
    VALIDATION_ERRORS,
    artifact_paths,
    clear_artifacts,
    read_bounds,
    validate,
)
from validate_checked import reject_artifact_collisions

ROOT = Path(__file__).resolve().parent
EXPECTED_SCENARIOS = 50


def inventory(output: bytes) -> dict[str, Any]:
    functions: Counter[str] = Counter()
    packets: Counter[str] = Counter()
    roles: Counter[str] = Counter()
    membership: Counter[str] = Counter()
    for record in loads_ndjson(output.decode("utf-8")):
        message = record.value.get("msg")
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
    )
    parser.add_argument("--bounds", type=Path, required=True)
    parser.add_argument(
        "--artifacts", type=Path, default=ROOT / "Artifacts/corpus-coverage"
    )
    parser.add_argument("--cvc5", type=Path)
    parser.add_argument("--solve", action="store_true")
    parser.add_argument("--core-reduction-seconds", type=float, default=5.0)
    parser.add_argument("--require-all", action="store_true")
    parser.add_argument(
        "--scenario",
        action="append",
        help="audit only this scenario; may be repeated",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="raise the first reduction or SMT error",
    )
    parser.add_argument(
        "--refresh-demo-certificates",
        action="store_true",
        help="rewrite the six checked-in demo certificates before the audit",
    )
    parser.add_argument(
        "--capture-dir",
        type=Path,
        help="write each raw captured scenario trace as NDJSON",
    )
    args = parser.parse_args(argv)
    if args.output is None:
        args.output = (
            ROOT / "Artifacts/corpus-coverage-targeted.json"
            if args.scenario
            else ROOT / "Measurements/corpus-coverage.json"
        )

    repo_root = find_repo_root()
    driver = repo_root / "build/raft_driver"
    scenario_root = repo_root / "tests/raft_scenarios"
    scenarios = sorted(path for path in scenario_root.iterdir() if path.is_file())
    if not args.scenario and len(scenarios) != EXPECTED_SCENARIOS:
        raise RuntimeError(
            f"expected {EXPECTED_SCENARIOS} scenarios, found {len(scenarios)}"
        )
    if args.scenario:
        requested = set(args.scenario)
        scenarios = [path for path in scenarios if path.name in requested]
        missing = requested.difference(path.name for path in scenarios)
        if missing:
            parser.error(f"unknown scenarios: {sorted(missing)}")

    destinations = [args.output]
    for scenario in scenarios:
        output_directory = args.artifacts / scenario.name
        destinations.extend(artifact_paths(output_directory))
        destinations.append(output_directory / "raw.ndjson")
        if args.capture_dir is not None:
            destinations.append(args.capture_dir / f"{scenario.name}.ndjson")
    demo_inputs = []
    certificate_root = ROOT / "Traces/Certificates"
    if args.refresh_demo_certificates:
        demo_inputs = sorted((ROOT / "Traces/Captured").glob("*.ndjson"))
        demo_inputs += sorted((ROOT / "Traces/Mutated").glob("*.ndjson"))
        destinations.extend(
            certificate_root / f"{path.stem}.json" for path in demo_inputs
        )
    inputs = (args.bounds, driver, *scenarios, *demo_inputs)
    try:
        reject_artifact_collisions(inputs, destinations)
    except VALIDATION_ERRORS as error:
        parser.error(str(error))

    args.output.unlink(missing_ok=True)
    try:
        bounds = read_bounds(args.bounds)
        if args.solve:
            args.cvc5 = find_cvc5(args.cvc5)
    except VALIDATION_ERRORS as error:
        parser.error(str(error))
    for input_path in demo_inputs:
        write_certificate(
            certificate_root / f"{input_path.stem}.json",
            build_certificate(read_ndjson(input_path)),
        )

    aggregate_functions: Counter[str] = Counter()
    aggregate_packets: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    for scenario in scenarios:
        row: dict[str, Any] = {"scenario": scenario.name}
        output = b""
        output_directory = args.artifacts / scenario.name
        phase = "capture"
        try:
            clear_artifacts(output_directory, protected_inputs=inputs)
            output, capture_wall_ms = capture(driver, scenario)
            raw_path = output_directory / "raw.ndjson"
            raw_path.write_bytes(output)
            if args.capture_dir is not None:
                args.capture_dir.mkdir(parents=True, exist_ok=True)
                (args.capture_dir / f"{scenario.name}.ndjson").write_bytes(output)
            row["capture_wall_ms"] = capture_wall_ms
            row["raw_records"] = len(output.splitlines())
            observed = inventory(output)
            row["inventory"] = observed
            aggregate_functions.update(observed["functions"])
            aggregate_packets.update(observed["packet_families"])

            phase = "validation"
            with contextlib.redirect_stdout(io.StringIO()):
                status = validate(
                    raw_path,
                    output_directory,
                    bounds=bounds,
                    cvc5=args.cvc5,
                    encode_only=not args.solve,
                    core_reduction_budget_seconds=args.core_reduction_seconds,
                )
            certificate = json.loads(
                (output_directory / "reduced-certificate.json").read_text(
                    encoding="utf-8"
                )
            )
            row["reduction"] = {
                "accepted": True,
                **certificate["counts"],
            }
            result = json.loads(
                (output_directory / "result.json").read_text(encoding="utf-8")
            )
            formula = (output_directory / "formula.smt2").read_text(encoding="utf-8")
            row["smt"] = {
                "accepted": True,
                "bytes": len(formula.encode("utf-8")),
                "named_assertions": formula.count("(assert (!"),
                "proof_gate": result["proof_gate"],
                "assurance": result["assurance"],
            }
            row["artifacts"] = str(output_directory)
            if args.solve:
                row["solver"] = status
        except (*VALIDATION_ERRORS, RuntimeError) as error:
            if args.fail_fast:
                raise
            reduced_path = output_directory / "reduced-certificate.json"
            if phase == "validation" and reduced_path.is_file():
                certificate = json.loads(reduced_path.read_text(encoding="utf-8"))
                row["reduction"] = {"accepted": True, **certificate["counts"]}
                phase = (
                    "checked_backend"
                    if (output_directory / "certificate.json").is_file()
                    else "normalization"
                )
            elif phase == "validation":
                phase = "reduction"
            row.setdefault("reduction", {"accepted": False})
            row["error"] = {"phase": phase, "message": str(error)}
            row["smt"] = {"accepted": False, "error": str(error)}
            match = re.search(r"\bline (\d+)\b|:(\d+):", str(error))
            if match is not None and output:
                line_number = int(match.group(1) or match.group(2))
                lines = output.splitlines()
                start = max(1, line_number - 2)
                end = min(len(lines), line_number + 2)
                row["error"]["context"] = [
                    {
                        "line": number,
                        "raw": lines[number - 1].decode("utf-8", errors="replace"),
                    }
                    for number in range(start, end + 1)
                ]
        rows.append(row)

    accepted = [row["scenario"] for row in rows if row["smt"]["accepted"]]
    solved = [row["scenario"] for row in rows if row.get("solver") == "sat"]
    result = {
        "bounds": dict(bounds),
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
