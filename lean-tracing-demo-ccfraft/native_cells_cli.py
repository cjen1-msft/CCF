# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Opt-in real-trace runner for the unproved canonical-cell representation."""

import hashlib
import json
from pathlib import Path
import subprocess
import time

from native_input import unique_object
from native_origin import reduce_raw
from native_reduction import native_document
from native_solver import find_z3
from Shared.solver import ValidationError


def run_cells(args):
    from native_cells import lower, trace_capacities
    from scripts.encoding_study import FULL_CYCLE, save, solve

    started = time.perf_counter()
    z3_path = find_z3(args.z3)
    output = args.output_dir.resolve()
    if output.exists():
        raise ValidationError("Canonical-cell runs require a fresh output directory")
    raw = args.trace.read_bytes()
    origin = reduce_raw(raw) if args.raw else None
    document = native_document(origin.trace, args.bootstrap) if origin else json.loads(raw, object_pairs_hook=unique_object)
    initial = json.loads(args.cells_initial_state.read_text(), object_pairs_hook=unique_object)
    capacities = trace_capacities(document, initial)
    if args.cells_capacity_scale < 1:
        raise ValidationError("Cells capacity scale must be positive")
    capacities["ledger"] *= args.cells_capacity_scale
    capacities["queue"] *= args.cells_capacity_scale
    source_seconds = time.perf_counter() - started
    output.mkdir(parents=True)
    save(output / "input.json", document)
    save(output / "initial-state.json", initial)
    save(output / "capacities.json", capacities)
    if origin:
        (output / "raw.ndjson").write_bytes(raw)
        save(output / "reduction.json", origin.certificate)
    native_started = time.perf_counter()
    completed = subprocess.run(
        ["lake", "env", "lean", "--run", "Prototype/CellsNativeMain.lean"],
        cwd=Path(__file__).parent, input=json.dumps({
            "input": document, "ledger": capacities["ledger"], "queue": capacities["queue"],
        }, sort_keys=True, separators=(",", ":")), text=True, capture_output=True,
    )
    if completed.returncode:
        raise ValidationError(f"Native bounded emission failed: {completed.stderr or completed.stdout}")
    native = json.loads(completed.stdout)
    native_seconds = time.perf_counter() - native_started
    save(output / "native-encoding.json", native)
    compiler_started = time.perf_counter()
    cells = lower(native, capacities)
    cells_seconds = time.perf_counter() - compiler_started
    save(output / "cells-encoding.json", cells)
    (output / "trace.smt2").write_text(cells["script"])
    (output / "reference.smt2").write_text(cells["reference_script"])
    result = solve(output / "solver", [cells["script"].removesuffix("(check-sat)\n")], FULL_CYCLE,
                   str(z3_path), args.cells_timeout, args.cells_profile)
    if result["status"] == "error":
        raise ValidationError(f"Canonical-cell solver failed; see {output / 'solver'}")
    names = {clause["name"] for clause in cells["clauses"]}
    if result["status"] == "unsat" and (not result["core"] or not set(result["core"]) <= names):
        raise ValidationError("Canonical-cell solver returned invalid source labels")
    summary = {
        "schema": "ccfraft-canonical-cells-run/v1",
        "status": result["status"], "backend": "canonical-cells",
        "projection_status": result["status"],
        "assurance": cells["assurance"], "trace_correctness_proved": False,
        "initial_state_is_explicit_assumption": True,
        "finite_projection_equivalence_proved": False,
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_records": len(raw.splitlines()) if origin else None,
        "raft_events": sum("msg" in json.loads(line) for line in raw.splitlines()) if origin else None,
        "instructions": len(document["instructions"]), "capacities": capacities,
        "source_seconds": source_seconds, "native_emission_seconds": native_seconds,
        "cell_lowering_seconds": cells_seconds,
        "solver_seconds": result.get("solver_seconds"), "total_seconds": time.perf_counter() - started,
        "metrics": cells["metrics"], "solver": result,
        "implementation_sha256": {
            name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
            for name in ("native_cells.py", "native_cells_cli.py", "Prototype/CellsTemplateMain.lean",
                         "Prototype/CellsNativeMain.lean")
        },
    }
    save(output / "result.json", summary)
    print(json.dumps({key: summary[key] for key in (
        "projection_status", "backend", "assurance", "trace_correctness_proved",
        "initial_state_is_explicit_assumption", "finite_projection_equivalence_proved",
        "raw_records", "raft_events", "instructions", "capacities",
        "native_emission_seconds", "cell_lowering_seconds", "solver_seconds", "total_seconds",
    )}))
