#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate the self-contained CCF Raft trace-validation pipeline report."""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
LEAN_ROOT = REPO_ROOT / "lean"
OUTPUT_PATH = LEAN_ROOT / "CCFRaft" / "trace-validation-pipeline-report.html"
EXPECTED_HEAD = "00d917fcf2d233f83194f8b223b8f0b74efffae6"
WORKSPACE_URL = (
    "vscode://vscode-remote/wsl+AzureLinux3.0"
    "/home/cjen1-msft/CCF/.worktrees/veil-consistency"
)

ARTIFACTS = {
    "certificate": LEAN_ROOT
    / ".lake/build/full-trace-prototype/proposed-mapping-certificate-v2.json",
    "cheap_witness": LEAN_ROOT / ".lake/build/cheap-full-state-smt/witness-v1.json",
    "benchmark": LEAN_ROOT / ".lake/build/cheap-full-state-smt/benchmark-v1.json",
    "benchmark_report": LEAN_ROOT / ".lake/build/cheap-full-state-smt/report.md",
    "canonical_output": LEAN_ROOT
    / ".lake/build/cheap-full-state-smt/canonical-lean.out",
    "full_witness": LEAN_ROOT / ".lake/build/naive-full-state-smt/witness-v1.json",
}

CURRENT_SOURCES = {
    "scenario": REPO_ROOT / "tests/raft_scenarios/replicate",
    "preprocessor": REPO_ROOT / "tests/raft_scenarios_runner.py",
    "reducer": LEAN_ROOT / "CCFRaft/full_trace_prototype.py",
    "smt": LEAN_ROOT / "CCFRaft/cheap_full_state_smt.py",
    "decoder": LEAN_ROOT / "CCFRaft/cheap_full_state_smt.py",
    "lean_generator": LEAN_ROOT / "CCFRaft/cheap_full_state_lean.py",
    "model": LEAN_ROOT / "CCFRaft/Model.lean",
    "simulation": LEAN_ROOT / "CCFRaft/Simulation.lean",
    "trace_validation": LEAN_ROOT / "CCFRaft/TraceValidation.lean",
    "properties": LEAN_ROOT / "CCFRaft/Properties.lean",
    "full_script": LEAN_ROOT / "check_ccfraft_full_trace_prototype.sh",
    "cheap_script": LEAN_ROOT / "check_ccfraft_cheap_full_state_prototype.sh",
    "generated_lean": LEAN_ROOT
    / ".lake/build/cheap-full-state-smt/CanonicalCheapFullStateWitness.lean",
}


class ReportError(RuntimeError):
    """Report missing or inconsistent report inputs."""


def require(condition: bool, message: str) -> None:
    """Raise a report error when an input contract is false."""

    if not condition:
        raise ReportError(message)


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON object with a path-labelled error."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReportError(f"cannot read JSON artifact {path}: {error}") from error
    require(isinstance(value, dict), f"JSON artifact is not an object: {path}")
    return value


def nested(mapping: Mapping[str, Any], *keys: str) -> Any:
    """Read a required nested field from an artifact."""

    value: Any = mapping
    traversed: list[str] = []
    for key in keys:
        traversed.append(key)
        require(
            isinstance(value, Mapping) and key in value,
            f"artifact field is absent: {'.'.join(traversed)}",
        )
        value = value[key]
    return value


def sha256_file(path: Path) -> str:
    """Return a file's SHA-256 digest."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_git(args: Sequence[str]) -> str:
    """Run a read-only git command from the repository root."""

    completed = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    require(
        completed.returncode == 0,
        f"git {' '.join(args)} failed: {completed.stderr.strip()}",
    )
    return completed.stdout.strip()


def find_line(path: Path, needle: str) -> int:
    """Find the first current-source line that contains a stable needle."""

    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if needle in line:
            return number
    raise ReportError(f"source marker {needle!r} is absent from {path}")


def find_committed_line(commit: str, relative: str, needle: str) -> int:
    """Find a source line in the exact committed file used by GitHub links."""

    source = run_git(["show", f"{commit}:{relative}"])
    for number, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return number
    raise ReportError(
        f"committed source marker {needle!r} is absent from {relative}@{commit}"
    )


def vscode_url(path: Path, line: int = 1, column: int = 1) -> str:
    """Build a VS Code WSL link without the invalid file path segment."""

    return (
        "vscode://vscode-remote/wsl+AzureLinux3.0" f"{path.resolve()}:{line}:{column}"
    )


def github_url(commit: str, relative: str, line: int) -> str:
    """Build a commit-pinned GitHub source link."""

    return f"https://github.com/cjen1-msft/CCF/blob/{commit}/{relative}" f"#L{line}"


def safe_json(value: Any) -> str:
    """Serialize JSON for an HTML script data block."""

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def as_int(value: Any, label: str) -> int:
    """Read a JSON integer without accepting booleans."""

    require(type(value) is int, f"{label} is not an integer")
    return value


def milliseconds(value: int) -> str:
    """Format milliseconds for a compact technical table."""

    if value >= 1000:
        return f"{value / 1000:.1f} s"
    return f"{value} ms"


def median(values: Sequence[int]) -> int:
    """Return the integer median used by the benchmark report."""

    require(bool(values), "solver benchmark has no samples")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) // 2


def percentile_95(values: Sequence[int]) -> int:
    """Return the nearest-rank 95th percentile."""

    require(bool(values), "solver benchmark has no samples")
    ordered = sorted(values)
    rank = (95 * len(ordered) + 99) // 100
    return ordered[rank - 1]


def event_numbers(reduction: Mapping[str, Any]) -> list[int]:
    """Extract event numbers from either certificate event representation."""

    result: list[int] = []
    events = reduction.get("events")
    require(isinstance(events, list), "reduction events are not a list")
    for event in events:
        if type(event) is int:
            result.append(event)
        else:
            require(isinstance(event, Mapping), "reduction event is malformed")
            result.append(as_int(event.get("event"), "reduction event number"))
    return result


def action_numbers(reduction: Mapping[str, Any]) -> list[int]:
    """Extract action numbers from a certificate reduction."""

    actions = reduction.get("actions")
    require(isinstance(actions, list), "reduction actions are not a list")
    return [
        as_int(action.get("action"), "reduction action number")
        for action in actions
        if isinstance(action, Mapping)
    ]


def source_map(head: str) -> list[dict[str, Any]]:
    """Build current and commit-pinned source links."""

    specs = [
        (
            "Scenario input",
            "tests/raft_scenarios/replicate",
            "replicate",
            "Real CCF Raft scenario.",
            True,
        ),
        (
            "Preprocessor",
            "tests/raft_scenarios_runner.py",
            "def preprocess_for_trace_validation",
            "Runs raft_driver and writes preprocessed NDJSON.",
            True,
        ),
        (
            "Deterministic reducer",
            "lean/CCFRaft/full_trace_prototype.py",
            "def reduce_trace",
            "Validates all 53 events and emits the mapping certificate.",
            False,
        ),
        (
            "Cheap SMT generator and decoder",
            "lean/CCFRaft/cheap_full_state_smt.py",
            "def build_encoding",
            "Builds the bounded formula and decodes cvc5 values.",
            False,
        ),
        (
            "Generated-source checker builder",
            "lean/CCFRaft/cheap_full_state_lean.py",
            "def generated_source",
            "Expands the witness and writes the current Lean checker source.",
            False,
        ),
        (
            "Canonical transition system",
            "lean/CCFRaft/Model.lean",
            "def system",
            "Defines Enabled, next, applyAction, and Reachable.",
            True,
        ),
        (
            "Executable structural checks",
            "lean/CCFRaft/Simulation.lean",
            "def stateChecks",
            "Defines stateChecks and edgeChecks used during replay.",
            True,
        ),
        (
            "Canonical replay",
            "lean/CCFRaft/TraceValidation.lean",
            "def applyChecked",
            "Runs applyAction, stateChecks, and edgeChecks.",
            True,
        ),
        (
            "Full invariant",
            "lean/CCFRaft/Properties.lean",
            "def SystemInductiveInvariant",
            "Defines the proof-level invariant that this prototype does not establish.",
            True,
        ),
        (
            "Current generated Lean source",
            "lean/.lake/build/cheap-full-state-smt/CanonicalCheapFullStateWitness.lean",
            "def check :",
            "Contains this witness as generated declarations and six span checks.",
            False,
        ),
        (
            "Pipeline driver",
            "lean/check_ccfraft_cheap_full_state_prototype.sh",
            'generated_source="$output_dir/CanonicalCheapFullStateWitness.lean"',
            "Runs SMT, negative controls, generation, compilation, and replay.",
            False,
        ),
    ]
    rows: list[dict[str, Any]] = []
    for name, relative, needle, role, committed in specs:
        path = REPO_ROOT / relative
        require(path.exists(), f"source-map target is absent: {path}")
        current_line = find_line(path, needle)
        row: dict[str, Any] = {
            "name": name,
            "path": relative,
            "role": role,
            "currentLine": current_line,
            "vscode": vscode_url(path, current_line),
            "github": None,
            "authority": "Current prototype",
        }
        if committed:
            committed_line = find_committed_line(head, relative, needle)
            row["github"] = github_url(head, relative, committed_line)
            row["authority"] = "Committed canonical source"
        rows.append(row)
    return rows


def validate_inputs() -> None:
    """Fail before generation if a required artifact or source is absent."""

    missing = [str(path) for path in ARTIFACTS.values() if not path.is_file()]
    missing.extend(str(path) for path in CURRENT_SOURCES.values() if not path.exists())
    require(
        not missing,
        "required trace-validation inputs are absent:\n  - " + "\n  - ".join(missing),
    )


def build_data() -> dict[str, Any]:
    """Load live artifacts and derive the report's compact data model."""

    validate_inputs()
    certificate = read_json(ARTIFACTS["certificate"])
    cheap = read_json(ARTIFACTS["cheap_witness"])
    benchmark = read_json(ARTIFACTS["benchmark"])
    full = read_json(ARTIFACTS["full_witness"])
    benchmark_report = ARTIFACTS["benchmark_report"].read_text(encoding="utf-8")
    canonical_output = ARTIFACTS["canonical_output"].read_text(encoding="utf-8")

    head = run_git(["rev-parse", "HEAD"])
    require(re.fullmatch(r"[0-9a-f]{40}", head) is not None, "git HEAD is malformed")
    counts = nested(certificate, "counts")
    cheap_counts = nested(cheap, "counts")
    require(
        counts == {key: cheap_counts[key] for key in counts}, "count artifacts differ"
    )
    require(
        as_int(nested(counts, "events"), "event count") == 53
        and as_int(nested(counts, "consumed_events"), "consumed event count") == 53
        and as_int(nested(counts, "reductions"), "reduction count") == 22
        and as_int(nested(counts, "actions"), "action count") == 43,
        "trace dimensions differ from the 53-event prototype",
    )
    require(
        nested(benchmark, "classification") == "VALID_SEGMENT_CHEAP_FOOTPRINT",
        "benchmark classification is not VALID_SEGMENT_CHEAP_FOOTPRINT",
    )
    require(
        "VALID_SEGMENT\n" in canonical_output + "\n", "canonical check did not pass"
    )
    require(
        "Result: `VALID_SEGMENT_CHEAP_FOOTPRINT`" in benchmark_report,
        "benchmark report classification differs",
    )

    reductions_value = certificate.get("reductions")
    require(isinstance(reductions_value, list), "certificate reductions are absent")
    reductions = []
    for reduction in reductions_value:
        require(isinstance(reduction, Mapping), "certificate reduction is malformed")
        events = event_numbers(reduction)
        actions = action_numbers(reduction)
        reductions.append(
            {
                "reduction": as_int(
                    reduction.get("reduction"), "reduction sequence number"
                ),
                "name": str(reduction.get("name", "")),
                "events": events,
                "eventLabel": ", ".join(str(number) for number in events),
                "actions": actions,
                "actionLabel": ", ".join(str(number) for number in actions) or "none",
                "delta": len(actions) - len(events),
                "summary": str(reduction.get("summary", "")),
                "exceptions": list(reduction.get("exception_ids", [])),
            }
        )

    cheap_dimensions = nested(cheap, "formula_dimensions")
    full_dimensions = nested(full, "formula_dimensions")
    cheap_timings = nested(cheap, "timings_ms")
    full_timings = nested(full, "timings_ms")
    benchmark_timings = nested(benchmark, "timings_ms")
    artifact_bytes = nested(benchmark, "artifact_bytes")
    solver_runs = [
        as_int(value, "solver-only sample")
        for value in nested(benchmark_timings, "solver_only_runs")
    ]
    generated_source = CURRENT_SOURCES["generated_lean"]
    generated_lines = len(generated_source.read_text(encoding="utf-8").splitlines())
    generated_bytes = generated_source.stat().st_size
    benchmark_generated_bytes = as_int(
        artifact_bytes["generated_lean_source"],
        "benchmark generated Lean source bytes",
    )
    require(
        generated_lines == 4298 and generated_bytes == benchmark_generated_bytes,
        "generated Lean source size differs from the current benchmark",
    )

    timing_rows = [
        {
            "metric": "Formula bytes",
            "kind": "size",
            "cheap": as_int(artifact_bytes["formula"], "cheap formula bytes"),
            "cheapDisplay": f"{artifact_bytes['formula']:,}",
            "full": as_int(full_dimensions["formula_bytes"], "full formula bytes"),
            "fullDisplay": f"{full_dimensions['formula_bytes']:,}",
            "ratio": "17.35x smaller",
        },
        {
            "metric": "Witness bytes",
            "kind": "size",
            "cheap": ARTIFACTS["cheap_witness"].stat().st_size,
            "cheapDisplay": f"{ARTIFACTS['cheap_witness'].stat().st_size:,}",
            "full": ARTIFACTS["full_witness"].stat().st_size,
            "fullDisplay": f"{ARTIFACTS['full_witness'].stat().st_size:,}",
            "ratio": "2.87x smaller",
        },
        {
            "metric": "Formula generation",
            "kind": "time",
            "cheap": as_int(cheap_timings["formula_generation"], "cheap formula time"),
            "cheapDisplay": milliseconds(cheap_timings["formula_generation"]),
            "full": as_int(full_timings["formula_generation"], "full formula time"),
            "fullDisplay": milliseconds(full_timings["formula_generation"]),
            "ratio": "16.54x faster",
        },
        {
            "metric": "cvc5 end to end",
            "kind": "time",
            "cheap": as_int(
                cheap_timings["direct_smt_end_to_end"], "cheap solver time"
            ),
            "cheapDisplay": milliseconds(cheap_timings["direct_smt_end_to_end"]),
            "full": as_int(full_timings["direct_smt"], "full solver time"),
            "fullDisplay": milliseconds(full_timings["direct_smt"]),
            "ratio": "24.22x faster",
        },
        {
            "metric": "Witness decode",
            "kind": "time",
            "cheap": as_int(benchmark_timings["decode_wall"], "decode wall time"),
            "cheapDisplay": milliseconds(benchmark_timings["decode_wall"]),
            "full": as_int(full_timings["decode"], "full decode time"),
            "fullDisplay": milliseconds(full_timings["decode"]),
            "ratio": "about 14x faster",
        },
        {
            "metric": "Lean generated compile and check",
            "kind": "time",
            "cheap": as_int(
                benchmark_timings["lean_compile_check"], "Lean compile and check time"
            ),
            "cheapDisplay": milliseconds(benchmark_timings["lean_compile_check"]),
            "full": -1,
            "fullDisplay": "not measured",
            "ratio": "generated-source only",
        },
    ]

    status_paths = [
        str(path.relative_to(REPO_ROOT))
        for path in (
            CURRENT_SOURCES["reducer"],
            CURRENT_SOURCES["smt"],
            CURRENT_SOURCES["lean_generator"],
            CURRENT_SOURCES["model"],
            CURRENT_SOURCES["simulation"],
            CURRENT_SOURCES["trace_validation"],
            CURRENT_SOURCES["properties"],
            CURRENT_SOURCES["full_script"],
            CURRENT_SOURCES["cheap_script"],
            SCRIPT_PATH,
            OUTPUT_PATH,
        )
    ]
    status = run_git(["status", "--short", "--", *status_paths])
    status_lines = status.splitlines() if status else []

    projection = nested(cheap, "field_provenance", "projection_summary")
    span_events = nested(projection, "action_span_events")
    require(span_events == [9, 11, 20, 25, 26, 31], "span events differ")
    observations = nested(cheap, "field_provenance", "observations")
    event_window = []
    for observation in observations:
        require(isinstance(observation, Mapping), "observation is malformed")
        event = as_int(observation.get("event"), "observation event")
        if 9 <= event <= 20:
            position = observation.get("position")
            require(isinstance(position, Mapping), "observation position is malformed")
            event_window.append(
                {
                    "event": event,
                    "position": dict(position),
                    "encoded": len(observation.get("encoded_fields", [])),
                    "omitted": len(observation.get("unencoded_fields", [])),
                    "exceptions": list(observation.get("exception_ids", [])),
                }
            )

    stages = [
        {
            "id": "scenario",
            "number": "01",
            "title": "Scenario",
            "summary": "Run the real replicate fixture.",
            "input": "tests/raft_scenarios/replicate and raft_driver",
            "operation": "The scenario drives node 0 and node 1 through bootstrap, reconfiguration, replication, signatures, heartbeats, commits, and final synchronization assertions.",
            "output": "A real raft_trace log tied to scenario commands.",
            "authority": "CCF implementation behavior. This is observed execution, not model validation.",
            "timing": "Included in the full prototype command, but not isolated in the current benchmark.",
            "failure": "A driver error or scenario assertion stops the pipeline before reduction.",
        },
        {
            "id": "preprocessing",
            "number": "02",
            "title": "Preprocessing",
            "summary": "Normalize the raw driver log into 53 NDJSON events.",
            "input": "Raw raft_driver output.",
            "operation": "raft_scenarios_runner.py retains the raft_trace records, attaches scenario command context, and writes replicate.ndjson.",
            "output": "Exactly 53 numbered, preprocessed events.",
            "authority": "Data transformation. It preserves selected implementation observations but does not assert Lean semantics.",
            "timing": "Not isolated in the benchmark.",
            "failure": "Missing records, malformed JSON, or a count other than 53 fails the full-trace script.",
        },
        {
            "id": "reduction",
            "number": "03",
            "title": "Grammar reduction",
            "summary": "Consume every event once and propose 43 actions.",
            "input": "53 preprocessed events.",
            "operation": "The deterministic grammar validates event shapes, groups helper records with their owning C++ operation, and expands aggregate packets into one-entry Lean actions.",
            "output": "22 reductions, 43 action templates, 53 observations, 47 point checkpoints, and six action spans.",
            "authority": "Correspondence data. It proposes a mapping and records omissions. It is not a proof that C++ and Lean steps are equivalent.",
            "timing": "Small compared with formula generation. The current benchmark does not isolate it.",
            "failure": "An unmapped, duplicated, reordered, or field-mismatched event fails certificate generation.",
        },
        {
            "id": "footprint",
            "number": "04",
            "title": "Footprint",
            "summary": "Restrict the experiment to the trace's active state.",
            "input": "Certificate capacities and action grammar.",
            "operation": "Hardcode nodes 0 and 1, seven log slots, four queue slots in each direction, configurations {0} and {0,1}, and one unknown Fin 64 transaction.",
            "output": "A 44-state, 43-action bounded world. Nodes 2 through 14 do not exist in SMT.",
            "authority": "Experimental assumption. The footprint is fixture-specific and its sufficiency is not proved.",
            "timing": "This restriction cuts the formula from 127,566,439 to 7,352,853 bytes.",
            "failure": "A valid full-world completion outside this footprint can make the bounded formula UNSAT.",
        },
        {
            "id": "formula",
            "number": "05",
            "title": "Formula",
            "summary": "Ask whether one bounded explanation exists.",
            "input": "Action skeletons, observation constraints, bounded state shape, and transition lowering.",
            "operation": "Generate an existential SMT formula for S0 through S43, A0 through A42 and unknown parameters, state/action observations, and every bounded transition equation.",
            "output": "A 7,352,853-byte SMT-LIB formula with 26,531 lines.",
            "authority": "Generated and hand-maintained lowering. Equivalence to CCFRaft.Model is not proved.",
            "timing": "About 1.1 seconds.",
            "failure": "Generator errors are pipeline errors. UNSAT is INCONCLUSIVE_ENCODING, not an invalid-trace result.",
        },
        {
            "id": "cvc5",
            "number": "06",
            "title": "cvc5",
            "summary": "Solve the bounded existential formula.",
            "input": "formula.smt2.",
            "operation": "cvc5 searches for values for all bounded states, actions, queues, logs, and the unknown transaction representative.",
            "output": "SAT plus model values. Ten solver-only runs had a 3,857 ms median.",
            "authority": "Authoritative only for satisfiability of the generated bounded formula.",
            "timing": "About 4.2 seconds end to end. Solver-only min 3,510 ms, median 3,857 ms, p95 4,661 ms.",
            "failure": "unknown or timeout is inconclusive. Bounded UNSAT is also inconclusive because lowering and footprint completeness are unproved.",
        },
        {
            "id": "decode",
            "number": "07",
            "title": "Decode",
            "summary": "Turn cvc5 values into a complete cheap witness.",
            "input": "SAT model values and the reduction certificate.",
            "operation": "Resolve aliases, materialize 44 two-node states and 43 actions, select transaction 1 as the Fin 64 representative, and retain field provenance.",
            "output": "witness-v1.json with states, actions, queues, logs, reductions, and observation bindings.",
            "authority": "Data transformation with structural validation. It does not make the witness canonical.",
            "timing": "About 0.9 seconds wall time.",
            "failure": "Missing values, malformed domains, or a certificate-hash mismatch is an encoding error.",
        },
        {
            "id": "lean",
            "number": "08",
            "title": "Canonical Lean check",
            "summary": "Replay the candidate through CCFRaft.Model.",
            "input": "Decoded witness, certificate, and an explicit inert completion for nodes 2 through 14.",
            "operation": "Check S0 stateChecks. For each of 43 actions, call system.applyAction, then stateChecks and edgeChecks. Check all 53 observations and all 558 projected fields.",
            "output": "VALID_SEGMENT, final logs and commits at 7, and all 15 queues drained.",
            "authority": "Canonical transition semantics for this segment. It does not prove S0 Reachable or SystemInductiveInvariant.",
            "timing": "About 70 seconds because Lean compiles 4,298 generated lines. Replay is not the measured bottleneck.",
            "failure": "A disabled action, failed state or edge check, or mismatched observation rejects the SAT witness as an encoding bug.",
        },
        {
            "id": "classification",
            "number": "09",
            "title": "Classification",
            "summary": "Name only what the evidence establishes.",
            "input": "SAT result and passing canonical replay.",
            "operation": "Combine the bounded candidate search with canonical segment checking.",
            "output": "VALID_SEGMENT_CHEAP_FOOTPRINT.",
            "authority": "Positive result for this fixed segment and this hardcoded footprint.",
            "timing": "Useful recurring cost before generated-checker compilation is about 6.2 seconds.",
            "failure": "Never promote this result to reachability, invariant preservation, full C++ and Lean equivalence, or proved SMT lowering.",
        },
    ]

    return {
        "head": head,
        "expectedHead": EXPECTED_HEAD,
        "headMatchesExpected": head == EXPECTED_HEAD,
        "generatedAt": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "workspace": WORKSPACE_URL,
        "classification": nested(benchmark, "classification"),
        "counts": counts,
        "stages": stages,
        "reductions": reductions,
        "eventWindow": event_window,
        "timings": timing_rows,
        "solverRuns": {
            "count": len(solver_runs),
            "min": min(solver_runs),
            "median": median(solver_runs),
            "p95": percentile_95(solver_runs),
            "max": max(solver_runs),
            "values": solver_runs,
        },
        "cheap": {
            "dimensions": cheap_dimensions,
            "timings": cheap_timings,
            "freshTransaction": nested(cheap, "fresh_transaction_id"),
            "initialSemantics": nested(cheap, "initial_state_semantics"),
            "manualAssumptions": nested(cheap, "manual_assumptions"),
            "projection": projection,
            "finalState": cheap["states"][-1],
        },
        "full": {
            "dimensions": full_dimensions,
            "timings": full_timings,
        },
        "benchmark": benchmark,
        "generatedSource": {
            "lines": generated_lines,
            "bytes": generated_bytes,
        },
        "artifactHashes": [
            {
                "name": name,
                "path": str(path.relative_to(REPO_ROOT)),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "vscode": vscode_url(path),
            }
            for name, path in ARTIFACTS.items()
        ],
        "gitStatus": {
            "dirty": bool(status_lines),
            "lines": status_lines,
            "summary": (
                "Current prototype sources have uncommitted changes."
                if status_lines
                else "Selected prototype sources match the worktree index."
            ),
        },
        "sources": source_map(head),
    }


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>CCF Raft trace-validation pipeline</title>
  <style>
    :root {
      --bg: #07111f;
      --panel: #0d1a2c;
      --panel-2: #122238;
      --line: #28415c;
      --text: #e8f0f7;
      --muted: #9eb0c2;
      --cyan: #35c9e6;
      --cyan-soft: #102f43;
      --green: #48d597;
      --amber: #f0b54a;
      --red: #ff6b78;
      --navy: #091728;
      --max: 1500px;
      --radius: 10px;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }
    a { color: var(--cyan); text-underline-offset: 3px; }
    button, input, select { font: inherit; }
    button:focus-visible, input:focus-visible, select:focus-visible, a:focus-visible {
      outline: 2px solid var(--cyan);
      outline-offset: 3px;
    }
    code, pre, .mono {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    }
    code {
      padding: .12rem .28rem;
      border-radius: 4px;
      background: #081525;
      color: #ccebf3;
    }
    pre {
      margin: 0;
      padding: 1rem;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: #06101c;
      color: #d7e8f2;
      white-space: pre-wrap;
    }
    h1, h2, h3, h4 { margin: 0; line-height: 1.2; }
    h1 { max-width: 1000px; font-size: clamp(2rem, 5vw, 4.8rem); letter-spacing: -.045em; }
    h2 { font-size: clamp(1.45rem, 2.5vw, 2.2rem); }
    h3 { font-size: 1.05rem; }
    p { margin: .65rem 0 0; }
    .wrap { width: min(calc(100% - 2rem), var(--max)); margin-inline: auto; }
    .skip {
      position: absolute;
      left: -10000px;
      top: auto;
    }
    .skip:focus {
      left: 1rem;
      top: 1rem;
      z-index: 100;
      padding: .65rem;
      background: var(--text);
      color: var(--bg);
    }
    header {
      padding: 1rem 0 4rem;
      border-bottom: 1px solid var(--line);
      background: var(--navy);
    }
    nav {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      margin-bottom: 5rem;
      color: var(--muted);
      font-size: .9rem;
    }
    nav .links { display: flex; flex-wrap: wrap; gap: 1rem; }
    .eyebrow {
      margin-bottom: .8rem;
      color: var(--cyan);
      font: 700 .76rem/1.2 "SFMono-Regular", Consolas, monospace;
      letter-spacing: .14em;
      text-transform: uppercase;
    }
    .lede {
      max-width: 980px;
      margin-top: 1.2rem;
      color: #c3d0dc;
      font-size: clamp(1rem, 1.8vw, 1.28rem);
    }
    .result-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: .8rem 1.2rem;
      margin-top: 1.6rem;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      min-height: 2rem;
      padding: .32rem .7rem;
      border: 1px solid #2d8b66;
      border-radius: 999px;
      background: #0c2a24;
      color: var(--green);
      font: 700 .78rem/1 "SFMono-Regular", Consolas, monospace;
    }
    .answer { color: var(--text); font-weight: 650; }
    .time-strip {
      display: grid;
      grid-template-columns: 1.1fr 4.2fr .9fr 70fr;
      min-height: 3.15rem;
      margin-top: 2rem;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: var(--radius);
    }
    .time-strip div {
      display: flex;
      align-items: center;
      min-width: 0;
      padding: .55rem .7rem;
      border-right: 1px solid var(--bg);
      font-size: .78rem;
      white-space: nowrap;
    }
    .time-strip div:last-child { border: 0; }
    .time-strip .formula, .time-strip .decode { background: var(--cyan-soft); }
    .time-strip .solver { background: #153344; }
    .time-strip .lean { background: #3a2b18; color: #ffd98d; }
    .time-note {
      margin-top: .55rem;
      color: var(--muted);
      font-size: .84rem;
    }
    main { padding: 0 0 5rem; }
    section {
      padding: 4.5rem 0;
      border-bottom: 1px solid var(--line);
    }
    .section-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(280px, 560px);
      gap: 2rem;
      align-items: end;
      margin-bottom: 2rem;
    }
    .section-head p { color: var(--muted); }
    .orientation-grid, .facts-grid, .claims-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 1rem;
    }
    .card {
      padding: 1.15rem;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--panel);
    }
    .card .value { margin-top: .5rem; color: var(--cyan); font-size: 1.45rem; font-weight: 750; }
    .card p { color: var(--muted); font-size: .9rem; }
    .note {
      margin-top: 1rem;
      padding: 1rem 1.1rem;
      border-left: 3px solid var(--amber);
      background: #261d11;
      color: #ead9b7;
    }
    .pipeline-layout {
      display: grid;
      grid-template-columns: minmax(260px, .78fr) minmax(0, 1.7fr);
      gap: 1.2rem;
      align-items: start;
    }
    .stage-list {
      display: grid;
      gap: .55rem;
    }
    .stage-button {
      display: grid;
      grid-template-columns: 2.4rem 1fr auto;
      gap: .75rem;
      width: 100%;
      padding: .9rem;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--panel);
      color: var(--text);
      text-align: left;
      cursor: pointer;
    }
    .stage-button:hover, .stage-button[aria-selected="true"] {
      border-color: var(--cyan);
      background: var(--cyan-soft);
    }
    .stage-number { color: var(--cyan); font: 700 .8rem/1.4 monospace; }
    .stage-button small { display: block; margin-top: .2rem; color: var(--muted); }
    .stage-arrow { align-self: center; color: var(--cyan); }
    .stage-detail {
      position: sticky;
      top: 1rem;
      min-height: 520px;
      padding: 1.35rem;
      border: 1px solid var(--cyan);
      border-radius: var(--radius);
      background: var(--panel);
    }
    .stage-detail .summary { color: #bed0dd; font-size: 1.05rem; }
    .stage-fields {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: .8rem;
      margin-top: 1.2rem;
    }
    .stage-field {
      padding: .9rem;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel-2);
    }
    .stage-field dt {
      color: var(--cyan);
      font: 700 .72rem/1.2 monospace;
      letter-spacing: .08em;
      text-transform: uppercase;
    }
    .stage-field dd { margin: .35rem 0 0; color: #d2dde6; }
    .stage-field.failure dt { color: var(--red); }
    .stage-field.authority dt { color: var(--green); }
    .flow {
      display: grid;
      grid-template-columns: repeat(9, minmax(110px, 1fr));
      gap: .5rem;
      overflow-x: auto;
      padding-bottom: .4rem;
    }
    .flow div {
      position: relative;
      min-height: 90px;
      padding: .8rem;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel);
    }
    .flow div::after {
      content: ">";
      position: absolute;
      right: -.48rem;
      top: 34%;
      z-index: 2;
      color: var(--cyan);
      font-weight: 800;
    }
    .flow div:last-child::after { content: ""; }
    .flow strong { display: block; font-size: .84rem; }
    .flow small { color: var(--muted); }
    .formula-widget {
      display: grid;
      grid-template-columns: 1.2fr .8fr;
      gap: 1rem;
    }
    .formula-box {
      min-height: 255px;
      padding: 1.25rem;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--panel);
    }
    .segmented {
      display: inline-flex;
      gap: .25rem;
      padding: .2rem;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--bg);
    }
    .segmented button, .term-button {
      border: 0;
      border-radius: 6px;
      background: transparent;
      color: var(--muted);
      cursor: pointer;
    }
    .segmented button { padding: .45rem .7rem; }
    .segmented button[aria-pressed="true"], .term-button[aria-pressed="true"] {
      background: var(--cyan-soft);
      color: var(--cyan);
    }
    .formula-render {
      display: flex;
      flex-wrap: wrap;
      gap: .4rem;
      align-items: center;
      min-height: 150px;
      padding-top: 1.2rem;
      font-family: "SFMono-Regular", Consolas, monospace;
    }
    .term-button {
      padding: .36rem .48rem;
      border: 1px solid var(--line);
    }
    .term-detail {
      padding: 1.2rem;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--panel-2);
    }
    .term-detail p { color: var(--muted); }
    .event-demo {
      display: grid;
      grid-template-columns: minmax(300px, .95fr) minmax(360px, 1.4fr);
      gap: 1rem;
      align-items: start;
    }
    .event-list { display: grid; gap: .35rem; }
    .event-button {
      display: grid;
      grid-template-columns: 4.8rem 1fr auto;
      gap: .65rem;
      width: 100%;
      padding: .6rem .7rem;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--text);
      text-align: left;
      cursor: pointer;
    }
    .event-button:hover, .event-button[aria-selected="true"] {
      border-color: var(--cyan);
      background: var(--cyan-soft);
    }
    .event-button .event-num { color: var(--cyan); font: 700 .8rem monospace; }
    .event-button small { color: var(--muted); }
    .lanes {
      min-height: 420px;
      padding: 1rem;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--panel);
    }
    .lane {
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: .6rem;
      margin-bottom: .75rem;
    }
    .lane-label { padding-top: .45rem; color: var(--muted); font: 700 .75rem monospace; }
    .lane-actions { display: flex; flex-wrap: wrap; gap: .35rem; }
    .action-chip {
      padding: .4rem .55rem;
      border: 1px solid #26708a;
      border-radius: 6px;
      background: var(--cyan-soft);
      color: #c8f2fa;
      font: 700 .76rem monospace;
    }
    .action-chip.synthetic { border-color: var(--amber); background: #2b2113; color: #f7d58f; }
    .demo-explain {
      margin-top: 1rem;
      padding-top: 1rem;
      border-top: 1px solid var(--line);
      color: #c9d6e0;
    }
    .controls {
      display: flex;
      flex-wrap: wrap;
      gap: .7rem;
      margin-bottom: .8rem;
    }
    input[type="search"], select {
      min-height: 2.35rem;
      padding: .4rem .65rem;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--text);
    }
    input[type="search"] { min-width: min(100%, 330px); }
    .table-wrap {
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: var(--radius);
    }
    table { width: 100%; border-collapse: collapse; background: var(--panel); }
    th, td {
      padding: .72rem .8rem;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }
    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: #102037;
      color: #c7d8e5;
      font-size: .78rem;
      letter-spacing: .04em;
      text-transform: uppercase;
    }
    th button {
      width: 100%;
      padding: 0;
      border: 0;
      background: transparent;
      color: inherit;
      text-align: left;
      cursor: pointer;
    }
    tbody tr:hover { background: #11263e; }
    td { color: #d1dce5; font-size: .9rem; }
    .empty { padding: 1rem; color: var(--muted); }
    details {
      margin-top: 1rem;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--panel);
    }
    summary { padding: .85rem 1rem; color: var(--cyan); cursor: pointer; }
    details > div { padding: 0 1rem 1rem; color: #c9d5df; }
    .failure-matrix td:nth-child(3) { font-weight: 700; }
    .status-green { color: var(--green); }
    .status-amber { color: var(--amber); }
    .status-red { color: var(--red); }
    .claim-step {
      position: relative;
      padding: 1rem;
      border-top: 3px solid var(--line);
      background: var(--panel);
    }
    .claim-step.established { border-color: var(--green); }
    .claim-step.partial { border-color: var(--amber); }
    .claim-step.absent { border-color: var(--red); }
    .claim-step .state { margin-top: .55rem; font: 700 .74rem monospace; text-transform: uppercase; }
    .claim-step.established .state { color: var(--green); }
    .claim-step.partial .state { color: var(--amber); }
    .claim-step.absent .state { color: var(--red); }
    .two-col {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 1rem;
    }
    .meta {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: .8rem;
      margin-top: 1rem;
    }
    .meta dl { margin: 0; padding: .8rem; border: 1px solid var(--line); background: var(--panel); }
    .meta dt { color: var(--muted); font-size: .75rem; text-transform: uppercase; }
    .meta dd { margin: .25rem 0 0; overflow-wrap: anywhere; font: .78rem monospace; }
    .hash { overflow-wrap: anywhere; color: var(--muted); font: .75rem monospace; }
    footer { padding: 2rem 0; color: var(--muted); font-size: .82rem; }
    .print-only { display: none; }
    @media (max-width: 1000px) {
      .orientation-grid, .facts-grid, .claims-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .pipeline-layout, .formula-widget, .event-demo { grid-template-columns: 1fr; }
      .stage-detail { position: static; min-height: 0; }
      .section-head { grid-template-columns: 1fr; }
      .time-strip { grid-template-columns: 1.1fr 4.2fr .9fr 12fr; }
    }
    @media (max-width: 650px) {
      nav { align-items: flex-start; }
      nav .links { display: none; }
      .orientation-grid, .facts-grid, .claims-grid, .two-col, .meta,
      .stage-fields { grid-template-columns: 1fr; }
      .time-strip { display: block; }
      .time-strip div { border-right: 0; border-bottom: 1px solid var(--bg); }
      section { padding: 3rem 0; }
      .lane { grid-template-columns: 1fr; }
    }
    @media print {
      :root { color-scheme: light; }
      body { background: white; color: #111; font-size: 10pt; }
      header, .card, .stage-button, .stage-detail, .formula-box, .term-detail,
      .lanes, table, details, .claim-step, .meta dl, pre {
        background: white !important;
        color: #111 !important;
      }
      a { color: #075d73; }
      nav, .controls, .segmented { display: none !important; }
      section { padding: 1.2rem 0; break-inside: avoid; }
      .wrap { width: 100%; }
      .pipeline-layout, .formula-widget, .event-demo, .two-col {
        display: block;
      }
      .stage-list { display: none; }
      .stage-detail { position: static; min-height: 0; }
      .print-only { display: block; }
      .table-wrap { overflow: visible; }
      th { position: static; }
      .hash { color: #333; }
    }
  </style>
</head>
<body>
  <a class="skip" href="#main">Skip to report</a>
  <header>
    <div class="wrap">
      <nav aria-label="Report sections">
        <span class="mono">CCF / Raft / trace validation</span>
        <div class="links">
          <a href="#pipeline">Pipeline</a>
          <a href="#reductions">Reductions</a>
          <a href="#formula">Formula</a>
          <a href="#lean-check">Lean check</a>
          <a href="#run">Run it</a>
          <a href="#sources">Source map</a>
        </div>
      </nav>
      <div class="eyebrow">Current prototype report</div>
      <h1>One real trace, reduced once, solved cheaply, checked canonically</h1>
      <p class="lede">Follow one real 53-event CCF Raft scenario through preprocessing, deterministic reduction, cheap bounded SMT solving, witness decoding, and canonical Lean checking, showing exactly what each stage contributes and what remains assumed.</p>
      <div class="result-row">
        <span class="badge" id="resultBadge">VALID_SEGMENT_CHEAP_FOOTPRINT</span>
        <span class="answer">The 53-event segment has a bounded SAT explanation that replays through the canonical Lean transition system.</span>
      </div>
      <div class="time-strip" aria-label="Approximate measured stage durations">
        <div class="formula">Formula<br>1.1 s</div>
        <div class="solver">cvc5<br>4.2 s</div>
        <div class="decode">Decode<br>0.9 s</div>
        <div class="lean">Generated Lean compile and check<br>about 70 s</div>
      </div>
      <p class="time-note">Useful recurring cost before generated-checker compilation is about 6.2 seconds. The long bar is compilation of witness-specific source, not 43-step replay.</p>
    </div>
  </header>

  <main id="main">
    <section id="orientation">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Orientation</div>
            <h2>Read the result at the right level</h2>
          </div>
          <p>The pipeline finds one bounded explanation, then asks the canonical Lean model to replay it. It does not prove that the segment starts in a reachable state.</p>
        </div>
        <div class="orientation-grid">
          <article class="card"><h3>Implementation input</h3><div class="value">53 events</div><p>The real <code>tests/raft_scenarios/replicate</code> fixture produces the preprocessed NDJSON trace.</p></article>
          <article class="card"><h3>Deterministic map</h3><div class="value">22 to 43</div><p>Twenty-two reductions consume every event once and propose 43 canonical action templates.</p></article>
          <article class="card"><h3>Bounded search</h3><div class="value">44 states</div><p>cvc5 selects S0 through S43, actions, queue contents, log cells, and one transaction representative.</p></article>
          <article class="card"><h3>Canonical gate</h3><div class="value">558 fields</div><p>Lean checks every projected field, 43 transitions, 43 edges, and state checks at S0 and after every action.</p></article>
        </div>
        <div class="note"><strong>Two jobs, two standards.</strong> Preprocessing, reduction, and decode transform data. SMT tests satisfiability of the current bounded lowering. Canonical Lean replay validates the decoded segment against <code>CCFRaft.Model</code>.</div>
      </div>
    </section>

    <section id="end-to-end">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">End-to-end pipeline</div><h2>Narrow each claim as data moves</h2></div>
          <p>Each arrow changes representation. Only the cvc5 and Lean stages make semantic claims, and those claims have different authority.</p>
        </div>
        <div class="flow" aria-label="Pipeline overview">
          <div><strong>Scenario</strong><small>Real C++ execution</small></div>
          <div><strong>Preprocess</strong><small>53 NDJSON events</small></div>
          <div><strong>Reduce</strong><small>43 action templates</small></div>
          <div><strong>Footprint</strong><small>2 SMT nodes</small></div>
          <div><strong>Formula</strong><small>Existential bounded state</small></div>
          <div><strong>cvc5</strong><small>SAT model</small></div>
          <div><strong>Decode</strong><small>44-state witness</small></div>
          <div><strong>Lean</strong><small>Canonical replay</small></div>
          <div><strong>Classify</strong><small>Valid segment</small></div>
        </div>
      </div>
    </section>

    <section id="pipeline">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Clickable stage explorer</div><h2>Inspect what each stage adds</h2></div>
          <p>Choose a stage. The detail pane states its input, operation, output, authority, timing, and failure meaning.</p>
        </div>
        <div class="pipeline-layout">
          <div class="stage-list" id="stageList" role="tablist" aria-label="Pipeline stages"></div>
          <article class="stage-detail" id="stageDetail" role="tabpanel" tabindex="0"></article>
        </div>
        <div class="print-only" id="printStages"></div>
      </div>
    </section>

    <section id="reductions">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Event-to-action reductions</div><h2>One C++ event need not equal one Lean action</h2></div>
          <p>A helper event can add no action. One aggregate packet can add several actions. The certificate records both cases.</p>
        </div>
        <div class="event-demo">
          <div>
            <h3>C++ events 9 through 20</h3>
            <p class="time-note">Use the event list to highlight its Lean action or action span.</p>
            <div class="event-list" id="eventList"></div>
          </div>
          <div class="lanes" id="eventDetail" aria-live="polite"></div>
        </div>
        <details open>
          <summary>Why span start and aggregate fields differ</summary>
          <div>
            <p>Event 9 observes one C++ batch for absolute indices 1 through 3. Lean sends one entry per action, so the batch expands to append ends 1, 2, and 3. Event 11 similarly expands one aggregate follower receive into three receives. Event 20 expands the aggregate response into response receives for 1, 2, and 3.</p>
            <p>The C++ event's state fields describe the state before the aggregate operation, so they constrain the span start. Packet range, destination, and aggregate result fields describe the batch as a whole, so they constrain all actions or the span end. Helper records such as <code>execute_append_entries_sync</code>, <code>commit</code>, and <code>send_append_entries_response</code> remain assertions inside the owning receive. They do not invent extra model actions.</p>
          </div>
        </details>
        <h3 style="margin-top:2rem">All certificate reductions</h3>
        <div class="controls">
          <label><span class="skip">Filter reductions</span><input id="reductionFilter" type="search" placeholder="Filter name, event, action, exception"></label>
          <label><span class="skip">Filter reduction type</span><select id="reductionType"><option value="all">All mappings</option><option value="expands">Expands actions</option><option value="contracts">Helper or assertion heavy</option><option value="equal">Equal event and action count</option></select></label>
        </div>
        <div class="table-wrap">
          <table id="reductionTable">
            <thead><tr>
              <th><button data-key="reduction">Reduction</button></th>
              <th><button data-key="name">Name</button></th>
              <th><button data-key="eventLabel">Events</button></th>
              <th><button data-key="actionLabel">Actions</button></th>
              <th><button data-key="delta">Delta</button></th>
              <th><button data-key="summary">Operation</button></th>
              <th><button data-key="exceptions">Exceptions</button></th>
            </tr></thead>
            <tbody><tr><td colspan="7">Loading reductions...</td></tr></tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="footprint">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Cheap bounded state</div><h2>Keep the sequence, shrink the world</h2></div>
          <p>The cheap experiment retains all 44 states and 43 actions. It removes unobserved node and lane dimensions from SMT.</p>
        </div>
        <div class="facts-grid">
          <article class="card"><h3>Nodes</h3><div class="value">0 and 1</div><p>Nodes 2 through 14 are absent in SMT. The canonical checker later supplies fixed inert states.</p></article>
          <article class="card"><h3>Logs</h3><div class="value">7 slots</div><p>Both SMT nodes have physical log slots 1 through 7.</p></article>
          <article class="card"><h3>Queues</h3><div class="value">2 x 4</div><p>Only lanes 0 to 1 and 1 to 0 exist, each with capacity four.</p></article>
          <article class="card"><h3>Values</h3><div class="value">2 configs + 1 tx</div><p>Only {0}, {0,1}, and one unknown <code>Fin 64</code> transaction representative occur.</p></article>
        </div>
        <div class="note">This footprint is hardcoded for the experiment. A bounded UNSAT result can mean that the footprint excluded a valid completion, so the pipeline reports <code>INCONCLUSIVE_ENCODING</code>.</div>
      </div>
    </section>

    <section id="formula">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Existential formula</div><h2>Find one complete bounded explanation</h2></div>
          <p>The formula chooses a start state and every hidden value. Observations and bounded transition equations constrain those choices.</p>
        </div>
        <div class="formula-widget">
          <div class="formula-box">
            <div class="segmented" aria-label="Formula display mode">
              <button id="plainMode" type="button" aria-pressed="true">Plain English</button>
              <button id="formalMode" type="button" aria-pressed="false">Formal shape</button>
            </div>
            <div class="formula-render" id="formulaRender"></div>
          </div>
          <aside class="term-detail" id="termDetail" aria-live="polite"></aside>
        </div>
        <details>
          <summary>Current lowering versus long-term proved lowering</summary>
          <div>
            <p>The current generator emits a hand-maintained bounded encoding. Lean does not prove that this formula is equivalent to <code>CCFRaft.Model</code>. SAT therefore supplies a candidate that Lean must check. UNSAT cannot reject the implementation trace.</p>
            <p>The long-term design needs a proved lowering or a proved automatic footprint extraction and lowering path. That future proof is separate from this prototype result.</p>
          </div>
        </details>
      </div>
    </section>

    <section id="witness">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">SAT witness</div><h2>Decode solver values before trusting them</h2></div>
          <p>cvc5 returns SAT. The decoder materializes every state, action, log, queue, and observed field in a JSON witness.</p>
        </div>
        <div class="two-col">
          <article class="card">
            <h3>What cvc5 selected</h3>
            <p>The unknown transaction representative is <code>1 : Fin 64</code>. S0 has node 0 as term-2 leader with log length 2 and commit 0. Node 1 is inert in the cheap world. The model fills all state and queue values through S43.</p>
          </article>
          <article class="card">
            <h3>Where the witness ends</h3>
            <p>At S43, nodes 0 and 1 both have log length 7 and commit index 7. Both cheap queues are empty. The canonical completion later checks all 15 destination queues as drained.</p>
          </article>
        </div>
        <div class="note">SAT means that the generated bounded formula has a model. The SAT result alone does not mean that <code>system.applyAction</code> accepts the decoded actions.</div>
      </div>
    </section>

    <section id="lean-check">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Canonical Lean check</div><h2>Replay through the source of semantic authority</h2></div>
          <p>The checker expands two SMT nodes to <code>Node (Fin 15)</code>, fixes nodes 2 through 14 as inert, and runs the canonical transition system.</p>
        </div>
        <div class="facts-grid">
          <article class="card"><h3>Entry</h3><div class="value">S0 checked</div><p><code>stateChecks</code> passes, but S0 remains an arbitrary existential segment entry.</p></article>
          <article class="card"><h3>Transitions</h3><div class="value">43 + 43</div><p>All 43 <code>system.applyAction</code> calls succeed. All 43 <code>edgeChecks</code> pass.</p></article>
          <article class="card"><h3>Observations</h3><div class="value">53 / 558</div><p>All events pass across 47 point checkpoints and six spans. Zero projected fields remain unchecked.</p></article>
          <article class="card"><h3>Final state</h3><div class="value">7 / 7</div><p>Both active logs and commits end at 7. All 15 destination queues are empty.</p></article>
        </div>
        <div class="note"><strong>Current checker shape.</strong> The prototype writes 4,298 lines and 382,143 bytes of witness-specific Lean source. About 70 seconds is compilation and checking of that generated source, not replay-only time. Profiling points to the six generated span functions, especially events 9 and 11. The intended generic precompiled checker reads witness data without recompiling these declarations.</div>
        <details>
          <summary>What the Lean check does not prove</summary>
          <div>
            <p>The checker does not prove <code>Reachable S0</code>. It also does not construct the proof-only histories required by <code>SystemInductiveInvariant S0</code>. Those missing premises prevent the valid segment from becoming a reachable-safety theorem.</p>
          </div>
        </details>
      </div>
    </section>

    <section id="failure-paths">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Failure paths</div><h2>Classify failure at the stage that owns it</h2></div>
          <p>A negative bounded result is not an implementation-trace rejection. A rejected SAT witness points to the encoding.</p>
        </div>
        <div class="table-wrap">
          <table class="failure-matrix">
            <thead><tr><th>Case</th><th>Meaning</th><th>Classification</th><th>Next evidence</th></tr></thead>
            <tbody>
              <tr><td>Unmapped event</td><td>The deterministic grammar cannot consume the current trace exactly once.</td><td class="status-red">Reducer failure</td><td>Fix or extend the correspondence grammar. Do not invoke SMT.</td></tr>
              <tr><td>SAT</td><td>The bounded formula has at least one model.</td><td class="status-amber">SAT pending canonical check</td><td>Decode and replay the witness.</td></tr>
              <tr><td>Bounded UNSAT</td><td>No model exists inside this lowering and hardcoded footprint.</td><td class="status-amber">INCONCLUSIVE_ENCODING</td><td>Do not call the trace invalid. Prove completeness or enlarge the encoding.</td></tr>
              <tr><td>unknown or timeout</td><td>The solver did not establish SAT or UNSAT.</td><td class="status-amber">INCONCLUSIVE_ENCODING</td><td>Inspect solver limits and formula shape.</td></tr>
              <tr><td>SAT witness rejected</td><td>Canonical <code>applyAction</code>, checks, or observations reject decoded values.</td><td class="status-red">Encoding bug</td><td>Fix the lowering, decoder, or correspondence data.</td></tr>
              <tr><td>Valid segment</td><td>SAT witness passes every canonical segment check.</td><td class="status-green">VALID_SEGMENT_CHEAP_FOOTPRINT</td><td>Keep reachability and invariant claims separate.</td></tr>
            </tbody>
          </table>
        </div>
        <details>
          <summary>Concrete negative control: commit violation</summary>
          <div>
            <p>Event 53 observes node 0 at commit index 7 before the final response receive. The mutation changes that checkpoint to commit index 6 at S42 while retaining action 40 <code>advanceCommitIndex</code> and actions 41 and 42 for the final append and receive. cvc5 returns UNSAT. The test proves that the bounded formula notices this in-domain contradiction. It does not prove that every possible commit violation is impossible in the full model.</p>
          </div>
        </details>
      </div>
    </section>

    <section id="timing">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Timing and size</div><h2>The cheap footprint removes solver cost, not generated-source cost</h2></div>
          <p>Filter and sort the live benchmark comparison. Time values use milliseconds for sorting even when the table shows seconds.</p>
        </div>
        <div class="controls">
          <label><span class="skip">Filter benchmark rows</span><input id="timingFilter" type="search" placeholder="Filter metric or ratio"></label>
          <label><span class="skip">Filter benchmark kind</span><select id="timingKind"><option value="all">All metrics</option><option value="time">Time</option><option value="size">Size</option></select></label>
        </div>
        <div class="table-wrap">
          <table id="timingTable">
            <thead><tr>
              <th><button data-key="metric">Metric</button></th>
              <th><button data-key="cheap">Cheap</button></th>
              <th><button data-key="full">Naive full</button></th>
              <th><button data-key="ratio">Comparison</button></th>
            </tr></thead>
            <tbody><tr><td colspan="4">Loading benchmark...</td></tr></tbody>
          </table>
        </div>
        <div class="meta">
          <dl><dt>Solver-only runs</dt><dd>10</dd></dl>
          <dl><dt>Distribution</dt><dd>min 3510 / median 3857 / p95 4661 / max 4661 ms</dd></dl>
          <dl><dt>Recurring before Lean compile</dt><dd>about 6.2 s</dd></dl>
        </div>
      </div>
    </section>

    <section id="claims">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Claims and non-claims</div><h2>Stop at valid segment</h2></div>
          <p>The claim ladder shows which evidence exists now and what remains outside this prototype.</p>
        </div>
        <div class="claims-grid">
          <article class="claim-step established"><h3>Preprocessed trace</h3><p>Exactly 53 real scenario events with command context.</p><div class="state">Established</div></article>
          <article class="claim-step established"><h3>Reducer coverage</h3><p>Every event is consumed once across 22 reductions and 53 observations.</p><div class="state">Established</div></article>
          <article class="claim-step partial"><h3>Bounded SMT</h3><p>A SAT explanation exists in the hardcoded two-node footprint.</p><div class="state">Established only for this encoding</div></article>
          <article class="claim-step established"><h3>Canonical segment</h3><p>All 43 decoded actions and 558 projected fields pass Lean checks.</p><div class="state">Established</div></article>
          <article class="claim-step absent"><h3>Reachable entry</h3><p>No proof connects the canonical initial state to S0.</p><div class="state">Not established</div></article>
          <article class="claim-step absent"><h3>Full invariant</h3><p>No <code>SystemInductiveInvariant S0</code> witness is constructed.</p><div class="state">Not established</div></article>
          <article class="claim-step absent"><h3>Proved lowering</h3><p>No theorem equates the generated SMT equations with <code>Model.lean</code>.</p><div class="state">Not established</div></article>
          <article class="claim-step absent"><h3>C++ and Lean equivalence</h3><p>The deterministic correspondence remains proposed and trace-specific.</p><div class="state">Not established</div></article>
        </div>
      </div>
    </section>

    <section id="run">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Run it</div><h2>Regenerate evidence in pipeline order</h2></div>
          <p>The full command reruns the real scenario and reducer. The cheap command reruns SMT, negative controls, source generation, Lean compilation, and canonical checking.</p>
        </div>
        <div class="two-col">
          <div>
            <h3>Full pipeline</h3>
            <pre><code>cd lean
./check_ccfraft_full_trace_prototype.sh
./check_ccfraft_cheap_full_state_prototype.sh</code></pre>
            <p class="time-note">Expect about 6 seconds through witness decode, then about 70 seconds for witness-specific Lean compilation and checking. Scenario execution and reduction add unisolated setup time.</p>
          </div>
          <div>
            <h3>Cached generated checker</h3>
            <pre><code>cd lean
lake env lean --run .lake/build/cheap-full-state-smt/CanonicalCheapFullStateWitness.lean</code></pre>
            <p class="time-note">This command still invokes Lean on generated source. It may use cached imports, but it is not the intended generic precompiled checker and does not isolate replay time.</p>
          </div>
        </div>
        <details>
          <summary>Generate this report</summary>
          <div><pre><code>python3 lean/CCFRaft/generate_trace_validation_pipeline_report.py</code></pre></div>
        </details>
      </div>
    </section>

    <section id="sources">
      <div class="wrap">
        <div class="section-head">
          <div><div class="eyebrow">Source map</div><h2>Jump to current files or committed canonical source</h2></div>
          <p>VS Code links target this WSL worktree. GitHub links pin canonical files to the detected commit.</p>
        </div>
        <p><a id="workspaceLink" href="__WORKSPACE_URL__">Open the workspace in VS Code</a></p>
        <div class="table-wrap" style="margin-top:1rem">
          <table id="sourceTable">
            <thead><tr><th>Source</th><th>Role</th><th>Authority</th><th>Links</th></tr></thead>
            <tbody><tr><td colspan="4">Loading sources...</td></tr></tbody>
          </table>
        </div>
        <details>
          <summary>Artifact hashes and generation metadata</summary>
          <div>
            <div class="meta">
              <dl><dt>Generated at</dt><dd id="generatedAt"></dd></dl>
              <dl><dt>Git HEAD</dt><dd id="gitHead"></dd></dl>
              <dl><dt>Prototype status</dt><dd id="gitStatus"></dd></dl>
            </div>
            <div class="table-wrap" style="margin-top:1rem">
              <table id="artifactTable">
                <thead><tr><th>Artifact</th><th>Bytes</th><th>SHA-256</th><th>Open</th></tr></thead>
                <tbody><tr><td colspan="4">Loading artifacts...</td></tr></tbody>
              </table>
            </div>
            <pre id="statusLines" style="margin-top:1rem"></pre>
          </div>
        </details>
      </div>
    </section>
  </main>

  <footer>
    <div class="wrap">Generated from current artifacts. Dependency-free HTML, vanilla JavaScript, and no network requests.</div>
  </footer>

  <script id="report-data" type="application/json">__REPORT_DATA__</script>
  <script>
    "use strict";
    const data = JSON.parse(document.getElementById("report-data").textContent);
    const escapeText = (value) => String(value);

    function renderStages() {
      const list = document.getElementById("stageList");
      const detail = document.getElementById("stageDetail");
      const print = document.getElementById("printStages");
      function choose(stage) {
        list.querySelectorAll("button").forEach((button) => {
          button.setAttribute("aria-selected", String(button.dataset.stage === stage.id));
          button.tabIndex = button.dataset.stage === stage.id ? 0 : -1;
        });
        detail.setAttribute("aria-labelledby", "stage-" + stage.id);
        detail.innerHTML = "";
        const eyebrow = document.createElement("div");
        eyebrow.className = "eyebrow";
        eyebrow.textContent = stage.number + " / " + stage.title;
        const title = document.createElement("h3");
        title.id = "stage-detail-title";
        title.textContent = stage.title;
        const summary = document.createElement("p");
        summary.className = "summary";
        summary.textContent = stage.summary;
        const fields = document.createElement("dl");
        fields.className = "stage-fields";
        [
          ["Input", stage.input, ""],
          ["Operation", stage.operation, ""],
          ["Output", stage.output, ""],
          ["Authority", stage.authority, "authority"],
          ["Timing", stage.timing, ""],
          ["Failure", stage.failure, "failure"]
        ].forEach(([label, value, className]) => {
          const block = document.createElement("div");
          block.className = "stage-field " + className;
          const term = document.createElement("dt");
          term.textContent = label;
          const description = document.createElement("dd");
          description.textContent = value;
          block.append(term, description);
          fields.append(block);
        });
        detail.append(eyebrow, title, summary, fields);
      }
      data.stages.forEach((stage, index) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "stage-button";
        button.id = "stage-" + stage.id;
        button.dataset.stage = stage.id;
        button.setAttribute("role", "tab");
        button.setAttribute("aria-controls", "stageDetail");
        button.setAttribute("aria-selected", String(index === 0));
        button.tabIndex = index === 0 ? 0 : -1;
        const number = document.createElement("span");
        number.className = "stage-number";
        number.textContent = stage.number;
        const copy = document.createElement("span");
        const strong = document.createElement("strong");
        strong.textContent = stage.title;
        const small = document.createElement("small");
        small.textContent = stage.summary;
        copy.append(strong, small);
        const arrow = document.createElement("span");
        arrow.className = "stage-arrow";
        arrow.setAttribute("aria-hidden", "true");
        arrow.textContent = ">";
        button.append(number, copy, arrow);
        button.addEventListener("click", () => choose(stage));
        button.addEventListener("keydown", (event) => {
          if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
          event.preventDefault();
          const buttons = [...list.querySelectorAll("button")];
          const current = buttons.indexOf(button);
          let next = current;
          if (event.key === "ArrowDown") next = (current + 1) % buttons.length;
          if (event.key === "ArrowUp") next = (current - 1 + buttons.length) % buttons.length;
          if (event.key === "Home") next = 0;
          if (event.key === "End") next = buttons.length - 1;
          buttons[next].focus();
          buttons[next].click();
        });
        list.append(button);
        const printed = document.createElement("article");
        printed.innerHTML = "<h3>" + escapeText(stage.number + " " + stage.title) + "</h3><p>" + escapeText(stage.summary) + "</p><p><strong>Authority:</strong> " + escapeText(stage.authority) + "</p>";
        print.append(printed);
      });
      choose(data.stages[0]);
    }

    const eventDescriptions = {
      9: ["send_append_entries batch 1..3", "span", "C++ sends one packet. Lean actions 8, 9, and 10 append ends 1, 2, and 3."],
      10: ["send_append_entries entry 4", "point", "Lean action 11 sends append end 4."],
      11: ["recv_append_entries batch 1..3", "span", "C++ receives one aggregate packet. Lean actions 12, 13, and 14 receive entries 1, 2, and 3."],
      12: ["add_configuration helper", "assertion", "An assertion after Lean action 12. It adds no action."],
      13: ["execute_append_entries_sync", "assertion", "An assertion after Lean action 12. It adds no action."],
      14: ["commit callback", "assertion", "A during-action assertion around Lean action 13. Atomicity omissions are recorded."],
      15: ["add_configuration helper", "assertion", "An assertion after Lean action 14. It adds no action."],
      16: ["send response helper", "assertion", "An assertion after Lean action 14. It adds no action."],
      17: ["recv_append_entries entry 4", "point", "Lean action 15 receives the packet for entry 4."],
      18: ["execute_append_entries_sync", "assertion", "A pre-action assertion owned by Lean action 15."],
      19: ["send response helper", "assertion", "An assertion after Lean action 15."],
      20: ["recv responses 1..3", "span", "C++ exposes the aggregate response at 3. Lean actions 16, 17, and 18 receive responses 1, 2, and 3."]
    };
    const actionLayouts = {
      9: [["C++ lane", ["event 9: batch 1..3"]], ["Lean 0 -> 1", ["A8 append end 1", "A9 append end 2", "A10 append end 3"]]],
      10: [["C++ lane", ["event 10: entry 4"]], ["Lean 0 -> 1", ["A11 append end 4"]]],
      11: [["C++ lane", ["event 11: receive 1..3"]], ["Lean at node 1", ["A12 receive 1", "A13 receive 2", "A14 receive 3"]]],
      12: [["C++ helper", ["event 12 assertion"]], ["Lean owner", ["after A12"]]],
      13: [["C++ helper", ["event 13 assertion"]], ["Lean owner", ["after A12"]]],
      14: [["C++ helper", ["event 14 commit callback"]], ["Lean owner", ["during A13"]]],
      15: [["C++ helper", ["event 15 assertion"]], ["Lean owner", ["after A14"]]],
      16: [["C++ helper", ["event 16 response"]], ["Lean owner", ["after A14"]]],
      17: [["C++ lane", ["event 17: entry 4"]], ["Lean at node 1", ["A15 receive 4"]]],
      18: [["C++ helper", ["event 18 assertion"]], ["Lean owner", ["before A15"]]],
      19: [["C++ helper", ["event 19 response"]], ["Lean owner", ["after A15"]]],
      20: [["C++ lane", ["event 20: response end 3"]], ["Lean 1 -> 0", ["A16 receive response 1", "A17 receive response 2", "A18 receive response 3"]]]
    };

    function renderEvents() {
      const list = document.getElementById("eventList");
      const detail = document.getElementById("eventDetail");
      function choose(number) {
        const [title, kind, explanation] = eventDescriptions[number];
        list.querySelectorAll("button").forEach((button) => {
          button.setAttribute("aria-selected", String(Number(button.dataset.event) === number));
        });
        detail.innerHTML = "";
        const heading = document.createElement("h3");
        heading.textContent = "Event " + number + ": " + title;
        const kindLine = document.createElement("p");
        kindLine.className = "time-note";
        kindLine.textContent = kind === "span" ? "Whole-action span" : kind === "assertion" ? "Helper or assertion only" : "Point checkpoint";
        detail.append(heading, kindLine);
        actionLayouts[number].forEach(([label, chips]) => {
          const lane = document.createElement("div");
          lane.className = "lane";
          const laneLabel = document.createElement("div");
          laneLabel.className = "lane-label";
          laneLabel.textContent = label;
          const actionRow = document.createElement("div");
          actionRow.className = "lane-actions";
          chips.forEach((chip) => {
            const element = document.createElement("span");
            element.className = "action-chip" + (kind === "assertion" ? " synthetic" : "");
            element.textContent = chip;
            actionRow.append(element);
          });
          lane.append(laneLabel, actionRow);
          detail.append(lane);
        });
        const explain = document.createElement("p");
        explain.className = "demo-explain";
        explain.textContent = explanation;
        detail.append(explain);
      }
      Object.keys(eventDescriptions).forEach((numberText) => {
        const number = Number(numberText);
        const [title, kind] = eventDescriptions[number];
        const button = document.createElement("button");
        button.type = "button";
        button.className = "event-button";
        button.dataset.event = String(number);
        button.setAttribute("aria-selected", String(number === 9));
        const label = document.createElement("span");
        label.className = "event-num";
        label.textContent = "Event " + number;
        const titleNode = document.createElement("span");
        titleNode.textContent = title;
        const kindNode = document.createElement("small");
        kindNode.textContent = kind;
        button.append(label, titleNode, kindNode);
        button.addEventListener("click", () => choose(number));
        list.append(button);
      });
      choose(9);
    }

    const formulaTerms = {
      S0: ["S0", "An arbitrary existential entry state. The formula constrains its two nodes, logs, queues, submitted transaction bit, and observed pre-state fields. It does not assert Reachable S0."],
      Actions: ["Actions", "A0 through A42 are action variables with certificate skeletons. Unknown parameters include the selected Fin 64 transaction representative."],
      Step: ["Step", "For each i from 0 through 42, the generated bounded equations relate Si, Ai, and S(i+1). This lowering is hand-maintained and not proved equivalent to Model.lean."],
      Observations: ["Observations", "All 53 event observations constrain state or action checkpoints. Six aggregate events constrain whole action spans."]
    };
    function renderFormula() {
      const render = document.getElementById("formulaRender");
      const detail = document.getElementById("termDetail");
      const plain = document.getElementById("plainMode");
      const formal = document.getElementById("formalMode");
      let mode = "plain";
      let selected = "S0";
      function chooseTerm(name) {
        selected = name;
        render.querySelectorAll(".term-button").forEach((button) => {
          button.setAttribute("aria-pressed", String(button.dataset.term === name));
        });
        const [title, copy] = formulaTerms[name];
        detail.innerHTML = "";
        const heading = document.createElement("h3");
        heading.textContent = title;
        const paragraph = document.createElement("p");
        paragraph.textContent = copy;
        detail.append(heading, paragraph);
      }
      function draw() {
        plain.setAttribute("aria-pressed", String(mode === "plain"));
        formal.setAttribute("aria-pressed", String(mode === "formal"));
        render.innerHTML = "";
        const pieces = mode === "plain"
          ? [["There exists", ""], ["S0", "S0"], ["and", ""], ["Actions", "Actions"], ["such that every", ""], ["Step", "Step"], ["holds and all", ""], ["Observations", "Observations"], ["match.", ""]]
          : [["exists S0...S43, A0...A42, params.", ""], ["S0", "S0"], ["Checks(S0) and", ""], ["Actions", "Actions"], ["Skeleton(A) and", ""], ["Step", "Step"], ["(Si,Ai,S(i+1)) and", ""], ["Observations", "Observations"], ["(S,A)", ""]];
        pieces.forEach(([text, term]) => {
          if (term) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "term-button";
            button.dataset.term = term;
            button.setAttribute("aria-pressed", String(term === selected));
            button.textContent = text;
            button.addEventListener("click", () => chooseTerm(term));
            render.append(button);
          } else {
            const span = document.createElement("span");
            span.textContent = text;
            render.append(span);
          }
        });
        chooseTerm(selected);
      }
      plain.addEventListener("click", () => { mode = "plain"; draw(); });
      formal.addEventListener("click", () => { mode = "formal"; draw(); });
      draw();
    }

    function installTable({tableId, rows, columns, filterId, selectId, selectPredicate}) {
      const table = document.getElementById(tableId);
      const body = table.querySelector("tbody");
      const filter = document.getElementById(filterId);
      const select = document.getElementById(selectId);
      let sortKey = columns[0][0];
      let direction = 1;
      function textValue(row) {
        return columns.map(([key]) => Array.isArray(row[key]) ? row[key].join(" ") : String(row[key])).join(" ").toLowerCase();
      }
      function draw() {
        const query = filter.value.trim().toLowerCase();
        const selected = select.value;
        const visible = rows.filter((row) => (!query || textValue(row).includes(query)) && selectPredicate(row, selected));
        visible.sort((left, right) => {
          const a = left[sortKey];
          const b = right[sortKey];
          if (typeof a === "number" && typeof b === "number") return direction * (a - b);
          return direction * String(a).localeCompare(String(b), undefined, {numeric: true});
        });
        body.innerHTML = "";
        visible.forEach((row) => {
          const tr = document.createElement("tr");
          columns.forEach(([key, displayKey]) => {
            const td = document.createElement("td");
            const value = displayKey ? row[displayKey] : row[key];
            td.textContent = Array.isArray(value) ? value.join(", ") || "none" : String(value);
            tr.append(td);
          });
          body.append(tr);
        });
        if (!visible.length) {
          const tr = document.createElement("tr");
          const td = document.createElement("td");
          td.colSpan = columns.length;
          td.className = "empty";
          td.textContent = "No rows match the current filters.";
          tr.append(td);
          body.append(tr);
        }
        table.querySelectorAll("th button").forEach((button) => {
          button.textContent = button.textContent.replace(/ (?:asc|desc)$/, "");
          if (button.dataset.key === sortKey) button.textContent += direction === 1 ? " asc" : " desc";
        });
      }
      table.querySelectorAll("th button").forEach((button) => {
        button.addEventListener("click", () => {
          if (sortKey === button.dataset.key) direction *= -1;
          else { sortKey = button.dataset.key; direction = 1; }
          draw();
        });
      });
      filter.addEventListener("input", draw);
      select.addEventListener("change", draw);
      draw();
    }

    function renderSources() {
      const sourceBody = document.querySelector("#sourceTable tbody");
      data.sources.forEach((source) => {
        const tr = document.createElement("tr");
        [source.name + "\n" + source.path, source.role, source.authority].forEach((value) => {
          const td = document.createElement("td");
          td.textContent = value;
          tr.append(td);
        });
        const links = document.createElement("td");
        const local = document.createElement("a");
        local.href = source.vscode;
        local.textContent = "VS Code line " + source.currentLine;
        links.append(local);
        if (source.github) {
          links.append(document.createTextNode(" | "));
          const github = document.createElement("a");
          github.href = source.github;
          github.textContent = "GitHub at HEAD";
          links.append(github);
        }
        tr.append(links);
        sourceBody.append(tr);
      });
      const artifactBody = document.querySelector("#artifactTable tbody");
      data.artifactHashes.forEach((artifact) => {
        const tr = document.createElement("tr");
        const name = document.createElement("td");
        name.textContent = artifact.name + "\n" + artifact.path;
        const bytes = document.createElement("td");
        bytes.textContent = artifact.bytes.toLocaleString();
        const hash = document.createElement("td");
        hash.className = "hash";
        hash.textContent = artifact.sha256;
        const open = document.createElement("td");
        const link = document.createElement("a");
        link.href = artifact.vscode;
        link.textContent = "Open";
        open.append(link);
        tr.append(name, bytes, hash, open);
        artifactBody.append(tr);
      });
      document.getElementById("generatedAt").textContent = data.generatedAt;
      document.getElementById("gitHead").textContent = data.head + (data.headMatchesExpected ? "" : " (differs from expected HEAD)");
      document.getElementById("gitStatus").textContent = data.gitStatus.summary;
      document.getElementById("statusLines").textContent = data.gitStatus.lines.join("\n") || "No selected prototype changes.";
    }

    renderStages();
    renderEvents();
    renderFormula();
    installTable({
      tableId: "reductionTable",
      rows: data.reductions,
      columns: [["reduction"], ["name"], ["eventLabel"], ["actionLabel"], ["delta"], ["summary"], ["exceptions"]],
      filterId: "reductionFilter",
      selectId: "reductionType",
      selectPredicate: (row, selected) => selected === "all" || (selected === "expands" && row.delta > 0) || (selected === "contracts" && row.delta < 0) || (selected === "equal" && row.delta === 0)
    });
    installTable({
      tableId: "timingTable",
      rows: data.timings,
      columns: [["metric"], ["cheap", "cheapDisplay"], ["full", "fullDisplay"], ["ratio"]],
      filterId: "timingFilter",
      selectId: "timingKind",
      selectPredicate: (row, selected) => selected === "all" || row.kind === selected
    });
    renderSources();
  </script>
</body>
</html>
"""


def render_report(data: Mapping[str, Any]) -> str:
    """Render the report with safely embedded live data."""

    rendered = HTML_TEMPLATE.replace("__REPORT_DATA__", safe_json(data)).replace(
        "__WORKSPACE_URL__", html.escape(WORKSPACE_URL, quote=True)
    )
    require("__REPORT_DATA__" not in rendered, "report data placeholder remains")
    require("__WORKSPACE_URL__" not in rendered, "workspace placeholder remains")
    require(rendered.isascii(), "generated report contains non-ASCII text")
    return rendered


def main() -> int:
    """Generate the report or print a clear input error."""

    try:
        data = build_data()
        OUTPUT_PATH.write_text(render_report(data), encoding="ascii")
    except ReportError as error:
        print(f"trace-validation report: {error}", file=sys.stderr)
        return 1
    print(f"generated {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    print(
        f"classification={data['classification']} "
        f"head={data['head']} dirty={str(data['gitStatus']['dirty']).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
