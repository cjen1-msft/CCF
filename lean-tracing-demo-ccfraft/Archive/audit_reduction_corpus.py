#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Audit the fixed 53-event reducer against every CCF Raft scenario."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import statistics
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
LEAN_ROOT = REPO_ROOT / "lean"
DEFAULT_DRIVER = REPO_ROOT / "build" / "raft_driver"
DEFAULT_SCENARIOS = REPO_ROOT / "tests" / "raft_scenarios"
DEFAULT_OUTPUT = (
    LEAN_ROOT / ".lake" / "build" / "reduction-critique" / "corpus-audit-v1.json"
)
SCHEMA_VERSION = "ccfraft-reduction-corpus-audit/v1"

EXPECTED_BASELINE = {
    "scenario_count": 50,
    "driver_successes": 50,
    "preprocessor_successes": 50,
    "raw_events": 10_092,
    "preprocessed_events": 9_480,
    "preprocessed_min": 3,
    "preprocessed_max": 696,
    "preprocessed_median": 151,
    "preprocessed_mean": 189.6,
    "accepted_scenarios": ["replicate"],
    "accepted_event_instances": 53,
    "function_count": 19,
    "packet_family_count": 7,
    "node_count_min": 1,
    "node_count_max": 5,
    "reducer_function_count": 10,
    "rejection_count": 49,
    "event_count_rejections": 49,
    "rejected_without_new_functions": [
        "append",
        "large_entry_batching",
        "reconfiguration",
        "reconnect",
        "retire_one",
        "startup",
        "startup_2nodes",
        "swap_single_node",
    ],
}

TERM_KEYS = {
    "current_view",
    "prev_term",
    "term",
    "term_of_idx",
    "term_of_last_committable_idx",
    "view",
}
INDEX_KEYS = {
    "commit_idx",
    "idx",
    "last_committable_idx",
    "last_idx",
    "last_log_idx",
    "leader_commit_idx",
    "match_idx",
    "prev_idx",
    "sent_idx",
    "seqno",
}


class AuditError(RuntimeError):
    """Report a corpus execution or baseline failure."""


def require(condition: bool, message: str) -> None:
    """Raise an audit error when a required condition is false."""

    if not condition:
        raise AuditError(message)


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one file."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    """Return a repository-relative path."""

    return path.resolve().relative_to(REPO_ROOT).as_posix()


def load_pipeline_modules() -> tuple[Any, Any]:
    """Import the exact test preprocessor and current fixture reducer."""

    tests_path = str(REPO_ROOT / "tests")
    reducer_path = str(LEAN_ROOT / "CCFRaft")
    for path in (tests_path, reducer_path):
        if path not in sys.path:
            sys.path.insert(0, path)
    runner = importlib.import_module("raft_scenarios_runner")
    reducer = importlib.import_module("full_trace_prototype")
    require(
        callable(getattr(runner, "preprocess_for_trace_validation", None)),
        "preprocess_for_trace_validation is unavailable",
    )
    require(
        callable(getattr(reducer, "validate_events", None)),
        "validate_events is unavailable",
    )
    return runner, reducer


def named_integer_values(value: Any, keys: set[str]) -> set[int]:
    """Collect integer values whose object key belongs to a known field set."""

    found: set[int] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key in keys and type(child) is int:
                found.add(child)
            found.update(named_integer_values(child, keys))
    elif isinstance(value, list):
        for child in value:
            found.update(named_integer_values(child, keys))
    return found


def configurations(value: Any) -> set[tuple[str, ...]]:
    """Collect configuration membership sets from trace objects."""

    found: set[tuple[str, ...]] = set()
    if isinstance(value, Mapping):
        nodes = value.get("nodes")
        if isinstance(nodes, Mapping):
            found.add(tuple(sorted((str(node) for node in nodes), key=node_sort_key)))
        for child in value.values():
            found.update(configurations(child))
    elif isinstance(value, list):
        for child in value:
            found.update(configurations(child))
    return found


def node_sort_key(node: str) -> tuple[int, int | str]:
    """Sort decimal node IDs numerically and all other IDs lexically."""

    return (0, int(node)) if node.isdigit() else (1, node)


def parse_trace_lines(lines: Iterable[str]) -> list[dict[str, Any]]:
    """Parse preprocessed NDJSON lines as objects."""

    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise AuditError(f"preprocessed event {number}: {error}") from error
        require(
            isinstance(row, dict),
            f"preprocessed event {number}: top level is not an object",
        )
        rows.append(row)
    return rows


def inventory(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Summarize functions, packets, nodes, terms, indices, and configurations."""

    function_counts: Counter[str] = Counter()
    packet_counts: Counter[str] = Counter()
    nodes: set[str] = set()
    terms: set[int] = set()
    indices: set[int] = set()
    config_sets: set[tuple[str, ...]] = set()
    leadership_states: set[str] = set()
    membership_states: set[str] = set()
    for row in rows:
        message = row.get("msg")
        if not isinstance(message, Mapping):
            continue
        function = message.get("function")
        if isinstance(function, str):
            function_counts[function] += 1
        packet = message.get("packet")
        if isinstance(packet, Mapping):
            family = packet.get("msg")
            if isinstance(family, str):
                packet_counts[family] += 1
        state = message.get("state")
        if isinstance(state, Mapping):
            node = state.get("node_id")
            if isinstance(node, (int, str)) and not isinstance(node, bool):
                nodes.add(str(node))
            role = state.get("leadership_state")
            if isinstance(role, str):
                leadership_states.add(role)
            membership = state.get("membership_state")
            if isinstance(membership, str):
                membership_states.add(membership)
        terms.update(named_integer_values(message, TERM_KEYS))
        indices.update(named_integer_values(message, INDEX_KEYS))
        config_sets.update(configurations(message))
    return {
        "function_counts": dict(sorted(function_counts.items())),
        "packet_family_counts": dict(sorted(packet_counts.items())),
        "node_ids": sorted(nodes, key=node_sort_key),
        "node_count": len(nodes),
        "terms": sorted(terms),
        "indices": sorted(indices),
        "configuration_sets": [list(value) for value in sorted(config_sets)],
        "leadership_states": sorted(leadership_states),
        "membership_states": sorted(membership_states),
    }


def classify_reducer_error(error: BaseException) -> tuple[str, str]:
    """Map the reducer's fail-closed exception to a stable audit stage."""

    reason = str(error).strip() or error.__class__.__name__
    if reason.startswith("real trace has ") and reason.endswith(" events, expected 53"):
        return "event_count", reason
    if reason.startswith("raw NDJSON event ") or "top level is not an object" in reason:
        return "parse", reason
    if "h_ts" in reason:
        return "envelope", reason
    if "top-level keys" in reason or "wrong tag" in reason or "wrong source" in reason:
        return "envelope", reason
    return "fixture_mapping", reason


def audit_scenario(
    scenario: Path,
    driver: Path,
    temporary_root: Path,
    timeout_seconds: int | None,
    runner: Any,
    reducer: Any,
) -> dict[str, Any]:
    """Run one scenario, preprocess it, and call the current reducer."""

    result: dict[str, Any] = {
        "scenario": scenario.name,
        "scenario_sha256": sha256_file(scenario),
        "driver_success": False,
        "preprocessor_success": False,
        "raw_count": 0,
        "preprocessed_count": 0,
        "reducer": {
            "accepted": False,
            "rejection_stage": "not_run",
            "reason": "driver did not complete",
        },
    }
    try:
        completed = subprocess.run(
            [str(driver.resolve()), str(scenario.resolve())],
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        require(timeout_seconds is not None, "driver timeout lacks a configured limit")
        result["reducer"] = {
            "accepted": False,
            "rejection_stage": "driver_timeout",
            "reason": f"raft_driver exceeded {timeout_seconds} seconds",
        }
        return result

    stderr = completed.stderr.decode("utf-8", errors="replace").strip()
    result["driver_returncode"] = completed.returncode
    result["driver_success"] = completed.returncode == 0 and not stderr
    if not result["driver_success"]:
        result["reducer"] = {
            "accepted": False,
            "rejection_stage": "driver",
            "reason": stderr or f"raft_driver returned {completed.returncode}",
        }
        return result

    stdout = completed.stdout.decode("utf-8")
    raw_lines = [line for line in stdout.splitlines() if '"raft_trace"' in line]
    raw_rows = parse_trace_lines(raw_lines)
    result["raw_trace_line_count"] = len(raw_lines)
    result["raw_count"] = sum(
        isinstance(row.get("msg"), Mapping)
        and isinstance(row["msg"].get("function"), str)
        for row in raw_rows
    )
    try:
        preprocessed_lines = runner.preprocess_for_trace_validation(raw_lines)
        rows = parse_trace_lines(preprocessed_lines)
    except (AssertionError, AuditError, json.JSONDecodeError, KeyError) as error:
        result["reducer"] = {
            "accepted": False,
            "rejection_stage": "preprocessor",
            "reason": str(error).strip() or error.__class__.__name__,
        }
        return result

    result["preprocessor_success"] = True
    result["preprocessed_count"] = len(preprocessed_lines)
    result.update(inventory(rows))

    scenario_directory = temporary_root / scenario.name
    scenario_directory.mkdir()
    trace_path = scenario_directory / "preprocessed.ndjson"
    trace_path.write_text("\n".join(preprocessed_lines) + "\n", encoding="utf-8")
    try:
        events = reducer.read_events(trace_path)
        reducer.validate_events(events)
    except (OSError, reducer.ReductionError) as error:
        stage, reason = classify_reducer_error(error)
        result["reducer"] = {
            "accepted": False,
            "rejection_stage": stage,
            "reason": reason,
        }
    else:
        result["reducer"] = {
            "accepted": True,
            "rejection_stage": None,
            "reason": "accepted exact replicate-v1 fixture",
        }
    return result


def range_summary(values: Iterable[int]) -> dict[str, Any]:
    """Build a sorted value set with minimum and maximum."""

    ordered = sorted(set(values))
    return {
        "minimum": ordered[0] if ordered else None,
        "maximum": ordered[-1] if ordered else None,
        "values": ordered,
    }


def aggregate_inventory(
    scenarios: Sequence[Mapping[str, Any]], field: str
) -> list[dict[str, Any]]:
    """Aggregate one per-scenario count map."""

    event_counts: Counter[str] = Counter()
    scenario_counts: Counter[str] = Counter()
    for scenario in scenarios:
        counts = scenario.get(field, {})
        if not isinstance(counts, Mapping):
            continue
        for name, count in counts.items():
            if isinstance(name, str) and type(count) is int:
                event_counts[name] += count
                scenario_counts[name] += 1
    return [
        {
            "name": name,
            "event_count": event_counts[name],
            "scenario_count": scenario_counts[name],
        }
        for name in sorted(event_counts)
    ]


def build_aggregate(
    scenarios: Sequence[Mapping[str, Any]], reducer: Any
) -> dict[str, Any]:
    """Build deterministic corpus totals and coverage summaries."""

    counts = [int(scenario["preprocessed_count"]) for scenario in scenarios]
    accepted = [
        str(scenario["scenario"])
        for scenario in scenarios
        if scenario["reducer"]["accepted"]
    ]
    reducer_functions = sorted(
        {expected.function for expected in reducer.EXPECTED_EVENTS.values()}
    )
    reducer_function_set = set(reducer_functions)
    no_new_functions = sorted(
        str(scenario["scenario"])
        for scenario in scenarios
        if not scenario["reducer"]["accepted"]
        and set(scenario.get("function_counts", {})).issubset(reducer_function_set)
    )
    all_terms = {
        value
        for scenario in scenarios
        for value in scenario.get("terms", [])
        if type(value) is int
    }
    all_indices = {
        value
        for scenario in scenarios
        for value in scenario.get("indices", [])
        if type(value) is int
    }
    all_nodes = {
        node for scenario in scenarios for node in scenario.get("node_ids", [])
    }
    all_configurations = {
        tuple(configuration)
        for scenario in scenarios
        for configuration in scenario.get("configuration_sets", [])
    }
    all_roles = {
        role for scenario in scenarios for role in scenario.get("leadership_states", [])
    }
    all_membership = {
        state
        for scenario in scenarios
        for state in scenario.get("membership_states", [])
    }
    function_inventory = aggregate_inventory(scenarios, "function_counts")
    packet_inventory = aggregate_inventory(scenarios, "packet_family_counts")
    accepted_events = sum(
        int(scenario["preprocessed_count"])
        for scenario in scenarios
        if scenario["reducer"]["accepted"]
    )
    total_preprocessed = sum(counts)
    median_count = statistics.median(counts)
    if median_count.is_integer():
        median_count = int(median_count)
    return {
        "scenario_count": len(scenarios),
        "driver_successes": sum(bool(row["driver_success"]) for row in scenarios),
        "preprocessor_successes": sum(
            bool(row["preprocessor_success"]) for row in scenarios
        ),
        "total_raw_events": sum(int(row["raw_count"]) for row in scenarios),
        "total_raw_trace_lines": sum(
            int(row["raw_trace_line_count"]) for row in scenarios
        ),
        "total_preprocessed_events": total_preprocessed,
        "preprocessed_event_count": {
            "minimum": min(counts),
            "maximum": max(counts),
            "median": median_count,
            "mean": round(statistics.mean(counts), 1),
        },
        "accepted_scenario_count": len(accepted),
        "accepted_scenarios": accepted,
        "rejected_scenario_count": len(scenarios) - len(accepted),
        "event_count_rejections": sum(
            row["reducer"]["rejection_stage"] == "event_count" for row in scenarios
        ),
        "accepted_event_instances": accepted_events,
        "accepted_event_percentage": round(
            100 * accepted_events / total_preprocessed, 2
        ),
        "function_inventory": function_inventory,
        "function_inventory_count": len(function_inventory),
        "packet_family_inventory": packet_inventory,
        "packet_family_count": len(packet_inventory),
        "node_ids": sorted(all_nodes, key=node_sort_key),
        "node_count": {
            "minimum": min(int(row["node_count"]) for row in scenarios),
            "maximum": max(int(row["node_count"]) for row in scenarios),
        },
        "term_range": range_summary(all_terms),
        "index_range": range_summary(all_indices),
        "configuration_sets": [
            list(configuration) for configuration in sorted(all_configurations)
        ],
        "leadership_states": sorted(all_roles),
        "membership_states": sorted(all_membership),
        "reducer_expected_functions": reducer_functions,
        "reducer_expected_function_count": len(reducer_functions),
        "rejected_without_new_functions": no_new_functions,
    }


def assert_baseline(aggregate: Mapping[str, Any]) -> None:
    """Fail when the measured corpus facts drift from the reviewed baseline."""

    observed = {
        "scenario_count": aggregate["scenario_count"],
        "driver_successes": aggregate["driver_successes"],
        "preprocessor_successes": aggregate["preprocessor_successes"],
        "raw_events": aggregate["total_raw_events"],
        "preprocessed_events": aggregate["total_preprocessed_events"],
        "preprocessed_min": aggregate["preprocessed_event_count"]["minimum"],
        "preprocessed_max": aggregate["preprocessed_event_count"]["maximum"],
        "preprocessed_median": aggregate["preprocessed_event_count"]["median"],
        "preprocessed_mean": aggregate["preprocessed_event_count"]["mean"],
        "accepted_scenarios": aggregate["accepted_scenarios"],
        "accepted_event_instances": aggregate["accepted_event_instances"],
        "function_count": aggregate["function_inventory_count"],
        "packet_family_count": aggregate["packet_family_count"],
        "node_count_min": aggregate["node_count"]["minimum"],
        "node_count_max": aggregate["node_count"]["maximum"],
        "reducer_function_count": aggregate["reducer_expected_function_count"],
        "rejection_count": aggregate["rejected_scenario_count"],
        "event_count_rejections": aggregate["event_count_rejections"],
        "rejected_without_new_functions": aggregate["rejected_without_new_functions"],
    }
    require(
        observed == EXPECTED_BASELINE,
        "corpus baseline drifted:\n"
        f"observed={json.dumps(observed, sort_keys=True)}\n"
        f"expected={json.dumps(EXPECTED_BASELINE, sort_keys=True)}",
    )


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    """Write stable JSON without a wall-clock field."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse corpus audit options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, default=DEFAULT_DRIVER)
    parser.add_argument("--scenarios-dir", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=None,
        help="optional per-scenario driver timeout",
    )
    parser.add_argument("--no-assert-baseline", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the corpus audit and write the deterministic manifest."""

    args = parse_args(argv)
    try:
        driver = args.driver.resolve()
        scenarios_directory = args.scenarios_dir.resolve()
        require(
            driver.is_file() and driver.stat().st_mode & 0o111,
            f"{driver} is not executable",
        )
        require(
            scenarios_directory.is_dir(),
            f"scenario directory is absent: {scenarios_directory}",
        )
        require(
            args.timeout_seconds is None or args.timeout_seconds > 0,
            "timeout must be positive",
        )
        scenario_paths = sorted(
            (path for path in scenarios_directory.iterdir() if path.is_file()),
            key=lambda path: path.name,
        )
        require(bool(scenario_paths), "scenario corpus is empty")
        runner, reducer = load_pipeline_modules()
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="corpus-audit-",
            dir=output.parent,
        ) as directory:
            temporary_root = Path(directory)
            scenarios = [
                audit_scenario(
                    scenario,
                    driver,
                    temporary_root,
                    args.timeout_seconds,
                    runner,
                    reducer,
                )
                for scenario in scenario_paths
            ]
        aggregate = build_aggregate(scenarios, reducer)
        if not args.no_assert_baseline:
            assert_baseline(aggregate)
        artifact = {
            "schema_version": SCHEMA_VERSION,
            "inputs": {
                "driver": relative(driver),
                "driver_sha256": sha256_file(driver),
                "scenario_directory": relative(scenarios_directory),
                "preprocessor": relative(REPO_ROOT / "tests/raft_scenarios_runner.py"),
                "preprocessor_sha256": sha256_file(
                    REPO_ROOT / "tests/raft_scenarios_runner.py"
                ),
                "reducer": relative(SCRIPT_PATH.with_name("full_trace_prototype.py")),
                "reducer_sha256": sha256_file(
                    SCRIPT_PATH.with_name("full_trace_prototype.py")
                ),
                "timeout_seconds_per_scenario": args.timeout_seconds,
            },
            "baseline_asserted": not args.no_assert_baseline,
            "aggregate": aggregate,
            "scenarios": scenarios,
        }
        write_json(output, artifact)
    except (AuditError, OSError, UnicodeError) as error:
        print(f"reduction corpus audit failed: {error}", file=sys.stderr)
        return 1
    print(
        f"corpus scenarios={aggregate['scenario_count']} "
        f"raw={aggregate['total_raw_events']} "
        f"preprocessed={aggregate['total_preprocessed_events']} "
        f"accepted={aggregate['accepted_scenario_count']} "
        f"output={output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
