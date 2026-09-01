#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Throwaway benchmark for exact symbolic CCFRaft logs over SMT arrays."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Iterable

import symbolic_sequence_prototype as common


def array(field: str, step: int, node: int) -> str:
    return f"log_{field}_s{step:02d}_n{node}"


def length(step: int, node: int) -> str:
    return f"log_len_s{step:02d}_n{node}"


def prefix(field: str, node: int) -> str:
    return f"prefix_{field}_n{node}"


def latest(label: str, step: int, node: int) -> str:
    return f"last_{label}_s{step:02d}_n{node}"


def select(value: str, index: str | int) -> str:
    return f"(select {value} {index})"


def store(value: str, index: str | int, item: str | int) -> str:
    return f"(store {value} {index} {item})"


def smt_and(expressions: Iterable[str]) -> str:
    return common.smt_and(expressions)


def declare_state(
    formula: common.Formula,
    scenario: common.Scenario,
    include_summaries: bool,
) -> None:
    for step in range(len(scenario.actions) + 1):
        for node in range(scenario.nodes):
            formula.add(f"(declare-const {length(step, node)} Int)")
            for field in common.FIELDS:
                formula.add(
                    f"(declare-const {array(field, step, node)} (Array Int Int))"
                )
            if include_summaries:
                formula.add(f"(declare-const {latest('signature', step, node)} Int)")
                formula.add(
                    f"(declare-const {latest('configuration', step, node)} Int)"
                )


def initial_constraints(
    formula: common.Formula,
    scenario: common.Scenario,
    prefix_length: int,
    include_summaries: bool,
) -> None:
    for node in range(scenario.nodes):
        values = {}
        for field in common.FIELDS:
            formula.add(f"(declare-const {prefix(field, node)} (Array Int Int))")
            values[field] = prefix(field, node)
        next_index = prefix_length
        for entry in scenario.initial_suffixes[node]:
            for field, item in zip(common.FIELDS, entry, strict=True):
                values[field] = store(values[field], next_index, item)
            next_index += 1
        formula.labelled(
            f"initial_n{node}_length",
            f"(= {length(0, node)} {next_index})",
        )
        for field in common.FIELDS:
            formula.labelled(
                f"initial_n{node}_{field}",
                f"(= {array(field, 0, node)} {values[field]})",
            )
        if include_summaries:
            for tag, label in (
                (common.SIGNATURE, "signature"),
                (common.RECONFIGURATION, "configuration"),
            ):
                suffix_positions = [
                    position
                    for position, entry in enumerate(
                        scenario.initial_suffixes[node],
                        start=1,
                    )
                    if entry[1] == tag
                ]
                summary = latest(label, 0, node)
                if suffix_positions:
                    constraint = f"(= {summary} {prefix_length + suffix_positions[-1]})"
                else:
                    constraint = (
                        f"(and (<= 0 {summary}) (<= {summary} {prefix_length}) "
                        f"(=> (> {summary} 0) "
                        f"(= {select(values['tag'], f'(- {summary} 1)')} {tag})))"
                    )
                formula.labelled(f"initial_n{node}_last_{label}", constraint)


def unchanged(previous_step: int, node: int) -> tuple[str, dict[str, str]]:
    return (
        length(previous_step, node),
        {field: array(field, previous_step, node) for field in common.FIELDS},
    )


def append_entry(
    previous_step: int,
    node: int,
    entry: tuple[str | int, str | int, str | int, str | int],
) -> tuple[str, dict[str, str]]:
    old_length = length(previous_step, node)
    return (
        f"(+ {old_length} 1)",
        {
            field: store(array(field, previous_step, node), old_length, item)
            for field, item in zip(common.FIELDS, entry, strict=True)
        },
    )


def receive_request(
    previous_step: int,
    destination: int,
    request: common.Request,
) -> tuple[str, dict[str, str]]:
    old_length = length(previous_step, destination)
    previous_matches = (
        "true"
        if request.previous_index == 0
        else (
            f"(= {select(array('term', previous_step, destination), request.previous_index - 1)} "
            f"{request.previous_term})"
        )
    )
    valid_prefix = smt_and(
        (
            f"(<= {request.previous_index} {old_length})",
            previous_matches,
        )
    )
    if request.entry is None:
        return unchanged(previous_step, destination)

    target = request.previous_index
    target_exists = f"(< {target} {old_length})"
    target_matches = (
        f"(= {select(array('term', previous_step, destination), target)} "
        f"{request.entry[0]})"
    )
    keep = f"(and {target_exists} {target_matches})"
    new_length = (
        f"(ite {valid_prefix} (ite {keep} {old_length} {target + 1}) {old_length})"
    )
    updates = {}
    for field, item in zip(common.FIELDS, request.entry, strict=True):
        old = array(field, previous_step, destination)
        updates[field] = (
            f"(ite {valid_prefix} "
            f"(ite {keep} {old} {store(old, target, item)}) {old})"
        )
    return new_length, updates


def add_latest_query(
    formula: common.Formula,
    action: common.Action,
    previous_step: int,
    tag: int,
    label: str,
) -> None:
    node = action.source
    result = f"last_{label}_a{action.number:02d}"
    size = length(previous_step, node)
    tags = array("tag", previous_step, node)
    formula.add(f"(declare-const {result} Int)")
    no_match = (
        f"(and (= {result} 0) "
        "(forall ((i Int)) "
        f"(=> (and (<= 1 i) (<= i {size})) "
        f"(not (= {select(tags, '(- i 1)')} {tag})))))"
    )
    latest_match = (
        f"(and (<= 1 {result}) (<= {result} {size}) "
        f"(= {select(tags, f'(- {result} 1)')} {tag}) "
        "(forall ((i Int)) "
        f"(=> (and (< {result} i) (<= i {size})) "
        f"(not (= {select(tags, '(- i 1)')} {tag})))))"
    )
    formula.labelled(
        f"action{action.number:02d}_latest_{label}",
        f"(or {no_match} {latest_match})",
    )


def add_historical_queries(
    formula: common.Formula,
    action: common.Action,
    previous_step: int,
) -> None:
    if action.kind not in {
        "advanceCommitIndex",
        "changeConfiguration",
        "signCommittableMessages",
    }:
        return
    add_latest_query(
        formula,
        action,
        previous_step,
        common.SIGNATURE,
        "signature",
    )
    add_latest_query(
        formula,
        action,
        previous_step,
        common.RECONFIGURATION,
        "configuration",
    )


def expected_summary_offset(
    scenario: common.Scenario,
    action: common.Action,
    label: str,
) -> int | None:
    if action.kind != "advanceCommitIndex":
        return None
    expected = {
        "signature-commit": {
            "signature": {15: 2},
            "configuration": {},
        },
        "replicate-53": {
            "signature": {1: 2, 20: 4, 29: 6, 40: 7},
            "configuration": {1: 1, 20: 3, 29: 3, 40: 3},
        },
    }
    return expected[scenario.name][label].get(action.number)


def transition_constraints(
    formula: common.Formula,
    scenario: common.Scenario,
    prefix_length: int,
    include_history_queries: bool,
    include_summaries: bool,
) -> None:
    queues: dict[tuple[int, int], list[common.Request]] = {}
    for action in scenario.actions:
        previous_step = action.number - 1
        updates = {
            node: unchanged(previous_step, node) for node in range(scenario.nodes)
        }
        summary_updates = {
            node: {
                "signature": latest("signature", previous_step, node),
                "configuration": latest("configuration", previous_step, node),
            }
            for node in range(scenario.nodes)
        }
        if include_history_queries:
            add_historical_queries(formula, action, previous_step)
        if include_summaries and action.kind in {
            "advanceCommitIndex",
            "changeConfiguration",
            "signCommittableMessages",
        }:
            for label in ("signature", "configuration"):
                query = f"summary_query_{label}_a{action.number:02d}"
                formula.add(f"(declare-const {query} Int)")
                formula.labelled(
                    f"action{action.number:02d}_summary_query_{label}",
                    f"(= {query} {latest(label, previous_step, action.source)})",
                )
                expected = expected_summary_offset(scenario, action, label)
                if expected is not None:
                    formula.labelled(
                        f"action{action.number:02d}_observed_{label}",
                        f"(= {query} {prefix_length + expected})",
                    )

        if action.kind == "clientRequest":
            updates[action.source] = append_entry(
                previous_step,
                action.source,
                (2, common.TRANSACTION, action.transaction, 0),
            )
        elif action.kind == "signCommittableMessages":
            updates[action.source] = append_entry(
                previous_step,
                action.source,
                (2, common.SIGNATURE, 0, 0),
            )
            summary_updates[action.source][
                "signature"
            ] = f"(+ {length(previous_step, action.source)} 1)"
        elif action.kind == "changeConfiguration":
            updates[action.source] = append_entry(
                previous_step,
                action.source,
                (2, common.RECONFIGURATION, 0, 3),
            )
            summary_updates[action.source][
                "configuration"
            ] = f"(+ {length(previous_step, action.source)} 1)"
        elif action.kind == "appendEntries":
            batch_end = prefix_length + action.parameter
            heartbeat = action.number in scenario.heartbeat_actions
            previous_index = batch_end if heartbeat else batch_end - 1
            previous_term = (
                "0"
                if previous_index == 0
                else select(
                    array("term", previous_step, action.source),
                    previous_index - 1,
                )
            )
            if action.number == scenario.mutation_action:
                previous_term = (
                    f"(ite mutation_wrong_prev_term (+ {previous_term} 1) "
                    f"{previous_term})"
                )
            entry = None
            if not heartbeat:
                entry = tuple(
                    select(
                        array(field, previous_step, action.source),
                        batch_end - 1,
                    )
                    for field in common.FIELDS
                )
            queues.setdefault((action.source, action.destination), []).append(
                common.Request(previous_index, previous_term, entry)
            )
        elif action.kind == "receive":
            pending = queues.get((action.source, action.destination), [])
            if pending:
                request = pending.pop(0)
                updates[action.destination] = receive_request(
                    previous_step,
                    action.destination,
                    request,
                )
                if include_summaries and request.entry is not None:
                    before = scenario.expected_lengths[previous_step][
                        action.destination
                    ]
                    after = scenario.expected_lengths[action.number][action.destination]
                    if after == before + 1:
                        for tag, label in (
                            (common.SIGNATURE, "signature"),
                            (common.RECONFIGURATION, "configuration"),
                        ):
                            summary_updates[action.destination][label] = (
                                f"(ite (= {request.entry[1]} {tag}) "
                                f"{request.previous_index + 1} "
                                f"{latest(label, previous_step, action.destination)})"
                            )

        for node in range(scenario.nodes):
            next_length, next_fields = updates[node]
            formula.labelled(
                f"action{action.number:02d}_n{node}_length",
                f"(= {length(action.number, node)} {next_length})",
            )
            for field in common.FIELDS:
                formula.labelled(
                    f"action{action.number:02d}_n{node}_{field}",
                    f"(= {array(field, action.number, node)} {next_fields[field]})",
                )
            if include_summaries:
                for label in ("signature", "configuration"):
                    summary = latest(label, action.number, node)
                    formula.labelled(
                        f"action{action.number:02d}_n{node}_last_{label}",
                        f"(= {summary} {summary_updates[node][label]})",
                    )
                    formula.labelled(
                        f"action{action.number:02d}_n{node}_{label}_range",
                        (
                            f"(and (<= 0 {summary}) "
                            f"(<= {summary} {length(action.number, node)}))"
                        ),
                    )

        for node, offset in enumerate(scenario.expected_lengths[action.number]):
            formula.labelled(
                f"observation{action.number:02d}_n{node}_length",
                f"(= {length(action.number, node)} {prefix_length + offset})",
            )


def build_formula(
    scenario: common.Scenario,
    prefix_length: int,
    include_history_queries: bool,
    include_summaries: bool,
) -> tuple[str, str, int]:
    formula = common.Formula()
    formula.add("(set-logic ALL)")
    formula.add("(set-option :produce-unsat-assumptions true)")
    mutation_label = "mutation_wrong_prev_term"
    formula.add(f"(declare-const {mutation_label} Bool)")
    declare_state(formula, scenario, include_summaries)
    initial_constraints(
        formula,
        scenario,
        prefix_length,
        include_summaries,
    )
    transition_constraints(
        formula,
        scenario,
        prefix_length,
        include_history_queries,
        include_summaries,
    )
    return (
        formula.text(),
        formula.text((mutation_label,), get_unsat_assumptions=True),
        len(formula.labels),
    )


def benchmark(
    root: Path,
    output_dir: Path,
    cvc5: Path,
    prefix_lengths: tuple[int, ...],
    samples: int,
    time_limit_ms: int,
    wall_timeout_seconds: int,
) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for scenario in common.build_scenarios(root):
        for mode, include_history_queries, include_summaries in (
            ("structural", False, False),
            ("quantified-history", True, False),
            ("summary-history", False, True),
        ):
            for prefix_length in prefix_lengths:
                sat_formula_text, mutation_formula_text, labels = build_formula(
                    scenario,
                    prefix_length,
                    include_history_queries,
                    include_summaries,
                )
                sat_formula_path = (
                    output_dir
                    / f"{scenario.name}-{mode}-prefix-{prefix_length}-sat.smt2"
                )
                mutation_formula_path = (
                    output_dir
                    / f"{scenario.name}-{mode}-prefix-{prefix_length}-mutation.smt2"
                )
                sat_formula_path.write_text(sat_formula_text, encoding="ascii")
                mutation_formula_path.write_text(
                    mutation_formula_text,
                    encoding="ascii",
                )
                sat_timings = []
                mutation_timings = []
                sat_status = ""
                mutation_status = ""
                core = ""
                common.run_solver(
                    cvc5,
                    sat_formula_path,
                    prefix_length + 1024,
                    time_limit_ms,
                    wall_timeout_seconds,
                )
                common.run_solver(
                    cvc5,
                    mutation_formula_path,
                    prefix_length + 1024,
                    time_limit_ms,
                    wall_timeout_seconds,
                )
                for _ in range(samples):
                    elapsed_ms, output, timed_out = common.run_solver(
                        cvc5,
                        sat_formula_path,
                        prefix_length + 1024,
                        time_limit_ms,
                        wall_timeout_seconds,
                    )
                    sat_timings.append(elapsed_ms)
                    if timed_out:
                        sat_status = "timeout"
                    else:
                        sat_status, _ = common.parse_solver_output(output)
                    elapsed_ms, output, timed_out = common.run_solver(
                        cvc5,
                        mutation_formula_path,
                        prefix_length + 1024,
                        time_limit_ms,
                        wall_timeout_seconds,
                    )
                    mutation_timings.append(elapsed_ms)
                    if timed_out:
                        mutation_status = "timeout"
                        core = ""
                    else:
                        mutation_status, core = common.parse_solver_output(output)
                row = {
                    "scenario": scenario.name,
                    "backend": "symbolic-array",
                    "mode": mode,
                    "actions": len(scenario.actions),
                    "nodes": scenario.nodes,
                    "prefix_length": prefix_length,
                    "formula_bytes": len(sat_formula_text.encode("ascii")),
                    "labels": labels,
                    "samples": samples,
                    "sat_samples_ms": sat_timings,
                    "sat_median_ms": int(statistics.median(sat_timings)),
                    "sat_p95_ms": (
                        common.percentile_95(sat_timings) if samples > 1 else None
                    ),
                    "mutation_samples_ms": mutation_timings,
                    "mutation_median_ms": int(statistics.median(mutation_timings)),
                    "mutation_p95_ms": (
                        common.percentile_95(mutation_timings) if samples > 1 else None
                    ),
                    "sat": sat_status,
                    "mutation": mutation_status,
                    "core_labels": len(core.strip("()").split()),
                }
                rows.append(row)
                print(
                    f"scenario={scenario.name} backend=symbolic-array mode={mode} "
                    f"prefix={prefix_length} actions={len(scenario.actions)} "
                    f"bytes={row['formula_bytes']} "
                    f"sat_ms={row['sat_median_ms']} sat={sat_status} "
                    f"mutation_ms={row['mutation_median_ms']} "
                    f"mutation={mutation_status}",
                    flush=True,
                )
    result = {
        "schema": "ccfraft-symbolic-array-prototype/v1",
        "question": (
            "Can exact symbolic log execution avoid materialising S0 and fixed "
            "log capacities at acceptable cost on the current trace shapes?"
        ),
        "scope": (
            "Log-only prototype with unbounded integer-indexed arrays. Structural "
            "mode measures append, point reads, and observed lengths; the two "
            "input traces do not exercise truncation. Quantified-history mode "
            "adds general exact latest-entry "
            "constraints. Summary-history uses a trace-relative equisatisfiable "
            "prefix repair: these traces never point-read an omitted prefix tag, "
            "so omitted tags can be chosen to realize each carried latest-entry "
            "summary. Packet pairing and branch choices remain trace-specific; "
            "the full CCFRaft state is not encoded."
        ),
        "cvc5": str(cvc5),
        "samples_per_case": samples,
        "warmup_runs_per_case": 1,
        "solver_time_limit_ms": time_limit_ms,
        "wall_timeout_seconds": wall_timeout_seconds,
        "rows": rows,
    }
    (output_dir / "benchmark.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cvc5", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--sequence-benchmark", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--prefix-lengths", default="0,15123,1000000")
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--time-limit-ms", type=int, default=10000)
    parser.add_argument("--wall-timeout-seconds", type=int, default=15)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    result = benchmark(
        root,
        args.output_dir,
        args.cvc5,
        tuple(int(value) for value in args.prefix_lengths.split(",")),
        args.samples,
        args.time_limit_ms,
        args.wall_timeout_seconds,
    )
    sequence = json.loads(args.sequence_benchmark.read_text(encoding="utf-8"))
    combined = {
        "schema": "ccfraft-symbolic-log-prototype-report/v1",
        "question": result["question"],
        "scope": (f"{result['scope']} Native sequence comparison: {sequence['scope']}"),
        "rows": sequence["rows"] + result["rows"],
        "sequence": sequence,
        "array": result,
    }
    common.render_report(combined, args.report)
    print(f"report={args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
