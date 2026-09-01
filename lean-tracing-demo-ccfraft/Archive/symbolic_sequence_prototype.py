#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Throwaway benchmark for exact symbolic CCFRaft log sequences."""

from __future__ import annotations

import argparse
import html
import json
import statistics
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

FIELDS = ("term", "tag", "tx", "config")
TRANSACTION = 1
SIGNATURE = 2
RECONFIGURATION = 3

LONG_LENGTHS = (
    (2, 0),
    (2, 0),
    (3, 0),
    (3, 0),
    (4, 0),
    (4, 0),
    (4, 0),
    (4, 0),
    (4, 0),
    (4, 0),
    (4, 0),
    (4, 0),
    (4, 1),
    (4, 2),
    (4, 3),
    (4, 4),
    (4, 4),
    (4, 4),
    (4, 4),
    (4, 4),
    (4, 4),
    (5, 4),
    (6, 4),
    (6, 4),
    (6, 4),
    (6, 5),
    (6, 6),
    (6, 6),
    (6, 6),
    (6, 6),
    (6, 6),
    (6, 6),
    (6, 6),
    (6, 6),
    (6, 6),
    (6, 6),
    (7, 6),
    (7, 6),
    (7, 7),
    (7, 7),
    (7, 7),
    (7, 7),
    (7, 7),
    (7, 7),
)


class PrototypeError(RuntimeError):
    """Report malformed prototype input or solver output."""


@dataclass(frozen=True)
class Action:
    number: int
    kind: str
    source: int = 0
    destination: int = 0
    parameter: int = 0
    transaction: int = 0


@dataclass(frozen=True)
class Request:
    previous_index: int
    previous_term: str
    entry: tuple[str, str, str, str] | None


@dataclass(frozen=True)
class Scenario:
    name: str
    nodes: int
    actions: tuple[Action, ...]
    initial_suffixes: tuple[tuple[tuple[int, int, int, int], ...], ...]
    expected_lengths: tuple[tuple[int, ...], ...]
    heartbeat_actions: frozenset[int]
    mutation_action: int


class Formula:
    """Build one labelled SMT-LIB query."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.labels: list[str] = []

    def add(self, line: str = "") -> None:
        self.lines.append(line)

    def labelled(self, label: str, expression: str) -> None:
        if label in self.labels:
            raise PrototypeError(f"duplicate label: {label}")
        self.labels.append(label)
        self.add(f"(declare-const {label} Bool)")
        self.add(f"(assert (=> {label} {expression}))")

    def text(
        self,
        extra_assumptions: tuple[str, ...] = (),
        get_unsat_assumptions: bool = False,
    ) -> str:
        assumptions = " ".join((*self.labels, *extra_assumptions))
        suffix = f"(check-sat-assuming ({assumptions}))\n"
        if get_unsat_assumptions:
            suffix += "(get-unsat-assumptions)\n"
        return "\n".join(self.lines) + "\n" + suffix


def seq(field: str, step: int, node: int) -> str:
    return f"log_{field}_s{step:02d}_n{node}"


def prefix(field: str, node: int) -> str:
    return f"prefix_{field}_n{node}"


def unit(value: str | int) -> str:
    return f"(seq.unit {value})"


def concat(left: str, right: str) -> str:
    return f"(seq.++ {left} {right})"


def append_value(sequence: str, value: str | int) -> str:
    return concat(sequence, unit(value))


def nth(sequence: str, index: str | int) -> str:
    return f"(seq.nth {sequence} {index})"


def extract(sequence: str, start: str | int, length: str | int) -> str:
    return f"(seq.extract {sequence} {start} {length})"


def smt_and(expressions: Iterable[str]) -> str:
    values = tuple(expressions)
    if not values:
        return "true"
    if len(values) == 1:
        return values[0]
    return f"(and {' '.join(values)})"


def unchanged(previous_step: int, step: int, node: int) -> dict[str, str]:
    return {field: seq(field, previous_step, node) for field in FIELDS}


def append_entry(
    previous_step: int,
    node: int,
    entry: tuple[str | int, str | int, str | int, str | int],
) -> dict[str, str]:
    return {
        field: append_value(seq(field, previous_step, node), value)
        for field, value in zip(FIELDS, entry, strict=True)
    }


def receive_request(
    previous_step: int,
    destination: int,
    request: Request,
) -> tuple[dict[str, str], str]:
    old_length = f"(seq.len {seq('tag', previous_step, destination)})"
    previous_matches = (
        "true"
        if request.previous_index == 0
        else (
            f"(= {nth(seq('term', previous_step, destination), request.previous_index - 1)} "
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
        return unchanged(previous_step, previous_step + 1, destination), valid_prefix

    target = request.previous_index
    target_exists = f"(< {target} {old_length})"
    target_matches = (
        f"(= {nth(seq('term', previous_step, destination), target)} "
        f"{request.entry[0]})"
    )
    updates = {}
    for field, value in zip(FIELDS, request.entry, strict=True):
        old = seq(field, previous_step, destination)
        replacement = append_value(extract(old, 0, target), value)
        updates[field] = (
            f"(ite {valid_prefix} "
            f"(ite (and {target_exists} {target_matches}) {old} {replacement}) "
            f"{old})"
        )
    return updates, valid_prefix


def parse_short_trace(path: Path) -> tuple[Action, ...]:
    actions: list[Action] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw:
            continue
        fields = raw.split(",")
        kind = fields[0]
        number = len(actions) + 1
        if kind == "client":
            actions.append(
                Action(
                    number, "clientRequest", int(fields[1]), transaction=int(fields[2])
                )
            )
        elif kind == "sign":
            actions.append(Action(number, "signCommittableMessages", int(fields[1])))
        elif kind == "append":
            actions.append(
                Action(
                    number,
                    "appendEntries",
                    int(fields[1]),
                    int(fields[2]),
                    int(fields[3]),
                )
            )
        elif kind == "receive":
            actions.append(Action(number, "receive", int(fields[1]), int(fields[2])))
        elif kind == "commit":
            actions.append(Action(number, "advanceCommitIndex", int(fields[1])))
        else:
            raise PrototypeError(f"unsupported short-trace action: {raw}")
    return tuple(actions)


def parse_long_actions(path: Path) -> tuple[Action, ...]:
    value = json.loads(path.read_text(encoding="utf-8"))
    actions = []
    for raw in [
        action for reduction in value["reductions"] for action in reduction["actions"]
    ]:
        parameters = raw["parameters"]
        actions.append(
            Action(
                raw["action"],
                raw["kind"],
                int(parameters.get("source", parameters.get("node", 0))),
                int(parameters.get("destination", 0)),
                int(parameters.get("batch_end", 0)),
                0,
            )
        )
    return tuple(actions)


def infer_lengths(
    actions: tuple[Action, ...],
    nodes: int,
    initial: tuple[int, ...],
    heartbeat_actions: frozenset[int],
) -> tuple[tuple[int, ...], ...]:
    lengths = list(initial)
    result = [tuple(lengths)]
    queues: dict[tuple[int, int], list[tuple[int, bool]]] = {}
    for action in actions:
        if action.kind in {
            "clientRequest",
            "signCommittableMessages",
            "changeConfiguration",
        }:
            lengths[action.source] += 1
        elif action.kind == "appendEntries":
            queues.setdefault((action.source, action.destination), []).append(
                (action.parameter - 1, action.number not in heartbeat_actions)
            )
        elif action.kind == "receive":
            pending = queues.get((action.source, action.destination), [])
            if pending:
                previous_index, has_entry = pending.pop(0)
                if previous_index <= lengths[action.destination] and has_entry:
                    lengths[action.destination] = previous_index + 1
        result.append(tuple(lengths))
    return tuple(result)


def build_scenarios(root: Path) -> tuple[Scenario, Scenario]:
    short_actions = parse_short_trace(root / "CCFRaft/traces/signature-commit.trace")
    short_lengths = infer_lengths(
        short_actions,
        3,
        (0, 0, 0),
        frozenset(),
    )
    short = Scenario(
        "signature-commit",
        3,
        short_actions,
        ((), (), ()),
        short_lengths,
        frozenset(),
        6,
    )

    long_actions = parse_long_actions(
        root / ".lake/build/full-trace-prototype/proposed-mapping-certificate-v2.json"
    )
    if len(long_actions) != 43:
        raise PrototypeError("long trace no longer contains 43 actions")
    if tuple(action.number for action in long_actions) != tuple(range(1, 44)):
        raise PrototypeError("long trace action numbers are not contiguous")
    for heartbeat in (30, 33, 41):
        if long_actions[heartbeat - 1].kind != "appendEntries":
            raise PrototypeError(
                f"heartbeat action {heartbeat} is no longer appendEntries"
            )
    if len(LONG_LENGTHS) != len(long_actions) + 1:
        raise PrototypeError(
            "long trace expected-length rows no longer match its actions"
        )
    long = Scenario(
        "replicate-53",
        2,
        long_actions,
        (
            (
                (2, RECONFIGURATION, 0, 1),
                (2, SIGNATURE, 0, 0),
            ),
            (),
        ),
        LONG_LENGTHS,
        frozenset({30, 33, 41}),
        37,
    )
    for scenario in (short, long):
        if len(scenario.expected_lengths) != len(scenario.actions) + 1:
            raise PrototypeError(
                f"{scenario.name}: expected-length rows do not match actions"
            )
        for action in scenario.actions:
            if action.kind == "appendEntries" and action.parameter < 1:
                raise PrototypeError(
                    f"{scenario.name}: append action {action.number} reads "
                    "an omitted prefix tag"
                )
    return short, long


def declare_sequence_state(formula: Formula, scenario: Scenario) -> None:
    for step in range(len(scenario.actions) + 1):
        for node in range(scenario.nodes):
            for field in FIELDS:
                formula.add(f"(declare-const {seq(field, step, node)} (Seq Int))")


def initial_constraints(
    formula: Formula,
    scenario: Scenario,
    prefix_length: int,
) -> None:
    for node in range(scenario.nodes):
        for field in FIELDS:
            formula.add(f"(declare-const {prefix(field, node)} (Seq Int))")
            formula.labelled(
                f"initial_n{node}_{field}_length",
                f"(= (seq.len {prefix(field, node)}) {prefix_length})",
            )
        values = {field: prefix(field, node) for field in FIELDS}
        for entry in scenario.initial_suffixes[node]:
            values = {
                field: append_value(values[field], value)
                for field, value in zip(FIELDS, entry, strict=True)
            }
        for field in FIELDS:
            formula.labelled(
                f"initial_n{node}_{field}_value",
                f"(= {seq(field, 0, node)} {values[field]})",
            )


def add_historical_queries(
    formula: Formula,
    action: Action,
    previous_step: int,
) -> None:
    if action.kind not in {
        "advanceCommitIndex",
        "changeConfiguration",
        "signCommittableMessages",
    }:
        return
    node = action.source
    for tag, label in (
        (SIGNATURE, "signature"),
        (RECONFIGURATION, "configuration"),
    ):
        value = f"last_{label}_a{action.number:02d}"
        tags = seq("tag", previous_step, node)
        formula.add(f"(declare-const {value} Int)")
        formula.labelled(
            f"action{action.number:02d}_latest_{label}",
            f"(= {value} (last-tag-index {tags} {tag}))",
        )
        formula.labelled(
            f"action{action.number:02d}_{label}_range",
            f"(and (<= 0 {value}) (<= {value} (seq.len {tags})))",
        )


def transition_constraints(
    formula: Formula,
    scenario: Scenario,
    prefix_length: int,
    include_history_queries: bool,
) -> None:
    queues: dict[tuple[int, int], list[Request]] = {}
    for action in scenario.actions:
        previous_step = action.number - 1
        updates = {
            node: unchanged(previous_step, action.number, node)
            for node in range(scenario.nodes)
        }
        branch_guard: str | None = None
        if include_history_queries:
            add_historical_queries(formula, action, previous_step)

        if action.kind == "clientRequest":
            updates[action.source] = append_entry(
                previous_step,
                action.source,
                (2, TRANSACTION, action.transaction, 0),
            )
        elif action.kind == "signCommittableMessages":
            updates[action.source] = append_entry(
                previous_step,
                action.source,
                (2, SIGNATURE, 0, 0),
            )
        elif action.kind == "changeConfiguration":
            updates[action.source] = append_entry(
                previous_step,
                action.source,
                (2, RECONFIGURATION, 0, 3),
            )
        elif action.kind == "appendEntries":
            batch_end = prefix_length + action.parameter
            heartbeat = action.number in scenario.heartbeat_actions
            previous_index = batch_end if heartbeat else batch_end - 1
            previous_term = (
                "0"
                if previous_index == 0
                else nth(seq("term", previous_step, action.source), previous_index - 1)
            )
            if action.number == scenario.mutation_action:
                previous_term = (
                    f"(ite mutation_wrong_prev_term (+ {previous_term} 1) "
                    f"{previous_term})"
                )
            entry = None
            if not heartbeat:
                entry = tuple(
                    nth(seq(field, previous_step, action.source), batch_end - 1)
                    for field in FIELDS
                )
            queues.setdefault((action.source, action.destination), []).append(
                Request(previous_index, previous_term, entry)
            )
        elif action.kind == "receive":
            pending = queues.get((action.source, action.destination), [])
            if pending:
                request = pending.pop(0)
                updates[action.destination], branch_guard = receive_request(
                    previous_step,
                    action.destination,
                    request,
                )

        for node in range(scenario.nodes):
            for field in FIELDS:
                formula.labelled(
                    f"action{action.number:02d}_n{node}_{field}",
                    f"(= {seq(field, action.number, node)} {updates[node][field]})",
                )
        if branch_guard is not None:
            formula.labelled(
                f"action{action.number:02d}_receive_branch_domain",
                f"(or {branch_guard} (not {branch_guard}))",
            )

        expected = scenario.expected_lengths[action.number]
        for node, offset in enumerate(expected):
            formula.labelled(
                f"observation{action.number:02d}_n{node}_length",
                (
                    f"(= (seq.len {seq('tag', action.number, node)}) "
                    f"{prefix_length + offset})"
                ),
            )


def build_formula(
    scenario: Scenario,
    prefix_length: int,
    include_history_queries: bool,
) -> tuple[str, str, int]:
    formula = Formula()
    formula.add("(set-logic ALL)")
    formula.add("(set-option :produce-unsat-assumptions true)")
    mutation_label = "mutation_wrong_prev_term"
    formula.add(f"(declare-const {mutation_label} Bool)")
    formula.add(
        "(define-fun last-tag-index ((s (Seq Int)) (tag Int)) Int "
        "(let ((distance (seq.indexof (seq.rev s) (seq.unit tag) 0))) "
        "(ite (= distance (- 1)) 0 (- (seq.len s) distance))))"
    )
    declare_sequence_state(formula, scenario)
    initial_constraints(formula, scenario, prefix_length)
    transition_constraints(
        formula,
        scenario,
        prefix_length,
        include_history_queries,
    )

    return (
        formula.text(),
        formula.text((mutation_label,), get_unsat_assumptions=True),
        len(formula.labels),
    )


def parse_solver_output(output: str) -> tuple[str, str]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    statuses = [line for line in lines if line in {"sat", "unsat", "unknown"}]
    if len(statuses) != 1:
        raise PrototypeError(f"unexpected solver statuses: {lines[-10:]}")
    core = lines[-1] if statuses[0] == "unsat" and len(lines) > 1 else ""
    return statuses[0], core


def run_solver(
    cvc5: Path,
    formula: Path,
    maximum_length: int,
    time_limit_ms: int,
    wall_timeout_seconds: int,
) -> tuple[int, str, bool]:
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            [
                str(cvc5),
                "--lang",
                "smt2",
                f"--tlimit-per={time_limit_ms}",
                f"--strings-model-max-len={maximum_length}",
                str(formula),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=wall_timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
        return elapsed_ms, "", True
    elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
    if result.returncode != 0:
        raise PrototypeError(
            f"cvc5 failed for {formula}:\n{result.stdout}\n{result.stderr}"
        )
    return elapsed_ms, result.stdout, False


def percentile_95(values: list[int]) -> int:
    ordered = sorted(values)
    return ordered[max(0, (len(ordered) * 95 + 99) // 100 - 1)]


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
    for scenario in build_scenarios(root):
        for mode, include_history_queries in (
            ("structural", False),
            ("history", True),
        ):
            for prefix_length in prefix_lengths:
                sat_formula_text, mutation_formula_text, labels = build_formula(
                    scenario,
                    prefix_length,
                    include_history_queries,
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
                for _ in range(samples):
                    elapsed_ms, output, timed_out = run_solver(
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
                        sat_status, _ = parse_solver_output(output)
                    elapsed_ms, output, timed_out = run_solver(
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
                        mutation_status, core = parse_solver_output(output)
                row = {
                    "scenario": scenario.name,
                    "backend": "native-sequence",
                    "mode": mode,
                    "actions": len(scenario.actions),
                    "nodes": scenario.nodes,
                    "prefix_length": prefix_length,
                    "formula_bytes": len(sat_formula_text.encode("ascii")),
                    "labels": labels,
                    "samples": samples,
                    "sat_samples_ms": sat_timings,
                    "sat_median_ms": int(statistics.median(sat_timings)),
                    "sat_p95_ms": (percentile_95(sat_timings) if samples > 1 else None),
                    "mutation_samples_ms": mutation_timings,
                    "mutation_median_ms": int(statistics.median(mutation_timings)),
                    "mutation_p95_ms": (
                        percentile_95(mutation_timings) if samples > 1 else None
                    ),
                    "sat": sat_status,
                    "mutation": mutation_status,
                    "core_labels": len(core.strip("()").split()),
                }
                rows.append(row)
                print(
                    f"scenario={scenario.name} mode={mode} prefix={prefix_length} "
                    f"actions={len(scenario.actions)} bytes={row['formula_bytes']} "
                    f"sat_ms={row['sat_median_ms']} sat={sat_status} "
                    f"mutation_ms={row['mutation_median_ms']} "
                    f"mutation={mutation_status}",
                    flush=True,
                )
    result = {
        "schema": "ccfraft-symbolic-sequence-prototype/v1",
        "question": (
            "Can exact symbolic log execution avoid materialising S0 and fixed "
            "log capacities at acceptable cost on the current trace shapes?"
        ),
        "scope": (
            "Log-only prototype. It uses unbounded SMT sequences, fixed trace "
            "branch choices, and trace-specific packet pairing. Unknown entry "
            "fields are unconstrained unless an action reads them. It does not "
            "encode queue state, roles, term-validity invariants, quorums, or "
            "the full CCFRaft state."
        ),
        "cvc5": str(cvc5),
        "samples_per_case": samples,
        "solver_time_limit_ms": time_limit_ms,
        "wall_timeout_seconds": wall_timeout_seconds,
        "rows": rows,
    }
    (output_dir / "benchmark.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def render_report(result: dict[str, object], output: Path) -> None:
    rows = result["rows"]
    assert isinstance(rows, list)
    summary_rows = [
        row
        for row in rows
        if row["backend"] == "symbolic-array" and row["mode"] == "summary-history"
    ]
    structural_rows = [
        row
        for row in rows
        if row["backend"] == "symbolic-array" and row["mode"] == "structural"
    ]
    summary_max = max(
        (int(row["sat_median_ms"]) for row in summary_rows),
        default=None,
    )
    structural_max = max(
        (int(row["sat_median_ms"]) for row in structural_rows),
        default=None,
    )
    summary_display = f"&le; {summary_max} ms" if summary_max is not None else "not run"
    structural_display = (
        f"&le; {structural_max} ms" if structural_max is not None else "not run"
    )
    body_rows = "\n".join(
        (
            f"<tr data-scenario='{html.escape(str(row['scenario']))}'>"
            f"<td>{html.escape(str(row['scenario']))}</td>"
            f"<td>{row['backend']}</td><td>{row['mode']}</td>"
            f"<td>{row['actions']}</td>"
            f"<td>{row['prefix_length']:,}</td>"
            f"<td>{row['formula_bytes']:,}</td><td>{row['samples']}</td>"
            f"<td>{row['sat_median_ms']}</td><td>{row['sat_p95_ms']}</td>"
            f"<td>{row['sat']}</td><td>{row['mutation_median_ms']}</td>"
            f"<td>{row['mutation']}</td></tr>"
        )
        for row in rows
    )
    data = json.dumps(result, sort_keys=True).replace("<", "\\u003c")
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Prototype: symbolic CCFRaft log cost</title>
<style>
body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 1200px; margin: 2rem auto; padding: 0 1rem; color: #172033; }}
h1 {{ margin-bottom: .25rem; }} .warning {{ border-left: 5px solid #b66b00; background: #fff6df; padding: 1rem; }}
button {{ margin-right: .5rem; padding: .5rem .8rem; }} table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ border-bottom: 1px solid #ccd3df; padding: .55rem; text-align: right; }} th:first-child, td:first-child {{ text-align: left; }}
code {{ background: #eef1f5; padding: .1rem .3rem; }} pre {{ background: #101827; color: #d9e2f2; padding: 1rem; overflow: auto; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin: 1.25rem 0; }}
.card {{ border: 1px solid #ccd3df; border-radius: 8px; padding: 1rem; }} .card strong {{ display: block; font-size: 1.6rem; }}
th {{ cursor: pointer; user-select: none; }} th:hover {{ background: #eef1f5; }}
</style>
</head>
<body>
<h1>Prototype: exact symbolic logs without materialising S0</h1>
<p>{html.escape(str(result['question']))}</p>
<div class="warning"><strong>Throwaway benchmark.</strong> {html.escape(str(result['scope']))}</div>
<h2>Verdict</h2>
<div class="cards">
<div class="card"><strong>{structural_display}</strong>Symbolic arrays, structural log operations, up to a 1,000,000-entry unknown prefix.</div>
<div class="card"><strong>{summary_display}</strong>Existential summary history, including the 43-action trace.</div>
<div class="card"><strong>UNKNOWN</strong>General quantified latest-entry scans. cvc5 reports an incomplete theory result.</div>
<div class="card"><strong>10-15 s</strong>Native SMT sequences with large prefixes hit the solver budget or wall timeout.</div>
</div>
<p>The promising shape is a symbolic array plus trace-relative, jointly-realizable history summaries. For these traces, no action point-reads an omitted prefix tag, so a satisfying summary assignment can be repaired into a matching prefix. This condition is checked from the trace shape, but it is not yet a general theorem. Native sequences are a poor fit, and direct quantified array scans do not produce useful SAT answers. The conflict run changes an AppendEntries previous term, so the later receive cannot append the observed entry.</p>
<h2>Measured runs</h2>
<p><button data-filter="all">All</button><button data-filter="signature-commit">Short trace</button><button data-filter="replicate-53">53-event trace</button></p>
<table><thead><tr><th>Trace</th><th>Backend</th><th>Mode</th><th>Actions</th><th>Unknown prefix</th><th>Formula bytes</th><th>Samples</th><th>SAT median ms</th><th>SAT p95 ms</th><th>Base</th><th>Conflict median ms</th><th>Conflict</th></tr></thead>
<tbody>{body_rows}</tbody></table>
<h2>What this exercises</h2>
<p>Each initial log is an unbounded SMT sequence. Actions construct new sequences with <code>seq.++</code>, <code>seq.extract</code>, and <code>seq.nth</code>. Historical signature and configuration lookups use <code>seq.rev</code> plus <code>seq.indexof</code>. The solver never receives explicit cells for the unknown prefix and the benchmark never requests a model.</p>
<p>The symbolic-array backend uses integer-indexed arrays plus a symbolic length. Its summary mode carries latest-signature and latest-configuration positions without scanning the omitted prefix. It is equisatisfiable for the append-only branches exercised here because omitted prefix tags are otherwise unread. Truncating across an omitted summary or reading a prefix tag needs a richer predecessor summary and a checked repair condition. Neither measured trace exercises truncation.</p>
<p>Open the <a href="vscode://vscode-remote/wsl+AzureLinux3.0/home/cjen1-msft/CCF/.worktrees/veil-consistency/lean/CCFRaft/symbolic_sequence_prototype.py:1:1">native sequence prototype</a>, <a href="vscode://vscode-remote/wsl+AzureLinux3.0/home/cjen1-msft/CCF/.worktrees/veil-consistency/lean/CCFRaft/symbolic_array_prototype.py:1:1">symbolic array prototype</a>, or <a href="vscode://vscode-remote/wsl+AzureLinux3.0/home/cjen1-msft/">workspace</a>.</p>
<h2>Full result state</h2>
<pre id="state"></pre>
<script type="application/json" id="result">{data}</script>
<script>
const result = JSON.parse(document.getElementById("result").textContent);
document.getElementById("state").textContent = JSON.stringify(result, null, 2);
for (const button of document.querySelectorAll("button[data-filter]")) {{
  button.addEventListener("click", () => {{
    const selected = button.dataset.filter;
    for (const row of document.querySelectorAll("tbody tr")) {{
      row.hidden = selected !== "all" && row.dataset.scenario !== selected;
    }}
  }});
}}
for (const [index, heading] of [...document.querySelectorAll("th")].entries()) {{
  heading.title = "Sort by this column";
  heading.addEventListener("click", () => {{
    const body = document.querySelector("tbody");
    const rows = [...body.querySelectorAll("tr")];
    const ascending = heading.dataset.order !== "asc";
    for (const other of document.querySelectorAll("th")) delete other.dataset.order;
    heading.dataset.order = ascending ? "asc" : "desc";
    rows.sort((left, right) => {{
      const a = left.children[index].textContent.replaceAll(",", "");
      const b = right.children[index].textContent.replaceAll(",", "");
      const numeric = Number(a) - Number(b);
      const comparison = Number.isNaN(numeric) ? a.localeCompare(b) : numeric;
      return ascending ? comparison : -comparison;
    }});
    for (const row of rows) body.appendChild(row);
  }});
}}
</script>
</body>
</html>
"""
    output.write_text(document, encoding="ascii")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cvc5", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--prefix-lengths", default="0,15123,1000000")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--time-limit-ms", type=int, default=10000)
    parser.add_argument("--wall-timeout-seconds", type=int, default=15)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    prefix_lengths = tuple(int(value) for value in args.prefix_lengths.split(","))
    result = benchmark(
        root,
        args.output_dir,
        args.cvc5,
        prefix_lengths,
        args.samples,
        args.time_limit_ms,
        args.wall_timeout_seconds,
    )
    render_report(result, args.report)
    print(f"report={args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
