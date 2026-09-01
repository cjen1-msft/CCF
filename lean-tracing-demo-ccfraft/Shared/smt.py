#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Encode reduced CCFRaft certificates as projected-state SMT.

This backend checks the term, role, log-length, commit-index, allocation, and
joined projections requested by the demo. It deliberately over-approximates
operations such as ``receive``. It is not the Lean-proved full symbolic
lowering in ``MachineGenerated/Lowering.lean``.

CCF may emit ``send_append_entries`` from inside an ``add_configuration``
callback before the enclosing replicate updates ``last_idx``. The reducer
puts those nested sends before the completed configuration action so every
flat action advances exactly one boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import re
import time
from typing import Any, Literal

CERTIFICATE_SCHEMA = "ccfraft-reduction-certificate/v2"

ROLE_VALUES = {
    "none": 0,
    "follower": 1,
    "candidate": 2,
    "leader": 3,
}

FIELD_SORTS = {
    "allocated": "Bool",
    "joined": "Bool",
    "role": "Int",
    "term": "Int",
    "log_length": "Int",
    "commit_index": "Int",
}

OBSERVATION_FIELDS = {
    "allocated": "allocated",
    "joined": "joined",
    "role": "role",
    "currentTerm": "term",
    "logLength": "log_length",
    "commitIndex": "commit_index",
}

ACTION_KINDS = {
    "advanceCommitIndex",
    "appendEntries",
    "becomeLeader",
    "changeConfiguration",
    "clientRequest",
    "receive",
    "requestVote",
    "signCommittableMessages",
    "timeout",
    "updateTerm",
}


class SmtEncodingError(ValueError):
    """Report a certificate shape that this backend cannot encode."""


@dataclass(frozen=True)
class SmtFormula:
    """A deterministic SMT-LIB formula and its node-index assignment."""

    text: str
    nodes: tuple[str, ...]


@dataclass(frozen=True)
class CoreReduction:
    """Result of deterministic, time-bounded UNSAT core shrinking."""

    names: tuple[str, ...]
    checks: int
    complete: bool
    wall_time_ms: float


CoreCheckResult = Literal["unsat", "sat", "inconclusive"]


NAMED_ASSERTION = re.compile(r"^\(assert \(! .+ :named ([^)]+)\)\)$")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SmtEncodingError(message)


def _sequence(value: Any, label: str) -> Sequence[Any]:
    _require(
        isinstance(value, Sequence) and not isinstance(value, (str, bytes)),
        f"{label} must be an array",
    )
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"{label} must be an object")
    return value


def _node(value: Any, label: str) -> str:
    _require(
        (isinstance(value, str) and value != "") or (type(value) is int and value >= 0),
        f"{label} must be a non-empty string or natural number",
    )
    return str(value)


def _node_sort_key(value: str) -> tuple[int, int, str]:
    if value.isdigit():
        return (0, int(value), value)
    return (1, 0, value)


def _first_line(item: Mapping[str, Any], label: str) -> int:
    provenance = _sequence(item.get("provenance"), f"{label}.provenance")
    lines: list[int] = []
    for position, entry_value in enumerate(provenance, 1):
        entry = _mapping(entry_value, f"{label}.provenance[{position}]")
        line = entry.get("line")
        _require(
            type(line) is int and line > 0,
            f"{label}.provenance[{position}].line must be positive",
        )
        _require(
            isinstance(entry.get("timestamp"), str)
            and str(entry["timestamp"]).isdigit(),
            f"{label}.provenance[{position}].timestamp must be decimal",
        )
        _require(
            isinstance(entry.get("function"), str) and bool(entry["function"]),
            f"{label}.provenance[{position}].function is missing",
        )
        lines.append(line)
    _require(lines, f"{label}.provenance must not be empty")
    return min(lines)


def _certificate_trace(
    certificate: Mapping[str, Any],
) -> Sequence[Any]:
    _require(
        certificate.get("artifact_kind") == "ccfraft_reduction_certificate",
        "unsupported certificate artifact_kind",
    )
    _require(
        certificate.get("schema_version") == CERTIFICATE_SCHEMA,
        "unsupported certificate schema_version",
    )
    return _sequence(certificate.get("steps"), "steps")


def _collect_nodes(
    instructions: Sequence[Any],
) -> tuple[str, ...]:
    nodes: set[str] = set()

    for position, value in enumerate(instructions, 1):
        label = f"instruction {position}"
        instruction = _mapping(value, label)
        kind = instruction.get("kind")
        _require(
            kind in {"action", "observation"},
            f"{label}.kind must be action or observation",
        )
        nodes.add(_node(instruction.get("node"), f"{label}.node"))
        if "source" in instruction:
            nodes.add(_node(instruction["source"], f"{label}.source"))
        if "destination" in instruction:
            nodes.add(_node(instruction["destination"], f"{label}.destination"))
        if "configuration" in instruction:
            configuration = _sequence(
                instruction["configuration"],
                f"{label}.configuration",
            )
            for member_position, member in enumerate(configuration, 1):
                nodes.add(
                    _node(
                        member,
                        f"{label}.configuration[{member_position}]",
                    )
                )
        if kind == "observation" and instruction.get("variable") == "firstMessageFrom":
            summary = _mapping(instruction.get("value"), f"{label}.value")
            nodes.add(_node(summary.get("source"), f"{label}.value.source"))

    _require(nodes, "certificate contains no node terms")
    return tuple(sorted(nodes, key=_node_sort_key))


def _state(field: str, boundary: int) -> str:
    return f"state_{boundary:04d}_{field}"


def _cell(field: str, boundary: int, node_index: int) -> str:
    return f"{_state(field, boundary)}_node_{node_index:04d}"


def _select(field: str, boundary: int, node_index: int) -> str:
    return f"(select {_state(field, boundary)} {node_index})"


def _eq(left: str, right: str | int | bool) -> str:
    if isinstance(right, bool):
        encoded = "true" if right else "false"
    else:
        encoded = str(right)
    return f"(= {left} {encoded})"


def _and(expressions: Sequence[str]) -> str:
    if not expressions:
        return "true"
    if len(expressions) == 1:
        return expressions[0]
    return f"(and {' '.join(expressions)})"


def _named(name: str, expression: str) -> str:
    return f"(assert (! {expression} :named {name}))"


def _same_field(
    field: str,
    before: int,
    after: int,
) -> str:
    return _eq(_state(field, after), _state(field, before))


def _frame_fields(
    fields: Sequence[str],
    before: int,
    after: int,
) -> list[str]:
    return [_same_field(field, before, after) for field in fields]


def _store(
    field: str,
    before: int,
    updates: Sequence[tuple[int, str | int | bool]],
) -> str:
    expression = _state(field, before)
    for node_index, value in updates:
        if isinstance(value, bool):
            encoded = "true" if value else "false"
        else:
            encoded = str(value)
        expression = f"(store {expression} {node_index} {encoded})"
    return expression


def _update_array(
    field: str,
    before: int,
    after: int,
    updates: Sequence[tuple[int, str | int | bool]],
) -> str:
    return _eq(_state(field, after), _store(field, before, updates))


def _action_node(
    action: Mapping[str, Any],
    field: str,
    node_indices: Mapping[str, int],
    label: str,
) -> int:
    _require(field in action, f"{label}.{field} is missing")
    node = _node(action[field], f"{label}.{field}")
    _require(node in node_indices, f"{label} refers to unknown node {node!r}")
    return node_indices[node]


def _transition_expression(
    action: Mapping[str, Any],
    position: int,
    node_indices: Mapping[str, int],
    before: int,
    after: int,
) -> str:
    label = f"action boundary {position}"
    _require(action.get("kind") == "action", f"{label}.kind must be action")
    kind = action.get("action")
    _require(kind in ACTION_KINDS, f"{label}.action is unsupported: {kind!r}")
    fields = tuple(FIELD_SORTS)
    constraints: list[str] = []

    if kind in {"clientRequest", "signCommittableMessages"}:
        node = _action_node(action, "node", node_indices, label)
        if kind == "clientRequest":
            _require(
                isinstance(action.get("transaction"), str)
                and bool(action["transaction"]),
                f"{label}.transaction is missing",
            )
        constraints.extend(
            [
                _eq(_select("role", before, node), ROLE_VALUES["leader"]),
                *_frame_fields(
                    tuple(field for field in fields if field != "log_length"),
                    before,
                    after,
                ),
                _update_array(
                    "log_length",
                    before,
                    after,
                    [
                        (
                            node,
                            f"(+ {_select('log_length', before, node)} 1)",
                        )
                    ],
                ),
            ]
        )

    elif kind == "changeConfiguration":
        source = _action_node(action, "node", node_indices, label)
        configuration_values = _sequence(
            action.get("configuration"),
            f"{label}.configuration",
        )
        configuration = {
            _node(value, f"{label}.configuration") for value in configuration_values
        }
        _require(configuration, f"{label}.configuration is empty")
        members = {node_indices[node] for node in configuration}
        constraints.append(_eq(_select("role", before, source), ROLE_VALUES["leader"]))
        constraints.extend(
            [
                *_frame_fields(
                    ("role", "term", "commit_index"),
                    before,
                    after,
                ),
                _update_array(
                    "log_length",
                    before,
                    after,
                    [
                        (
                            source,
                            f"(+ {_select('log_length', before, source)} 1)",
                        )
                    ],
                ),
            ]
        )
        for node_index in node_indices.values():
            allocated_before = _select("allocated", before, node_index)
            allocated_after = _select("allocated", after, node_index)
            joined_before = _select("joined", before, node_index)
            joined_after = _select("joined", after, node_index)
            if node_index not in members:
                constraints.extend(
                    [
                        _eq(allocated_after, allocated_before),
                        _eq(joined_after, joined_before),
                    ]
                )
            else:
                constraints.extend(
                    [
                        f"(=> {allocated_before} {allocated_after})",
                        f"(=> {joined_before} {joined_after})",
                    ]
                )
            constraints.append(_eq(allocated_after, joined_after))

    elif kind in {"appendEntries", "requestVote"}:
        source = _action_node(action, "node", node_indices, label)
        if kind == "appendEntries":
            _natural_value(action.get("batchEnd"), f"{label}.batchEnd")
        destination = _action_node(
            action,
            "destination",
            node_indices,
            label,
        )
        required_role = "leader" if kind == "appendEntries" else "candidate"
        constraints.extend(
            [
                _eq(_select("role", before, source), ROLE_VALUES[required_role]),
                _eq(_select("allocated", before, source), True),
                _eq(_select("allocated", before, destination), True),
            ]
        )
        constraints.extend(_frame_fields(fields, before, after))

    elif kind == "receive":
        _action_node(action, "source", node_indices, label)
        destination = _action_node(
            action,
            "node",
            node_indices,
            label,
        )
        constraints.extend(
            [
                *_frame_fields(
                    ("term", "allocated", "joined"),
                    before,
                    after,
                ),
                *[
                    _update_array(
                        field,
                        before,
                        after,
                        [(destination, _select(field, after, destination))],
                    )
                    for field in ("role", "log_length", "commit_index")
                ],
            ]
        )

    elif kind == "advanceCommitIndex":
        node = _action_node(action, "node", node_indices, label)
        constraints.extend(
            [
                _eq(_select("role", before, node), ROLE_VALUES["leader"]),
                f"(> {_select('commit_index', after, node)} "
                f"{_select('commit_index', before, node)})",
                f"(<= {_select('commit_index', after, node)} "
                f"{_select('log_length', after, node)})",
            ]
        )
        constraints.extend(
            [
                *_frame_fields(
                    tuple(field for field in fields if field != "commit_index"),
                    before,
                    after,
                ),
                _update_array(
                    "commit_index",
                    before,
                    after,
                    [(node, _select("commit_index", after, node))],
                ),
            ]
        )

    elif kind == "timeout":
        node = _action_node(action, "node", node_indices, label)
        role = _select("role", before, node)
        constraints.extend(
            [
                f"(or {_eq(role, ROLE_VALUES['follower'])} "
                f"{_eq(role, ROLE_VALUES['candidate'])})",
                _eq(_select("role", after, node), ROLE_VALUES["candidate"]),
                _eq(
                    _select("term", after, node),
                    f"(+ {_select('term', before, node)} 1)",
                ),
            ]
        )
        constraints.extend(
            [
                *_frame_fields(
                    ("allocated", "joined", "log_length", "commit_index"),
                    before,
                    after,
                ),
                _update_array(
                    "role",
                    before,
                    after,
                    [(node, ROLE_VALUES["candidate"])],
                ),
                _update_array(
                    "term",
                    before,
                    after,
                    [(node, f"(+ {_select('term', before, node)} 1)")],
                ),
            ]
        )

    elif kind == "updateTerm":
        _action_node(action, "source", node_indices, label)
        destination = _action_node(
            action,
            "node",
            node_indices,
            label,
        )
        constraints.extend(
            [
                f"(> {_select('term', after, destination)} "
                f"{_select('term', before, destination)})",
                _eq(
                    _select("role", after, destination),
                    ROLE_VALUES["follower"],
                ),
            ]
        )
        constraints.extend(
            [
                *_frame_fields(
                    ("allocated", "joined", "log_length", "commit_index"),
                    before,
                    after,
                ),
                _update_array(
                    "role",
                    before,
                    after,
                    [(destination, ROLE_VALUES["follower"])],
                ),
                _update_array(
                    "term",
                    before,
                    after,
                    [(destination, _select("term", after, destination))],
                ),
            ]
        )

    elif kind == "becomeLeader":
        node = _action_node(action, "node", node_indices, label)
        constraints.extend(
            [
                _eq(_select("role", before, node), ROLE_VALUES["candidate"]),
                _eq(_select("role", after, node), ROLE_VALUES["leader"]),
                f"(<= {_select('log_length', after, node)} "
                f"{_select('log_length', before, node)})",
            ]
        )
        constraints.extend(
            [
                *_frame_fields(
                    tuple(
                        field for field in fields if field not in {"role", "log_length"}
                    ),
                    before,
                    after,
                ),
                _update_array(
                    "role",
                    before,
                    after,
                    [(node, ROLE_VALUES["leader"])],
                ),
                _update_array(
                    "log_length",
                    before,
                    after,
                    [(node, _select("log_length", after, node))],
                ),
            ]
        )

    else:
        raise AssertionError(f"unhandled action kind {kind}")

    return _and(constraints)


def _natural_value(value: Any, label: str) -> int:
    _require(type(value) is int and value >= 0, f"{label} must be a natural number")
    return value


def _first_message_expression(
    value: Any,
    node_indices: Mapping[str, int],
    label: str,
) -> str:
    summary = _mapping(value, f"{label}.value")
    family = summary.get("messageType")
    extras = {
        "raft_append_entries": {
            "batchEnd",
            "leaderCommitIndex",
            "previousIndex",
        },
        "raft_append_entries_response": {"lastLogIndex", "success"},
        "raft_request_vote": {"lastCommittableIndex"},
        "raft_request_vote_response": {"voteGranted"},
    }
    _require(family in extras, f"{label}.value.messageType is unsupported")
    expected = {
        "batchCount",
        "batchPosition",
        "messageType",
        "source",
        "term",
        *extras[str(family)],
    }
    _require(
        set(summary) == expected,
        f"{label}.value fields do not match {family}",
    )
    source = _node(summary["source"], f"{label}.value.source")
    _require(source in node_indices, f"{label}.value.source is unknown")
    count = _natural_value(summary["batchCount"], f"{label}.value.batchCount")
    position = _natural_value(
        summary["batchPosition"],
        f"{label}.value.batchPosition",
    )
    _require(count > 0, f"{label}.value.batchCount must be positive")
    _require(
        1 <= position <= count,
        f"{label}.value.batchPosition is outside its batch",
    )
    _natural_value(summary["term"], f"{label}.value.term")
    if family == "raft_append_entries":
        _natural_value(summary["batchEnd"], f"{label}.value.batchEnd")
        _natural_value(
            summary["leaderCommitIndex"],
            f"{label}.value.leaderCommitIndex",
        )
        _natural_value(summary["previousIndex"], f"{label}.value.previousIndex")
    elif family == "raft_append_entries_response":
        _natural_value(summary["lastLogIndex"], f"{label}.value.lastLogIndex")
        _require(
            summary["success"] in {"OK", "FAIL"},
            f"{label}.value.success is unsupported",
        )
    elif family == "raft_request_vote":
        _natural_value(
            summary["lastCommittableIndex"],
            f"{label}.value.lastCommittableIndex",
        )
    else:
        _require(
            type(summary["voteGranted"]) is bool,
            f"{label}.value.voteGranted must be Boolean",
        )
    return "true"


def _observation_expression(
    observation: Mapping[str, Any],
    boundary: int,
    node_indices: Mapping[str, int],
    label: str,
) -> str:
    _require(observation.get("kind") == "observation", f"{label}.kind is invalid")
    variable = observation.get("variable")
    if variable == "firstMessageFrom":
        return _first_message_expression(
            observation.get("value"),
            node_indices,
            label,
        )
    _require(
        variable in OBSERVATION_FIELDS,
        f"{label}.variable is unsupported: {variable!r}",
    )
    node = _node(observation.get("node"), f"{label}.node")
    _require(node in node_indices, f"{label} refers to unknown node {node!r}")
    value = observation.get("value")
    field = OBSERVATION_FIELDS[str(variable)]
    if variable in {"allocated", "joined"}:
        _require(type(value) is bool, f"{label}.value must be Boolean")
        encoded: int | bool = value
    elif variable == "role":
        _require(value in ROLE_VALUES, f"{label}.value has unknown role")
        encoded = ROLE_VALUES[str(value)]
    else:
        _natural_value(value, f"{label}.value")
        encoded = value
    return _eq(_select(field, boundary, node_indices[node]), encoded)


def build_formula(certificate: Mapping[str, Any]) -> SmtFormula:
    """Build a deterministic quantifier-free projected-state formula."""

    instructions = _certificate_trace(certificate)
    nodes = _collect_nodes(instructions)
    node_indices = {node: index for index, node in enumerate(nodes)}
    action_count = sum(
        _mapping(value, f"instruction {position}").get("kind") == "action"
        for position, value in enumerate(instructions, 1)
    )
    lines = [
        "; Generated by Shared/smt.py.",
        "; Projected state only. This is not the Lean-proved full lowering.",
        "(set-logic QF_AUFLIA)",
    ]
    for index, node in enumerate(nodes):
        lines.append(f"; node {index}: {node!r}")
    for field, sort in FIELD_SORTS.items():
        lines.append(f"(declare-const state_base_{field} (Array Int {sort}))")

    for boundary in range(action_count + 1):
        for field, sort in FIELD_SORTS.items():
            for node_index in range(len(nodes)):
                lines.append(
                    f"(declare-const {_cell(field, boundary, node_index)} {sort})"
                )
            array = f"state_base_{field}"
            for node_index in range(len(nodes)):
                array = (
                    f"(store {array} {node_index} "
                    f"{_cell(field, boundary, node_index)})"
                )
            lines.append(
                f"(define-fun {_state(field, boundary)} () "
                f"(Array Int {sort}) {array})"
            )

    for boundary in range(action_count + 1):
        for node_index in range(len(nodes)):
            role = _select("role", boundary, node_index)
            domain = _and(
                [
                    f"(and (>= {role} {ROLE_VALUES['none']}) "
                    f"(<= {role} {ROLE_VALUES['leader']}))",
                    f"(>= {_select('term', boundary, node_index)} 0)",
                    f"(>= {_select('log_length', boundary, node_index)} 0)",
                    f"(>= {_select('commit_index', boundary, node_index)} 0)",
                ]
            )
            lines.append(
                _named(
                    f"state_domain_boundary_{boundary:04d}_node_{node_index:04d}",
                    domain,
                )
            )

    for node_index in range(len(nodes)):
        valid_entry = _and(
            [
                _eq(
                    _select("allocated", 0, node_index),
                    _select("joined", 0, node_index),
                ),
                f"(>= {_select('commit_index', 0, node_index)} 0)",
                f"(<= {_select('commit_index', 0, node_index)} "
                f"{_select('log_length', 0, node_index)})",
            ]
        )
        lines.append(_named(f"valid_entry_node_{node_index:04d}", valid_entry))

    boundary = 0
    pending_message: tuple[str, str] | None = None
    for instruction_index, value in enumerate(instructions, 1):
        label = f"instruction {instruction_index}"
        instruction = _mapping(value, label)
        line = _first_line(instruction, label)
        kind = instruction.get("kind")
        if pending_message is not None:
            expected_source, expected_destination = pending_message
            _require(
                kind == "action"
                and instruction.get("action") == "receive"
                and _node(instruction.get("source"), f"{label}.source")
                == expected_source
                and _node(instruction.get("node"), f"{label}.node")
                == expected_destination,
                f"{label} must receive the preceding firstMessageFrom evidence",
            )
            pending_message = None
        elif kind == "action" and instruction.get("action") == "receive":
            raise SmtEncodingError(
                f"{label} receive has no preceding firstMessageFrom evidence"
            )
        if kind == "observation":
            variable = instruction.get("variable")
            if variable == "firstMessageFrom":
                summary = _mapping(instruction.get("value"), f"{label}.value")
                pending_message = (
                    _node(summary.get("source"), f"{label}.value.source"),
                    _node(instruction.get("node"), f"{label}.node"),
                )
                lines.append(
                    f"; {label} validates firstMessageFrom evidence; "
                    "queue selection is an unencoded projection constraint"
                )
                name = (
                    f"evidence_instruction_{instruction_index:04d}_"
                    f"action_boundary_{boundary:04d}_line_{line:04d}_"
                    "firstMessageFrom_unencoded_projection"
                )
            else:
                name = (
                    f"observation_instruction_{instruction_index:04d}_"
                    f"action_boundary_{boundary:04d}_line_{line:04d}_{variable}"
                )
            lines.append(
                _named(
                    name,
                    _observation_expression(
                        instruction,
                        boundary,
                        node_indices,
                        label,
                    ),
                )
            )
            continue
        _require(kind == "action", f"{label}.kind must be action or observation")
        before = boundary
        boundary += 1
        action = instruction.get("action")
        lines.append(
            _named(
                f"transition_instruction_{instruction_index:04d}_"
                f"action_boundary_{boundary:04d}_line_{line:04d}_{action}",
                _transition_expression(
                    instruction,
                    boundary,
                    node_indices,
                    before,
                    boundary,
                ),
            )
        )
    _require(pending_message is None, "final firstMessageFrom has no receive action")
    _require(boundary == action_count, "action boundary count is inconsistent")

    lines.extend(["(check-sat)", ""])
    return SmtFormula("\n".join(lines), nodes)


def add_query(formula: str, query: str) -> str:
    """Append one post-check query to a generated formula."""

    _require(query in {"get-unsat-core", "get-proof"}, "unsupported SMT query")
    _require(formula.endswith("(check-sat)\n"), "formula has no final check-sat")
    options = (
        [
            "(set-option :produce-unsat-cores true)",
            "(set-option :check-unsat-cores true)",
        ]
        if query == "get-unsat-core"
        else [
            "(set-option :produce-proofs true)",
            "(set-option :check-proofs true)",
        ]
    )
    lines = formula.splitlines()
    logic_position = lines.index("(set-logic QF_AUFLIA)")
    lines[logic_position + 1 : logic_position + 1] = options
    return "\n".join(lines) + f"\n({query})\n"


def parse_unsat_core(payload: str) -> tuple[str, ...]:
    """Parse the symbols returned by one `get-unsat-core` query."""

    stripped = payload.strip()
    _require(
        stripped.startswith("(") and stripped.endswith(")"),
        "unsat core is not an SMT symbol list",
    )
    names = tuple(stripped[1:-1].split())
    _require(names, "unsat core is empty")
    _require(len(names) == len(set(names)), "unsat core contains duplicates")
    return names


def restrict_to_assertions(formula: str, names: Sequence[str]) -> str:
    """Keep declarations and only the named assertions selected by a core."""

    selected = set(names)
    _require(len(selected) == len(names), "selected assertions contain duplicates")
    available: set[str] = set()
    output: list[str] = []
    for line in formula.splitlines():
        match = NAMED_ASSERTION.fullmatch(line)
        if match is None:
            output.append(line)
            continue
        name = match.group(1)
        available.add(name)
        if name in selected:
            output.append(line)
    missing = selected.difference(available)
    _require(not missing, f"unsat core names unknown assertions: {sorted(missing)}")
    return "\n".join(output) + "\n"


def reduce_unsat_core(
    names: Sequence[str],
    check: Callable[[tuple[str, ...], float], CoreCheckResult],
    *,
    budget_seconds: float,
) -> CoreReduction:
    """Shrink an UNSAT core with chunk removal followed by a greedy pass."""

    _require(budget_seconds > 0, "core reduction budget must be positive")
    current = tuple(names)
    _require(current, "cannot reduce an empty core")
    started = time.monotonic()
    deadline = started + budget_seconds
    checks = 0

    def within_budget() -> bool:
        return time.monotonic() < deadline

    def check_candidate(candidate: tuple[str, ...]) -> CoreCheckResult:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "inconclusive"
        result = check(candidate, remaining)
        _require(
            result in {"unsat", "sat", "inconclusive"},
            f"invalid core check result: {result}",
        )
        return result

    granularity = 2
    complete = True
    while len(current) >= 2:
        if not within_budget():
            complete = False
            break
        chunk_size = max(1, (len(current) + granularity - 1) // granularity)
        removed_chunk = False
        for start in range(0, len(current), chunk_size):
            if not within_budget():
                complete = False
                break
            candidate = current[:start] + current[start + chunk_size :]
            if not candidate:
                continue
            checks += 1
            result = check_candidate(candidate)
            if result == "inconclusive":
                complete = False
                break
            if result == "unsat":
                current = candidate
                granularity = max(2, granularity - 1)
                removed_chunk = True
                break
        if not complete:
            break
        if removed_chunk:
            continue
        if granularity >= len(current):
            break
        granularity = min(len(current), granularity * 2)

    if complete:
        position = 0
        while position < len(current):
            if not within_budget():
                complete = False
                break
            candidate = current[:position] + current[position + 1 :]
            if not candidate:
                position += 1
                continue
            checks += 1
            result = check_candidate(candidate)
            if result == "inconclusive":
                complete = False
                break
            if result == "unsat":
                current = candidate
            else:
                position += 1

    return CoreReduction(
        names=current,
        checks=checks,
        complete=complete,
        wall_time_ms=(time.monotonic() - started) * 1000,
    )


def write_formula(path: Path, formula: SmtFormula | str) -> None:
    """Write SMT-LIB without changing its deterministic bytes."""

    path.write_text(
        formula.text if isinstance(formula, SmtFormula) else formula,
        encoding="utf-8",
    )
