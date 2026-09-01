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
retains that order. The encoder therefore models an immediately following
AppendEntries block inside the enclosing configuration transition.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CERTIFICATE_SCHEMA = "ccfraft-reduction-certificate/v1"

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
        lines.append(line)
    _require(lines, f"{label}.provenance must not be empty")
    return min(lines)


def _certificate_trace(
    certificate: Mapping[str, Any],
) -> tuple[Sequence[Any], Sequence[Any]]:
    _require(
        certificate.get("artifact_kind") == "ccfraft_reduction_certificate",
        "unsupported certificate artifact_kind",
    )
    _require(
        certificate.get("schema_version") == CERTIFICATE_SCHEMA,
        "unsupported certificate schema_version",
    )
    reduced = _mapping(certificate.get("reduced_trace"), "reduced_trace")
    entry = _sequence(
        reduced.get("observations_at_entry"),
        "reduced_trace.observations_at_entry",
    )
    steps = _sequence(reduced.get("steps"), "reduced_trace.steps")
    return entry, steps


def _collect_nodes(
    entry_observations: Sequence[Any],
    steps: Sequence[Any],
) -> tuple[str, ...]:
    nodes: set[str] = set()

    def add_observation(value: Any, label: str) -> None:
        observation = _mapping(value, label)
        parameters = _mapping(observation.get("parameters"), f"{label}.parameters")
        if "node" in parameters:
            nodes.add(_node(parameters["node"], f"{label}.parameters.node"))

    for position, observation in enumerate(entry_observations, 1):
        add_observation(observation, f"entry observation {position}")

    for position, step_value in enumerate(steps, 1):
        step = _mapping(step_value, f"step {position}")
        action = _mapping(step.get("action"), f"step {position}.action")
        parameters = _mapping(
            action.get("parameters"),
            f"step {position}.action.parameters",
        )
        for field in ("node", "source", "destination"):
            if field in parameters:
                nodes.add(
                    _node(
                        parameters[field],
                        f"step {position}.action.parameters.{field}",
                    )
                )
        if "newConfiguration" in parameters:
            configuration = _sequence(
                parameters["newConfiguration"],
                f"step {position}.action.parameters.newConfiguration",
            )
            for member_position, member in enumerate(configuration, 1):
                nodes.add(
                    _node(
                        member,
                        "step "
                        f"{position}.action.parameters.newConfiguration"
                        f"[{member_position}]",
                    )
                )
        observations = _sequence(
            step.get("observations_after"),
            f"step {position}.observations_after",
        )
        for observation_position, observation in enumerate(observations, 1):
            add_observation(
                observation,
                f"step {position} observation {observation_position}",
            )

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
    parameters: Mapping[str, Any],
    field: str,
    node_indices: Mapping[str, int],
    label: str,
) -> int:
    _require(field in parameters, f"{label}.parameters.{field} is missing")
    node = _node(parameters[field], f"{label}.parameters.{field}")
    _require(node in node_indices, f"{label} refers to unknown node {node!r}")
    return node_indices[node]


def _transition_expression(
    action: Mapping[str, Any],
    position: int,
    node_indices: Mapping[str, int],
    before: int,
    after: int,
) -> str:
    label = f"action {position}"
    index = action.get("index")
    _require(
        type(index) is int and index == position,
        f"{label}.index must be {position}",
    )
    kind = action.get("kind")
    _require(kind in ACTION_KINDS, f"{label}.kind is unsupported: {kind!r}")
    parameters = _mapping(action.get("parameters"), f"{label}.parameters")
    fields = tuple(FIELD_SORTS)
    constraints: list[str] = []

    if kind in {"clientRequest", "signCommittableMessages"}:
        node = _action_node(parameters, "node", node_indices, label)
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
        source = _action_node(parameters, "source", node_indices, label)
        configuration_values = _sequence(
            parameters.get("newConfiguration"),
            f"{label}.parameters.newConfiguration",
        )
        configuration = {
            _node(value, f"{label}.parameters.newConfiguration")
            for value in configuration_values
        }
        _require(configuration, f"{label}.parameters.newConfiguration is empty")
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
        source = _action_node(parameters, "source", node_indices, label)
        destination = _action_node(
            parameters,
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
        _action_node(parameters, "source", node_indices, label)
        destination = _action_node(
            parameters,
            "destination",
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
        node = _action_node(parameters, "node", node_indices, label)
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
        node = _action_node(parameters, "node", node_indices, label)
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
        _action_node(parameters, "source", node_indices, label)
        destination = _action_node(
            parameters,
            "destination",
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
        node = _action_node(parameters, "node", node_indices, label)
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


def _transition_edges(steps: Sequence[Any]) -> dict[int, tuple[int, int]]:
    edges = {
        position: (position - 1, position) for position in range(1, len(steps) + 1)
    }
    position = 1
    while position <= len(steps):
        step = _mapping(steps[position - 1], f"step {position}")
        action = _mapping(step.get("action"), f"step {position}.action")
        if action.get("kind") != "changeConfiguration":
            position += 1
            continue
        parameters = _mapping(
            action.get("parameters"),
            f"step {position}.action.parameters",
        )
        source = _node(
            parameters.get("source"),
            f"step {position}.action.parameters.source",
        )
        end = position
        while end < len(steps):
            nested_step = _mapping(steps[end], f"step {end + 1}")
            nested_action = _mapping(
                nested_step.get("action"),
                f"step {end + 1}.action",
            )
            if nested_action.get("kind") != "appendEntries":
                break
            nested_parameters = _mapping(
                nested_action.get("parameters"),
                f"step {end + 1}.action.parameters",
            )
            nested_source = _node(
                nested_parameters.get("source"),
                f"step {end + 1}.action.parameters.source",
            )
            if nested_source != source:
                break
            end += 1
        if end > position:
            edges[position] = (position - 1, end)
            for nested_position in range(position + 1, end + 1):
                edges[nested_position] = (
                    nested_position - 2,
                    nested_position - 1,
                )
            position = end + 1
        else:
            position += 1
    return edges


def _observation_expression(
    observation: Mapping[str, Any],
    boundary: int,
    node_indices: Mapping[str, int],
    label: str,
) -> str:
    kind = observation.get("kind")
    _require(
        kind in OBSERVATION_FIELDS,
        f"{label}.kind is unsupported: {kind!r}",
    )
    parameters = _mapping(observation.get("parameters"), f"{label}.parameters")
    node = _node(parameters.get("node"), f"{label}.parameters.node")
    _require(node in node_indices, f"{label} refers to unknown node {node!r}")
    value = parameters.get("value")
    field = OBSERVATION_FIELDS[str(kind)]
    if kind in {"allocated", "joined"}:
        _require(type(value) is bool, f"{label}.parameters.value must be Boolean")
        encoded: int | bool = value
    elif kind == "role":
        _require(value in ROLE_VALUES, f"{label}.parameters.value has unknown role")
        encoded = ROLE_VALUES[str(value)]
    else:
        _require(
            type(value) is int and value >= 0,
            f"{label}.parameters.value must be a natural number",
        )
        encoded = value
    return _eq(_select(field, boundary, node_indices[node]), encoded)


def build_formula(certificate: Mapping[str, Any]) -> SmtFormula:
    """Build a deterministic quantifier-free projected-state formula."""

    entry_observations, steps = _certificate_trace(certificate)
    nodes = _collect_nodes(entry_observations, steps)
    node_indices = {node: index for index, node in enumerate(nodes)}
    lines = [
        "; Generated by Shared/smt.py.",
        "; Projected state only. This is not the Lean-proved full lowering.",
        "(set-logic QF_AUFLIA)",
    ]
    for index, node in enumerate(nodes):
        lines.append(f"; node {index}: {node!r}")
    for field, sort in FIELD_SORTS.items():
        lines.append(f"(declare-const state_base_{field} (Array Int {sort}))")

    for boundary in range(len(steps) + 1):
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

    for boundary in range(len(steps) + 1):
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

    observation_index = 0
    transition_edges = _transition_edges(steps)

    def add_observations(values: Sequence[Any], boundary: int, prefix: str) -> None:
        nonlocal observation_index
        for position, value in enumerate(values, 1):
            observation_index += 1
            label = f"{prefix} observation {position}"
            observation = _mapping(value, label)
            line = _first_line(observation, label)
            kind = observation.get("kind")
            name = (
                f"observation_{observation_index:04d}_line_{line:04d}_"
                f"boundary_{boundary:04d}_{kind}"
            )
            lines.append(
                _named(
                    name,
                    _observation_expression(
                        observation,
                        boundary,
                        node_indices,
                        label,
                    ),
                )
            )

    add_observations(entry_observations, 0, "entry")
    for position, step_value in enumerate(steps, 1):
        step = _mapping(step_value, f"step {position}")
        action = _mapping(step.get("action"), f"step {position}.action")
        line = _first_line(action, f"action {position}")
        kind = action.get("kind")
        before, after = transition_edges[position]
        if (before, after) != (position - 1, position):
            lines.append(
                f"; action {position} uses boundary {before} -> {after} "
                "to retain nested configuration callback order"
            )
        lines.append(
            _named(
                f"transition_action_{position:04d}_line_{line:04d}_{kind}",
                _transition_expression(
                    action,
                    position,
                    node_indices,
                    before,
                    after,
                ),
            )
        )
        observations = _sequence(
            step.get("observations_after"),
            f"step {position}.observations_after",
        )
        add_observations(observations, position, f"step {position}")

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


def write_formula(path: Path, formula: SmtFormula | str) -> None:
    """Write SMT-LIB without changing its deterministic bytes."""

    path.write_text(
        formula.text if isinstance(formula, SmtFormula) else formula,
        encoding="utf-8",
    )
