#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate and decode the naive bounded full-state CCF Raft SMT prototype."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

CERTIFICATE_SCHEMA = "ccfraft-proposed-deterministic-mapping/v2"
ENCODING_SCHEMA = "ccfraft-naive-full-state-smt/v1"
WITNESS_SCHEMA = "ccfraft-naive-full-state-smt-witness/v1"
EXPECTED_EVENTS = 53
EXPECTED_REDUCTIONS = 22
EXPECTED_ACTIONS = 43
TX_COUNT = 64

ROLE_NONE = 0
ROLE_FOLLOWER = 1
ROLE_CANDIDATE = 2
ROLE_LEADER = 3
ROLE_NAMES = ("none", "follower", "candidate", "leader")

ENTRY_UNUSED = 0
ENTRY_TRANSACTION = 1
ENTRY_SIGNATURE = 2
ENTRY_RECONFIGURATION = 3
ENTRY_NAMES = ("unused", "transaction", "signature", "reconfiguration")

MESSAGE_UNUSED = 0
MESSAGE_APPEND_REQUEST = 1
MESSAGE_APPEND_RESPONSE = 2
MESSAGE_VOTE_REQUEST = 3
MESSAGE_VOTE_RESPONSE = 4
MESSAGE_NAMES = (
    "unused",
    "appendEntriesRequest",
    "appendEntriesResponse",
    "requestVoteRequest",
    "requestVoteResponse",
)

ACTION_KINDS = {
    "clientRequest": 1,
    "changeConfiguration": 2,
    "signCommittableMessages": 3,
    "appendEntries": 4,
    "receive": 5,
    "advanceCommitIndex": 6,
    "timeout": 7,
    "requestVote": 8,
    "updateTerm": 9,
    "becomeLeader": 10,
}
ACTION_KIND_NAMES = {value: key for key, value in ACTION_KINDS.items()}

STATE_FIELDS: dict[str, str] = {
    "role": "Int",
    "term": "Int",
    "log_len": "Int",
    "commit": "Int",
    "is_new_follower": "Bool",
    "voted_for_has": "Bool",
    "voted_for_value": "Int",
    "votes_granted": "Bool",
    "sent_index": "Int",
    "match_index": "Int",
    "log_term": "Int",
    "log_tag": "Int",
    "log_tx": "Int",
    "log_config": "Bool",
    "queue_len": "Int",
    "queue_tag": "Int",
    "queue_source": "Int",
    "queue_destination": "Int",
    "queue_term": "Int",
    "queue_prev_log_index": "Int",
    "queue_prev_log_term": "Int",
    "queue_leader_commit": "Int",
    "queue_entry_present": "Bool",
    "queue_entry_term": "Int",
    "queue_entry_tag": "Int",
    "queue_entry_tx": "Int",
    "queue_entry_config": "Bool",
    "queue_response_success": "Bool",
    "queue_response_last_log_index": "Int",
    "queue_vote_last_term": "Int",
    "queue_vote_last_index": "Int",
    "queue_vote_granted": "Bool",
    "submitted": "Bool",
    "has_joined": "Bool",
}

NODE_FIELDS = (
    "role",
    "term",
    "log_len",
    "commit",
    "is_new_follower",
    "voted_for_has",
    "voted_for_value",
)
PAIR_FIELDS = ("votes_granted", "sent_index", "match_index")
LOG_FIELDS = ("log_term", "log_tag", "log_tx")
QUEUE_SLOT_FIELDS = (
    "queue_tag",
    "queue_source",
    "queue_destination",
    "queue_term",
    "queue_prev_log_index",
    "queue_prev_log_term",
    "queue_leader_commit",
    "queue_entry_present",
    "queue_entry_term",
    "queue_entry_tag",
    "queue_entry_tx",
    "queue_response_success",
    "queue_response_last_log_index",
    "queue_vote_last_term",
    "queue_vote_last_index",
    "queue_vote_granted",
)

QUEUE_DEFAULTS: dict[str, str] = {
    "queue_tag": "0",
    "queue_source": "0",
    "queue_destination": "0",
    "queue_term": "0",
    "queue_prev_log_index": "0",
    "queue_prev_log_term": "0",
    "queue_leader_commit": "0",
    "queue_entry_present": "false",
    "queue_entry_term": "0",
    "queue_entry_tag": "0",
    "queue_entry_tx": "0",
    "queue_response_success": "false",
    "queue_response_last_log_index": "0",
    "queue_vote_last_term": "0",
    "queue_vote_last_index": "0",
    "queue_vote_granted": "false",
}


class EncodingError(RuntimeError):
    """Report malformed input, encoding, solver output, or witness data."""


def require(condition: bool, message: str) -> None:
    """Raise an encoding error when a required condition is false."""

    if not condition:
        raise EncodingError(message)


def sha256_bytes(value: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash a file exactly as stored."""

    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: Any) -> None:
    """Write stable JSON."""

    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def smt_and(expressions: Sequence[str]) -> str:
    """Build a compact SMT conjunction."""

    if not expressions:
        return "true"
    if len(expressions) == 1:
        return expressions[0]
    return f"(and {' '.join(expressions)})"


def smt_or(expressions: Sequence[str]) -> str:
    """Build a compact SMT disjunction."""

    if not expressions:
        return "false"
    if len(expressions) == 1:
        return expressions[0]
    return f"(or {' '.join(expressions)})"


def smt_not(expression: str) -> str:
    """Build an SMT negation."""

    return f"(not {expression})"


def smt_eq(left: str, right: str | int | bool) -> str:
    """Build an SMT equality with a Python scalar on either side."""

    if isinstance(right, bool):
        encoded = "true" if right else "false"
    else:
        encoded = str(right)
    return f"(= {left} {encoded})"


def smt_max(left: str, right: str) -> str:
    """Build an integer maximum without an uninterpreted helper."""

    return f"(ite (>= {left} {right}) {left} {right})"


def state_name(field: str, step: int) -> str:
    """Return one state-array symbol."""

    return f"s{step:02d}_{field}"


def select(field: str, step: int, index: str | int) -> str:
    """Read one state-array element."""

    return f"(select {state_name(field, step)} {index})"


def node_pair(node: str | int, peer: str | int, node_count: int) -> str:
    """Flatten a node-by-node table index."""

    return f"(+ (* {node} {node_count}) {peer})"


def log_slot(node: str | int, absolute_index: str | int, log_capacity: int) -> str:
    """Flatten a one-based log index."""

    return f"(+ (* {node} {log_capacity}) (- {absolute_index} 1))"


def log_config_slot(
    node: str | int,
    absolute_index: str | int,
    member: str | int,
    node_count: int,
    log_capacity: int,
) -> str:
    """Flatten log entry configuration membership."""

    return (
        f"(+ (* {log_slot(node, absolute_index, log_capacity)} {node_count}) "
        f"{member})"
    )


def queue_slot(destination: str | int, slot: str | int, queue_capacity: int) -> str:
    """Flatten a destination FIFO slot."""

    return f"(+ (* {destination} {queue_capacity}) {slot})"


def queue_config_slot(
    destination: str | int,
    slot: str | int,
    member: str | int,
    node_count: int,
    queue_capacity: int,
) -> str:
    """Flatten queued entry configuration membership."""

    return (
        f"(+ (* {queue_slot(destination, slot, queue_capacity)} {node_count}) "
        f"{member})"
    )


def store(array: str, index: str | int, value: str | int | bool) -> str:
    """Build an SMT array store."""

    if isinstance(value, bool):
        encoded = "true" if value else "false"
    else:
        encoded = str(value)
    return f"(store {array} {index} {encoded})"


def store_many(
    array: str, changes: Sequence[tuple[str | int, str | int | bool]]
) -> str:
    """Build a deterministic nested store chain."""

    result = array
    for index, value in changes:
        result = store(result, index, value)
    return result


@dataclass(frozen=True)
class Certificate:
    """Validated certificate data used by the encoding."""

    path: Path
    data: dict[str, Any]
    events: dict[int, dict[str, Any]]
    observations: dict[int, dict[str, Any]]
    actions: list[dict[str, Any]]
    action_reductions: dict[int, dict[str, Any]]
    node_count: int
    log_capacity: int
    queue_capacity: int
    max_term: int


def load_certificate(path: Path) -> Certificate:
    """Load and validate the reducer certificate contract."""

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise EncodingError(f"certificate JSON is invalid: {error}") from error
    require(isinstance(data, dict), "certificate top level is not an object")
    require(
        data.get("schema_version") == CERTIFICATE_SCHEMA,
        "corrected v2 certificate schema is absent or unsupported",
    )
    require(
        data.get("artifact_kind") == "proposed_deterministic_mapping_certificate",
        "corrected certificate artifact kind is absent or unsupported",
    )
    counts = data.get("counts")
    capacities = data.get("capacities")
    reductions = data.get("reductions")
    raw_events = data.get("raw_events")
    require(isinstance(counts, dict), "certificate counts are absent")
    require(isinstance(capacities, dict), "certificate capacities are absent")
    require(isinstance(reductions, list), "certificate reductions are absent")
    require(isinstance(raw_events, list), "certificate raw events are absent")
    expected_counts = {
        "actions": EXPECTED_ACTIONS,
        "consumed_events": EXPECTED_EVENTS,
        "events": EXPECTED_EVENTS,
        "observations": EXPECTED_EVENTS,
        "reductions": EXPECTED_REDUCTIONS,
        "action_span_observations": 6,
        "action_checkpoint_observations": 47,
    }
    require(
        counts == expected_counts,
        f"unexpected certificate counts: {counts}",
    )
    require(len(reductions) == EXPECTED_REDUCTIONS, "wrong reduction count")
    require(len(raw_events) == EXPECTED_EVENTS, "wrong raw event count")

    events: dict[int, dict[str, Any]] = {}
    for retained in raw_events:
        require(isinstance(retained, dict), "raw event record is not an object")
        number = retained.get("event")
        raw = retained.get("raw")
        require(isinstance(number, int), "raw event number is absent")
        require(isinstance(raw, str), f"event {number}: raw text is absent")
        require(
            retained.get("sha256") == sha256_bytes(raw.encode("utf-8")),
            f"event {number}: retained hash differs",
        )
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as error:
            raise EncodingError(f"event {number}: raw JSON is invalid") from error
        require(isinstance(row, dict), f"event {number}: raw JSON is not an object")
        events[number] = row
    require(
        sorted(events) == list(range(1, EXPECTED_EVENTS + 1)),
        "raw events are not numbered 1..53",
    )

    observations: dict[int, dict[str, Any]] = {}
    actions: list[dict[str, Any]] = []
    action_reductions: dict[int, dict[str, Any]] = {}
    consumed: list[int] = []
    for reduction in reductions:
        require(isinstance(reduction, dict), "reduction is not an object")
        consumed.extend(reduction.get("events", []))
        for action in reduction.get("actions", []):
            require(isinstance(action, dict), "action is not an object")
            actions.append(action)
            action_reductions[action["action"]] = reduction
        for observation in reduction.get("observations", []):
            require(isinstance(observation, dict), "observation is not an object")
            observations[observation["event"]] = observation
    require(
        consumed == list(range(1, EXPECTED_EVENTS + 1)),
        "reductions do not consume events 1..53 once in order",
    )
    require(
        [action.get("action") for action in actions]
        == list(range(1, EXPECTED_ACTIONS + 1)),
        "actions are not numbered 1..43",
    )
    require(
        sorted(observations) == list(range(1, EXPECTED_EVENTS + 1)),
        "observations do not cover events 1..53",
    )
    require(
        {
            number
            for number, observation in observations.items()
            if observation.get("position", {}).get("kind") == "action_span"
        }
        == {9, 11, 20, 25, 26, 31},
        "corrected action-span observations are absent or changed",
    )
    for number, observation in observations.items():
        decisions = observation.get("field_decisions")
        require(
            isinstance(decisions, list) and decisions,
            f"event {number}: field decisions are absent",
        )
        require(
            all(
                isinstance(decision, dict)
                and decision.get("status") in {"projected", "omitted"}
                and isinstance(decision.get("path"), str)
                and isinstance(decision.get("reason"), str)
                and isinstance(decision.get("field_kind"), str)
                and isinstance(decision.get("field_position"), dict)
                for decision in decisions
            ),
            f"event {number}: field decisions lack explicit kind/position metadata",
        )
        require(
            all(
                decision["field_position"].get("kind") != "input_event"
                for decision in decisions
                if decision["status"] == "projected"
            ),
            f"event {number}: a projected field is positioned only at the input event",
        )
    event8_sent = [
        decision
        for decision in observations[8]["field_decisions"]
        if decision["path"] == "msg.sent_idx"
    ]
    require(
        len(event8_sent) == 1
        and event8_sent[0]["status"] == "omitted"
        and event8_sent[0]["reason"] == "event8-sent-index-translation"
        and event8_sent[0]["field_position"].get("kind") == "input_event",
        "event 8 sent_idx is not the explicit omission/translation",
    )

    node_count = capacities.get("node_world_capacity")
    log_capacity = capacities.get("max_absolute_log_index")
    max_lane = capacities.get("max_per_source_destination_lane")
    lanes = capacities.get("network_lanes")
    require(node_count == 15, f"unexpected node capacity {node_count}")
    require(log_capacity == 7, f"unexpected log capacity {log_capacity}")
    require(max_lane == 4, f"unexpected lane capacity {max_lane}")
    require(
        capacities.get("distinct_configuration_value_count") == 2
        and capacities.get("physical_configuration_record_capacity") == 3
        and capacities.get("configuration_record_indices") == [0, 1, 3]
        and capacities.get("max_active_configuration_history_length") == 2,
        "corrected configuration value/history capacities are absent",
    )
    require(isinstance(lanes, list) and lanes, "network lane metadata is absent")
    destination_totals: dict[int, int] = {}
    for lane in lanes:
        require(isinstance(lane, dict), "network lane metadata is malformed")
        destination = lane.get("destination")
        maximum = lane.get("maximum_occupancy")
        require(
            isinstance(destination, int) and isinstance(maximum, int),
            "network lane capacity is malformed",
        )
        destination_totals[destination] = (
            destination_totals.get(destination, 0) + maximum
        )
    queue_capacity = max(max_lane, max(destination_totals.values()))

    max_term = max(
        int(events[number]["msg"]["state"]["current_view"]) for number in events
    )
    require(max_term == 2, f"unexpected observed maximum term {max_term}")
    return Certificate(
        path=path,
        data=data,
        events=events,
        observations=observations,
        actions=actions,
        action_reductions=action_reductions,
        node_count=node_count,
        log_capacity=log_capacity,
        queue_capacity=queue_capacity,
        max_term=max_term,
    )


@dataclass
class Encoding:
    """Generated formula plus deterministic decoder metadata."""

    text: str
    labels: dict[str, str]
    query_aliases: list[str]
    observation_provenance: list[dict[str, Any]]
    dimensions: dict[str, int]
    mutation: str


class SmtBuilder:
    """Accumulate declarations, labelled constraints, and witness aliases."""

    def __init__(self) -> None:
        self.declarations: list[str] = []
        self.assertions: list[str] = []
        self.assumptions: list[str] = []
        self.labels: dict[str, str] = {}
        self.aliases: list[str] = []
        self.alias_definitions: list[str] = []

    def declare(self, declaration: str) -> None:
        """Append one declaration."""

        self.declarations.append(declaration)

    def labelled(self, label: str, description: str, expression: str) -> None:
        """Guard an assertion with a unique assumption label."""

        require(re.fullmatch(r"[A-Za-z0-9_]+", label) is not None, f"bad label {label}")
        require(label not in self.labels, f"duplicate SMT label {label}")
        self.labels[label] = description
        self.assumptions.append(label)
        self.declarations.append(f"(declare-const {label} Bool)")
        self.assertions.append(f"(assert (=> {label} {expression}))")

    def alias(self, name: str, sort: str, expression: str) -> None:
        """Define and request one atom-valued witness expression."""

        require(re.fullmatch(r"[A-Za-z0-9_]+", name) is not None, f"bad alias {name}")
        require(name not in self.aliases, f"duplicate witness alias {name}")
        self.aliases.append(name)
        self.alias_definitions.append(f"(define-fun {name} () {sort} {expression})")


def action_symbol(field: str, action: int) -> str:
    """Return one action field symbol."""

    return f"a{action:02d}_{field}"


def action_config(action: int, member: int) -> str:
    """Read one action configuration bit."""

    return f"(select {action_symbol('configuration', action)} {member})"


def action_parameters(action: Mapping[str, Any]) -> tuple[int, int, int, str]:
    """Return source, destination, bounded integer parameter, and transaction form."""

    kind = action["kind"]
    parameters = action["parameters"]
    if kind == "clientRequest":
        return parameters["node"], 0, 0, "fresh_tx"
    if kind == "changeConfiguration":
        return parameters["source"], 0, 0, "0"
    if kind == "signCommittableMessages":
        return parameters["node"], 0, 0, "0"
    if kind in {"appendEntries", "receive", "updateTerm", "requestVote"}:
        return (
            parameters["source"],
            parameters["destination"],
            parameters.get("batch_end", 0),
            "0",
        )
    if kind in {"advanceCommitIndex", "timeout", "becomeLeader"}:
        return parameters["node"], 0, 0, "0"
    raise EncodingError(f"unsupported action kind {kind}")


def declare_states(builder: SmtBuilder, action_count: int) -> None:
    """Declare all complete state arrays."""

    for step in range(action_count + 1):
        for field, element_sort in STATE_FIELDS.items():
            builder.declare(
                f"(declare-const {state_name(field, step)} (Array Int {element_sort}))"
            )


def declare_actions(
    builder: SmtBuilder, certificate: Certificate, mutation: str
) -> None:
    """Declare, bound, and fix the certificate action skeleton."""

    builder.declare("(declare-const fresh_tx Int)")
    builder.labelled(
        "fresh_transaction_domain",
        "the only unknown client transaction is in the full Simulation Fin 64 domain",
        f"(and (>= fresh_tx 0) (< fresh_tx {TX_COUNT}))",
    )
    for action in certificate.actions:
        number = action["action"]
        for field in ("kind", "source", "destination", "parameter", "transaction"):
            builder.declare(f"(declare-const {action_symbol(field, number)} Int)")
        builder.declare(
            f"(declare-const {action_symbol('configuration', number)} "
            "(Array Int Bool))"
        )
        builder.labelled(
            f"action{number:02d}_domain",
            f"action {number} has bounded node, index, transaction, and configuration parameters",
            smt_and(
                [
                    f"(and (>= {action_symbol('kind', number)} 1) "
                    f"(<= {action_symbol('kind', number)} 10))",
                    f"(and (>= {action_symbol('source', number)} 0) "
                    f"(< {action_symbol('source', number)} {certificate.node_count}))",
                    f"(and (>= {action_symbol('destination', number)} 0) "
                    f"(< {action_symbol('destination', number)} {certificate.node_count}))",
                    f"(and (>= {action_symbol('parameter', number)} 0) "
                    f"(<= {action_symbol('parameter', number)} {certificate.log_capacity}))",
                    f"(and (>= {action_symbol('transaction', number)} 0) "
                    f"(< {action_symbol('transaction', number)} {TX_COUNT}))",
                ]
            ),
        )
        source, destination, parameter, transaction = action_parameters(action)
        if mutation == "wrong-destination-action-param" and number == 3:
            destination = 2
        configuration = set(action["parameters"].get("new_configuration", []))
        fixed = [
            smt_eq(action_symbol("kind", number), ACTION_KINDS[action["kind"]]),
            smt_eq(action_symbol("source", number), source),
            smt_eq(action_symbol("destination", number), destination),
            smt_eq(action_symbol("parameter", number), parameter),
            smt_eq(action_symbol("transaction", number), transaction),
        ]
        fixed.extend(
            smt_eq(action_config(number, member), member in configuration)
            for member in range(certificate.node_count)
        )
        builder.labelled(
            f"action{number:02d}_certificate_skeleton",
            f"certificate fixes action {number} as {action['template']}",
            smt_and(fixed),
        )


def entry_equal(
    step: int,
    left_node: int,
    right_node: int,
    index: int,
    certificate: Certificate,
) -> str:
    """Compare complete log entries at one absolute index."""

    left = log_slot(left_node, index, certificate.log_capacity)
    right = log_slot(right_node, index, certificate.log_capacity)
    comparisons = [
        smt_eq(select(field, step, left), select(field, step, right))
        for field in LOG_FIELDS
    ]
    comparisons.extend(
        smt_eq(
            select(
                "log_config",
                step,
                log_config_slot(
                    left_node,
                    index,
                    member,
                    certificate.node_count,
                    certificate.log_capacity,
                ),
            ),
            select(
                "log_config",
                step,
                log_config_slot(
                    right_node,
                    index,
                    member,
                    certificate.node_count,
                    certificate.log_capacity,
                ),
            ),
        )
        for member in range(certificate.node_count)
    )
    return smt_and(comparisons)


def current_configuration_expressions(
    step: int, node: int, certificate: Certificate
) -> tuple[str, list[str]]:
    """Derive current configuration index and membership with nested ITEs."""

    current_index = "0"
    current_members = ["true" if member == 0 else "false" for member in range(15)]
    log_length = select("log_len", step, node)
    commit = select("commit", step, node)
    for index in range(1, certificate.log_capacity + 1):
        slot = log_slot(node, index, certificate.log_capacity)
        eligible = smt_and(
            [
                f"(<= {index} {log_length})",
                f"(<= {index} {commit})",
                smt_eq(select("log_tag", step, slot), ENTRY_RECONFIGURATION),
            ]
        )
        current_index = f"(ite {eligible} {index} {current_index})"
        for member in range(certificate.node_count):
            membership = select(
                "log_config",
                step,
                log_config_slot(
                    node,
                    index,
                    member,
                    certificate.node_count,
                    certificate.log_capacity,
                ),
            )
            current_members[member] = (
                f"(ite {eligible} {membership} {current_members[member]})"
            )
    return current_index, current_members


def state_structural_constraints(
    step: int, certificate: Certificate, full_world: bool
) -> tuple[list[str], list[str], list[str]]:
    """Build finite-domain, encoded stateChecks, and relevant pair constraints."""

    domain: list[str] = []
    state_checks: list[str] = []
    relevant_pairs: list[str] = []
    node_count = certificate.node_count
    log_capacity = certificate.log_capacity
    queue_capacity = certificate.queue_capacity
    checked_nodes = range(node_count) if full_world else (0, 1)
    checked_destinations = range(node_count) if full_world else (0, 1)

    for node in checked_nodes:
        role = select("role", step, node)
        term = select("term", step, node)
        log_length = select("log_len", step, node)
        commit = select("commit", step, node)
        domain.extend(
            [
                f"(and (>= {role} {ROLE_NONE}) (<= {role} {ROLE_LEADER}))",
                f"(and (>= {term} 0) (<= {term} {certificate.max_term}))",
                f"(and (>= {log_length} 0) (<= {log_length} {log_capacity}))",
                f"(and (>= {commit} 0) (<= {commit} {log_capacity}))",
                f"(=> (not {select('voted_for_has', step, node)}) "
                f"(= {select('voted_for_value', step, node)} 0))",
                f"(and (>= {select('voted_for_value', step, node)} 0) "
                f"(< {select('voted_for_value', step, node)} {node_count}))",
            ]
        )
        state_checks.append(f"(<= {commit} {log_length})")

        for peer in range(node_count):
            pair = node_pair(node, peer, node_count)
            sent = select("sent_index", step, pair)
            matched = select("match_index", step, pair)
            domain.extend(
                [
                    f"(and (>= {sent} 0) (<= {sent} {log_capacity}))",
                    f"(and (>= {matched} 0) (<= {matched} {log_capacity}))",
                    f"(<= {sent} {log_length})",
                    f"(<= {matched} {log_length})",
                ]
            )

        previous_term = "0"
        for index in range(1, log_capacity + 1):
            slot = log_slot(node, index, log_capacity)
            active = f"(<= {index} {log_length})"
            inactive = smt_not(active)
            entry_term = select("log_term", step, slot)
            entry_tag = select("log_tag", step, slot)
            entry_tx = select("log_tx", step, slot)
            config_bits = [
                select(
                    "log_config",
                    step,
                    log_config_slot(
                        node,
                        index,
                        member,
                        node_count,
                        log_capacity,
                    ),
                )
                for member in range(node_count)
            ]
            config_clear = [smt_not(bit) for bit in config_bits]
            domain.extend(
                [
                    f"(=> {active} (and (>= {entry_term} 1) "
                    f"(<= {entry_term} {certificate.max_term})))",
                    f"(=> {active} (and (>= {entry_tag} {ENTRY_TRANSACTION}) "
                    f"(<= {entry_tag} {ENTRY_RECONFIGURATION})))",
                    f"(=> {active} (and (>= {entry_tx} 0) (< {entry_tx} {TX_COUNT})))",
                    f"(=> {inactive} {smt_and([smt_eq(entry_term, 0), smt_eq(entry_tag, 0), smt_eq(entry_tx, 0), *config_clear])})",
                    f"(=> (and {active} (not (= {entry_tag} {ENTRY_TRANSACTION}))) "
                    f"(= {entry_tx} 0))",
                    f"(=> (and {active} (not (= {entry_tag} {ENTRY_RECONFIGURATION}))) "
                    f"{smt_and(config_clear)})",
                    f"(=> (and {active} (= {entry_tag} {ENTRY_RECONFIGURATION})) "
                    f"{smt_or(config_bits)})",
                ]
            )
            state_checks.extend(
                [
                    f"(=> {active} (<= {entry_term} {term}))",
                    f"(=> {active} (<= {previous_term} {entry_term}))",
                ]
            )
            previous_term = entry_term

        committed_signature_cases = []
        for index in range(1, log_capacity + 1):
            slot = log_slot(node, index, log_capacity)
            committed_signature_cases.append(
                smt_and(
                    [
                        smt_eq(commit, index),
                        smt_eq(select("log_tag", step, slot), ENTRY_SIGNATURE),
                    ]
                )
            )
        state_checks.append(smt_or([smt_eq(commit, 0), *committed_signature_cases]))

        current_index, current_members = current_configuration_expressions(
            step, node, certificate
        )
        state_checks.extend(
            [
                smt_or(current_members),
                f"(<= {current_index} {commit})",
            ]
        )

    election_nodes = range(node_count) if full_world else (0, 1)
    for left in election_nodes:
        for right in election_nodes:
            if left >= right:
                continue
            state_checks.append(
                f"(=> (and (= {select('role', step, left)} {ROLE_LEADER}) "
                f"(= {select('role', step, right)} {ROLE_LEADER}) "
                f"(= {select('term', step, left)} {select('term', step, right)})) "
                "false)"
            )

    for left in range(node_count):
        for right in range(node_count):
            if left >= right:
                continue
            if not full_world and left >= 2:
                continue
            left_commit = select("commit", step, left)
            right_commit = select("commit", step, right)
            left_prefix = [
                f"(=> (<= {index} {left_commit}) "
                f"{entry_equal(step, left, right, index, certificate)})"
                for index in range(1, log_capacity + 1)
            ]
            right_prefix = [
                f"(=> (<= {index} {right_commit}) "
                f"{entry_equal(step, left, right, index, certificate)})"
                for index in range(1, log_capacity + 1)
            ]
            relevant_pairs.append(
                smt_or(
                    [
                        smt_and([f"(<= {left_commit} {right_commit})", *left_prefix]),
                        smt_and([f"(<= {right_commit} {left_commit})", *right_prefix]),
                    ]
                )
            )
            for index in range(1, log_capacity + 1):
                same_term = smt_and(
                    [
                        f"(<= {index} {select('log_len', step, left)})",
                        f"(<= {index} {select('log_len', step, right)})",
                        smt_eq(
                            select(
                                "log_term",
                                step,
                                log_slot(left, index, log_capacity),
                            ),
                            select(
                                "log_term",
                                step,
                                log_slot(right, index, log_capacity),
                            ),
                        ),
                    ]
                )
                relevant_pairs.append(
                    f"(=> {same_term} "
                    f"{smt_and([entry_equal(step, left, right, prefix, certificate) for prefix in range(1, index + 1)])})"
                )

    for destination in checked_destinations:
        length = select("queue_len", step, destination)
        domain.append(f"(and (>= {length} 0) (<= {length} {queue_capacity}))")
        for slot_number in range(queue_capacity):
            flattened = queue_slot(destination, slot_number, queue_capacity)
            active = f"(< {slot_number} {length})"
            inactive = smt_not(active)
            tag = select("queue_tag", step, flattened)
            source = select("queue_source", step, flattened)
            message_destination = select("queue_destination", step, flattened)
            message_term = select("queue_term", step, flattened)
            entry_present = select("queue_entry_present", step, flattened)
            entry_tag = select("queue_entry_tag", step, flattened)
            entry_term = select("queue_entry_term", step, flattened)
            entry_tx = select("queue_entry_tx", step, flattened)
            entry_config = [
                select(
                    "queue_entry_config",
                    step,
                    queue_config_slot(
                        destination,
                        slot_number,
                        member,
                        node_count,
                        queue_capacity,
                    ),
                )
                for member in range(node_count)
            ]
            inactive_defaults = [
                smt_eq(
                    select(field, step, flattened),
                    QUEUE_DEFAULTS[field],
                )
                for field in QUEUE_SLOT_FIELDS
            ]
            inactive_defaults.extend(smt_not(bit) for bit in entry_config)
            domain.extend(
                [
                    f"(=> {active} (and (>= {tag} {MESSAGE_APPEND_REQUEST}) "
                    f"(<= {tag} {MESSAGE_VOTE_RESPONSE})))",
                    f"(=> {active} (and (>= {source} 0) (< {source} {node_count})))",
                    f"(=> {active} (= {message_destination} {destination}))",
                    f"(=> {active} (and (>= {message_term} 0) "
                    f"(<= {message_term} {certificate.max_term})))",
                    f"(=> {inactive} {smt_and(inactive_defaults)})",
                ]
            )

            request = smt_and([active, smt_eq(tag, MESSAGE_APPEND_REQUEST)])
            response = smt_and([active, smt_eq(tag, MESSAGE_APPEND_RESPONSE)])
            vote_request = smt_and([active, smt_eq(tag, MESSAGE_VOTE_REQUEST)])
            vote_response = smt_and([active, smt_eq(tag, MESSAGE_VOTE_RESPONSE)])
            request_fields = [
                select("queue_prev_log_index", step, flattened),
                select("queue_prev_log_term", step, flattened),
                select("queue_leader_commit", step, flattened),
            ]
            domain.extend(
                f"(=> {request} (and (>= {field} 0) (<= {field} {log_capacity})))"
                for field in request_fields
            )
            domain.append(
                f"(=> {request} (<= (+ {request_fields[0]} "
                f"(ite {entry_present} 1 0)) {log_capacity}))"
            )
            entry_config_clear = [smt_not(bit) for bit in entry_config]
            response_success = select("queue_response_success", step, flattened)
            response_last = select("queue_response_last_log_index", step, flattened)
            vote_last_term = select("queue_vote_last_term", step, flattened)
            vote_last_index = select("queue_vote_last_index", step, flattened)
            vote_granted = select("queue_vote_granted", step, flattened)
            append_defaults = [
                *[smt_eq(field, 0) for field in request_fields],
                smt_not(entry_present),
                smt_eq(entry_term, 0),
                smt_eq(entry_tag, 0),
                smt_eq(entry_tx, 0),
                *entry_config_clear,
            ]
            response_defaults = [
                smt_not(response_success),
                smt_eq(response_last, 0),
            ]
            vote_defaults = [
                smt_eq(vote_last_term, 0),
                smt_eq(vote_last_index, 0),
                smt_not(vote_granted),
            ]
            domain.extend(
                [
                    f"(=> (and {request} {entry_present}) "
                    f"(and (>= {entry_term} 1) (<= {entry_term} {certificate.max_term}) "
                    f"(>= {entry_tag} {ENTRY_TRANSACTION}) "
                    f"(<= {entry_tag} {ENTRY_RECONFIGURATION}) "
                    f"(>= {entry_tx} 0) (< {entry_tx} {TX_COUNT})))",
                    f"(=> (and {request} {entry_present} "
                    f"(not (= {entry_tag} {ENTRY_TRANSACTION}))) (= {entry_tx} 0))",
                    f"(=> (and {request} {entry_present} "
                    f"(not (= {entry_tag} {ENTRY_RECONFIGURATION}))) "
                    f"{smt_and(entry_config_clear)})",
                    f"(=> (and {request} {entry_present} "
                    f"(= {entry_tag} {ENTRY_RECONFIGURATION})) {smt_or(entry_config)})",
                    f"(=> (and {request} (not {entry_present})) "
                    f"{smt_and([smt_eq(entry_term, 0), smt_eq(entry_tag, 0), smt_eq(entry_tx, 0), *entry_config_clear])})",
                    f"(=> {request} {smt_and([*response_defaults, *vote_defaults])})",
                    f"(=> {response} {smt_and([*append_defaults, f'(and (>= {response_last} 0) (<= {response_last} {log_capacity}))', *vote_defaults])})",
                    f"(=> {vote_request} {smt_and([*append_defaults, *response_defaults, f'(and (>= {vote_last_term} 0) (<= {vote_last_term} {certificate.max_term}))', f'(and (>= {vote_last_index} 0) (<= {vote_last_index} {log_capacity}))', smt_not(vote_granted)])})",
                    f"(=> {vote_response} {smt_and([*append_defaults, *response_defaults, smt_eq(vote_last_term, 0), smt_eq(vote_last_index, 0)])})",
                ]
            )
    return domain, state_checks, relevant_pairs


def add_structural_constraints(builder: SmtBuilder, certificate: Certificate) -> None:
    """Label structural constraints at all 44 complete states."""

    for step in range(EXPECTED_ACTIONS + 1):
        domain, state_checks, relevant_pairs = state_structural_constraints(
            step, certificate, full_world=step == 0
        )
        scope = (
            "all 15 nodes and destination queues"
            if step == 0
            else "changing nodes 0/1 and queues 0/1; all others are framed from S0"
        )
        builder.labelled(
            f"state_s{step:02d}_finite_domains_and_canonical_unused",
            f"S{step} has bounded fields, bounded indices, and canonical unused log/queue slots for {scope}",
            smt_and(domain),
        )
        builder.labelled(
            f"state_s{step:02d}_encoded_state_checks",
            f"S{step} encodes commit bounds, signatures, log terms, election safety, and configuration checks for {scope}",
            smt_and(state_checks),
        )
        builder.labelled(
            f"state_s{step:02d}_relevant_prefix_and_log_matching",
            (
                f"S{step} encodes committed-prefix consistency and log matching "
                + (
                    "for all 15 nodes"
                    if step == 0
                    else "for every pair touching changing nodes 0 or 1; framed-only pairs inherit S0"
                )
            ),
            smt_and(relevant_pairs),
        )


def add_bootstrap_constraints(builder: SmtBuilder, certificate: Certificate) -> None:
    """Constrain the synthetic event-1 pre-commit checkpoint S0."""

    node_count = certificate.node_count
    log_capacity = certificate.log_capacity
    constraints = [
        smt_eq(select("role", 0, 0), ROLE_LEADER),
        smt_eq(select("term", 0, 0), 2),
        smt_eq(select("log_len", 0, 0), 2),
        smt_eq(select("commit", 0, 0), 0),
        smt_eq(
            select("log_term", 0, log_slot(0, 1, log_capacity)),
            2,
        ),
        smt_eq(
            select("log_tag", 0, log_slot(0, 1, log_capacity)),
            ENTRY_RECONFIGURATION,
        ),
        smt_eq(
            select("log_term", 0, log_slot(0, 2, log_capacity)),
            2,
        ),
        smt_eq(
            select("log_tag", 0, log_slot(0, 2, log_capacity)),
            ENTRY_SIGNATURE,
        ),
        select("has_joined", 0, 0),
        smt_not(select("has_joined", 0, 1)),
    ]
    constraints.extend(
        smt_eq(
            select(
                "log_config",
                0,
                log_config_slot(
                    0,
                    1,
                    member,
                    node_count,
                    log_capacity,
                ),
            ),
            member == 0,
        )
        for member in range(node_count)
    )
    constraints.extend(
        smt_eq(select("queue_len", 0, destination), 0)
        for destination in range(node_count)
    )
    constraints.extend(
        smt_not(select("submitted", 0, tx_id)) for tx_id in range(TX_COUNT)
    )
    builder.labelled(
        "synthetic_event1_precommit_bootstrap",
        "S0 is the synthetic event-1 pre-commit leader-0 term-2 singleton bootstrap with existential unobserved nodes",
        smt_and(constraints),
    )


def unchanged_updates(step: int) -> dict[str, str]:
    """Start a transition with equality for every full state array."""

    return {field: state_name(field, step) for field in STATE_FIELDS}


def update_node_field(
    updates: dict[str, str], field: str, node: int, value: str | int | bool
) -> None:
    """Store one local-node field into a transition update."""

    updates[field] = store(updates[field], node, value)


def update_pair_field(
    updates: dict[str, str],
    field: str,
    node: int | str,
    peer: int | str,
    value: str | int | bool,
    certificate: Certificate,
) -> None:
    """Store one node-peer index or vote bit."""

    updates[field] = store(
        updates[field],
        node_pair(node, peer, certificate.node_count),
        value,
    )


def queue_message_values(
    *,
    tag: int,
    source: int | str,
    destination: int | str,
    term: str | int,
    prev_log_index: str | int = 0,
    prev_log_term: str | int = 0,
    leader_commit: str | int = 0,
    entry_present: str | bool = False,
    entry_term: str | int = 0,
    entry_tag: str | int = 0,
    entry_tx: str | int = 0,
    entry_config: Sequence[str | bool] | None = None,
    response_success: str | bool = False,
    response_last_log_index: str | int = 0,
    vote_last_term: str | int = 0,
    vote_last_index: str | int = 0,
    vote_granted: str | bool = False,
    node_count: int,
) -> tuple[dict[str, str | int | bool], list[str | bool]]:
    """Construct complete queued-message fields, including unused values."""

    values: dict[str, str | int | bool] = {
        "queue_tag": tag,
        "queue_source": source,
        "queue_destination": destination,
        "queue_term": term,
        "queue_prev_log_index": prev_log_index,
        "queue_prev_log_term": prev_log_term,
        "queue_leader_commit": leader_commit,
        "queue_entry_present": entry_present,
        "queue_entry_term": entry_term,
        "queue_entry_tag": entry_tag,
        "queue_entry_tx": entry_tx,
        "queue_response_success": response_success,
        "queue_response_last_log_index": response_last_log_index,
        "queue_vote_last_term": vote_last_term,
        "queue_vote_last_index": vote_last_index,
        "queue_vote_granted": vote_granted,
    }
    config = list(entry_config or [False] * node_count)
    require(len(config) == node_count, "queued entry configuration has wrong width")
    return values, config


def message_equal_at(
    step: int,
    destination: int | str,
    slot_number: int,
    values: Mapping[str, str | int | bool],
    config: Sequence[str | bool],
    certificate: Certificate,
) -> str:
    """Compare a complete message with one concrete queue slot."""

    flattened = queue_slot(destination, slot_number, certificate.queue_capacity)
    comparisons = [
        smt_eq(select(field, step, flattened), value) for field, value in values.items()
    ]
    comparisons.extend(
        smt_eq(
            select(
                "queue_entry_config",
                step,
                queue_config_slot(
                    destination,
                    slot_number,
                    member,
                    certificate.node_count,
                    certificate.queue_capacity,
                ),
            ),
            config[member],
        )
        for member in range(certificate.node_count)
    )
    return smt_and(comparisons)


def enqueue_message(
    updates: dict[str, str],
    step: int,
    destination: int | str,
    values: Mapping[str, str | int | bool],
    config: Sequence[str | bool],
    certificate: Certificate,
    insertion_slot: int,
) -> list[str]:
    """Append one nonduplicate complete message and return exact enqueue guards."""

    length = select("queue_len", step, destination)
    require(
        0 <= insertion_slot < certificate.queue_capacity,
        "queue insertion exceeds bounded capacity",
    )
    guards = [smt_eq(length, insertion_slot)]
    for slot_number in range(insertion_slot):
        guards.append(
            smt_not(
                message_equal_at(
                    step,
                    destination,
                    slot_number,
                    values,
                    config,
                    certificate,
                )
            )
        )
    dynamic_slot = queue_slot(destination, insertion_slot, certificate.queue_capacity)
    updates["queue_len"] = store(updates["queue_len"], destination, insertion_slot + 1)
    for field, value in values.items():
        updates[field] = store(updates[field], dynamic_slot, value)
    for member, membership in enumerate(config):
        updates["queue_entry_config"] = store(
            updates["queue_entry_config"],
            queue_config_slot(
                destination,
                insertion_slot,
                member,
                certificate.node_count,
                certificate.queue_capacity,
            ),
            membership,
        )
    return guards


def shift_queue(
    updates: dict[str, str],
    step: int,
    destination: int,
    certificate: Certificate,
    expected_length: int,
) -> None:
    """Remove a destination queue head and canonically clear its tail."""

    require(expected_length > 0, "cannot shift an empty expected queue")
    updates["queue_len"] = store(updates["queue_len"], destination, expected_length - 1)
    for field in QUEUE_SLOT_FIELDS:
        changes: list[tuple[str, str | bool]] = []
        for slot_number in range(certificate.queue_capacity - 1):
            changes.append(
                (
                    queue_slot(destination, slot_number, certificate.queue_capacity),
                    select(
                        field,
                        step,
                        queue_slot(
                            destination,
                            slot_number + 1,
                            certificate.queue_capacity,
                        ),
                    ),
                )
            )
        changes.append(
            (
                queue_slot(
                    destination,
                    certificate.queue_capacity - 1,
                    certificate.queue_capacity,
                ),
                QUEUE_DEFAULTS[field],
            )
        )
        updates[field] = store_many(updates[field], changes)

    config_changes: list[tuple[str, str | bool]] = []
    for slot_number in range(certificate.queue_capacity - 1):
        for member in range(certificate.node_count):
            config_changes.append(
                (
                    queue_config_slot(
                        destination,
                        slot_number,
                        member,
                        certificate.node_count,
                        certificate.queue_capacity,
                    ),
                    select(
                        "queue_entry_config",
                        step,
                        queue_config_slot(
                            destination,
                            slot_number + 1,
                            member,
                            certificate.node_count,
                            certificate.queue_capacity,
                        ),
                    ),
                )
            )
    for member in range(certificate.node_count):
        config_changes.append(
            (
                queue_config_slot(
                    destination,
                    certificate.queue_capacity - 1,
                    member,
                    certificate.node_count,
                    certificate.queue_capacity,
                ),
                False,
            )
        )
    updates["queue_entry_config"] = store_many(
        updates["queue_entry_config"], config_changes
    )


def transition_action_bindings(
    action: Mapping[str, Any],
    certificate: Certificate,
    consumed_fields: set[str],
) -> list[str]:
    """Bind every declared action field inside its transition equation."""

    number = action["action"]
    source, destination, parameter, transaction = action_parameters(action)
    expected: dict[str, str | int] = {
        "kind": ACTION_KINDS[action["kind"]],
        "source": source,
        "destination": destination,
        "parameter": parameter,
        "transaction": transaction,
    }
    bindings = [
        smt_eq(action_symbol(field, number), value)
        for field, value in expected.items()
        if field not in consumed_fields
    ]
    configuration = set(action["parameters"].get("new_configuration", []))
    bindings.extend(
        smt_eq(action_config(number, member), member in configuration)
        for member in range(certificate.node_count)
    )
    return bindings


def action_transition(
    action: Mapping[str, Any],
    step: int,
    certificate: Certificate,
    queue_lengths: Sequence[int],
) -> tuple[dict[str, str], list[str], str]:
    """Specialize one exact canonical branch from S(step) to S(step+1)."""

    number = action["action"]
    kind = action["kind"]
    parameters = action["parameters"]
    updates = unchanged_updates(step)
    consumed_action_fields = {"destination"} if kind == "appendEntries" else set()
    guards = transition_action_bindings(action, certificate, consumed_action_fields)
    node_count = certificate.node_count
    log_capacity = certificate.log_capacity

    if kind == "advanceCommitIndex":
        node = parameters["node"]
        targets = {1: 2, 20: 4, 29: 6, 40: 7}
        require(number in targets, f"action {number}: unknown commit branch")
        target = targets[number]
        log_length = select("log_len", step, node)
        commit = select("commit", step, node)
        target_slot = log_slot(node, target, log_capacity)
        guards.extend(
            [
                smt_eq(select("role", step, node), ROLE_LEADER),
                f"(< {commit} {target})",
                smt_eq(log_length, target),
                smt_eq(select("log_tag", step, target_slot), ENTRY_SIGNATURE),
                smt_eq(
                    select("log_term", step, target_slot),
                    select("term", step, node),
                ),
            ]
        )
        if target >= 4:
            guards.append(
                f"(>= {select('match_index', step, node_pair(0, 1, node_count))} {target})"
            )
        update_node_field(updates, "commit", node, target)
        branch = f"highestCommittableIndex-specialized-{target}"

    elif kind == "changeConfiguration":
        source = parameters["source"]
        new_configuration = set(parameters["new_configuration"])
        old_length = select("log_len", step, source)
        new_index = "3"
        flattened = log_slot(source, new_index, log_capacity)
        guards.extend(
            [
                smt_eq(select("role", step, source), ROLE_LEADER),
                f"(< {old_length} {log_capacity})",
                smt_not(select("has_joined", step, 1)),
                smt_eq(old_length, 2),
            ]
        )
        update_node_field(updates, "log_len", source, 3)
        updates["log_term"] = store(
            updates["log_term"], flattened, select("term", step, source)
        )
        updates["log_tag"] = store(updates["log_tag"], flattened, ENTRY_RECONFIGURATION)
        updates["log_tx"] = store(updates["log_tx"], flattened, 0)
        for member in range(node_count):
            updates["log_config"] = store(
                updates["log_config"],
                f"(+ (* {flattened} {node_count}) {member})",
                member in new_configuration,
            )
        update_pair_field(
            updates,
            "sent_index",
            source,
            1,
            old_length,
            certificate,
        )
        updates["has_joined"] = store(updates["has_joined"], 1, True)
        branch = "leader-appends-reconfiguration-and-resets-added-peer-sent"

    elif kind in {"signCommittableMessages", "clientRequest"}:
        node = parameters["node"]
        old_length = select("log_len", step, node)
        target_indices = {4: 4, 21: 5, 22: 6, 36: 7}
        require(number in target_indices, f"action {number}: unknown append target")
        target_index = target_indices[number]
        new_index = str(target_index)
        flattened = log_slot(node, new_index, log_capacity)
        guards.extend(
            [
                smt_eq(select("role", step, node), ROLE_LEADER),
                smt_eq(old_length, target_index - 1),
            ]
        )
        if kind == "signCommittableMessages":
            guards.append(f"(> {old_length} 0)")
            entry_tag = ENTRY_SIGNATURE
            entry_tx: str | int = 0
            branch = "leader-appends-current-term-signature"
        else:
            guards.append(smt_not(select("submitted", step, "fresh_tx")))
            entry_tag = ENTRY_TRANSACTION
            entry_tx = "fresh_tx"
            updates["submitted"] = store(updates["submitted"], "fresh_tx", True)
            branch = "leader-appends-fresh-client-transaction"
        update_node_field(updates, "log_len", node, target_index)
        updates["log_term"] = store(
            updates["log_term"], flattened, select("term", step, node)
        )
        updates["log_tag"] = store(updates["log_tag"], flattened, entry_tag)
        updates["log_tx"] = store(updates["log_tx"], flattened, entry_tx)
        for member in range(node_count):
            updates["log_config"] = store(
                updates["log_config"],
                f"(+ (* {flattened} {node_count}) {member})",
                False,
            )

    elif kind == "appendEntries":
        source = parameters["source"]
        expected_destination = parameters["destination"]
        destination = action_symbol("destination", number)
        batch_end = parameters["batch_end"]
        pair = node_pair(source, destination, node_count)
        previous_by_action = {
            3: 2,
            8: 0,
            9: 1,
            10: 2,
            11: 3,
            23: 4,
            24: 5,
            30: 6,
            33: 6,
            37: 6,
            41: 7,
        }
        require(number in previous_by_action, f"action {number}: unknown sent index")
        previous_value = previous_by_action[number]
        previous = str(previous_value)
        source_length = select("log_len", step, source)
        has_entry = previous_value < batch_end
        entry_present = "true" if has_entry else "false"
        entry_index = str(batch_end)
        entry_slot = log_slot(source, entry_index, log_capacity)
        previous_term = (
            "0"
            if previous_value == 0
            else select(
                "log_term",
                step,
                log_slot(source, previous_value, log_capacity),
            )
        )
        guards.extend(
            [
                smt_eq(select("role", step, source), ROLE_LEADER),
                smt_not(smt_eq(source, destination)),
                smt_eq(select("sent_index", step, pair), previous_value),
                smt_eq(
                    str(batch_end),
                    f"(ite (<= {previous_value + 1} {source_length}) "
                    f"{previous_value + 1} {source_length})",
                ),
            ]
        )
        entry_config = [
            (
                select(
                    "log_config",
                    step,
                    log_config_slot(
                        source,
                        entry_index,
                        member,
                        node_count,
                        log_capacity,
                    ),
                )
                if has_entry
                else "false"
            )
            for member in range(node_count)
        ]
        values, config = queue_message_values(
            tag=MESSAGE_APPEND_REQUEST,
            source=source,
            destination=destination,
            term=select("term", step, source),
            prev_log_index=previous,
            prev_log_term=previous_term,
            leader_commit=select("commit", step, source),
            entry_present=entry_present,
            entry_term=select("log_term", step, entry_slot) if has_entry else 0,
            entry_tag=select("log_tag", step, entry_slot) if has_entry else 0,
            entry_tx=select("log_tx", step, entry_slot) if has_entry else 0,
            entry_config=[
                membership if has_entry else False for membership in entry_config
            ],
            node_count=node_count,
        )
        guards.extend(
            enqueue_message(
                updates,
                step,
                destination,
                values,
                config,
                certificate,
                queue_lengths[expected_destination],
            )
        )
        update_pair_field(
            updates,
            "sent_index",
            source,
            destination,
            batch_end,
            certificate,
        )
        branch = "append-one-entry-or-heartbeat-enqueueNoDup"

    elif kind == "updateTerm":
        source = parameters["source"]
        destination = parameters["destination"]
        head = queue_slot(destination, 0, certificate.queue_capacity)
        message_term = select("queue_term", step, head)
        guards.extend(
            [
                smt_eq(
                    select("queue_len", step, destination),
                    queue_lengths[destination],
                ),
                smt_eq(select("queue_source", step, head), source),
                f"(> {message_term} {select('term', step, destination)})",
            ]
        )
        update_node_field(updates, "role", destination, ROLE_FOLLOWER)
        update_node_field(updates, "term", destination, message_term)
        update_node_field(updates, "voted_for_has", destination, False)
        update_node_field(updates, "voted_for_value", destination, 0)
        update_node_field(updates, "is_new_follower", destination, True)
        branch = "newer-message-term-observed-without-dequeue"

    elif kind == "receive":
        source = parameters["source"]
        destination = parameters["destination"]
        head = queue_slot(destination, 0, certificate.queue_capacity)
        expected_queue_length = queue_lengths[destination]
        guards.extend(
            [
                smt_eq(
                    select("queue_len", step, destination),
                    expected_queue_length,
                ),
                smt_eq(select("queue_source", step, head), source),
                smt_eq(select("queue_destination", step, head), destination),
            ]
        )
        if destination == 1:
            require(source == 0, f"action {number}: unsupported request lane")
            guards.append(
                smt_eq(
                    select("queue_tag", step, head),
                    MESSAGE_APPEND_REQUEST,
                )
            )
            request_term = select("queue_term", step, head)
            previous = select("queue_prev_log_index", step, head)
            previous_term = select("queue_prev_log_term", step, head)
            entry_present = select("queue_entry_present", step, head)
            follower_length = select("log_len", step, destination)
            follower_commit = select("commit", step, destination)
            request_previous = {
                6: 2,
                12: 0,
                13: 1,
                14: 2,
                15: 3,
                25: 4,
                26: 5,
                31: 6,
                34: 6,
                38: 6,
                42: 7,
            }[number]
            guards.append(smt_eq(previous, request_previous))
            if number == 6:
                guards.extend(
                    [
                        smt_eq(request_term, select("term", step, destination)),
                        smt_eq(select("role", step, destination), ROLE_FOLLOWER),
                        f"(> {previous} {follower_length})",
                    ]
                )
                response_values, response_config = queue_message_values(
                    tag=MESSAGE_APPEND_RESPONSE,
                    source=destination,
                    destination=source,
                    term=select("term", step, destination),
                    response_success=False,
                    response_last_log_index=follower_length,
                    node_count=node_count,
                )
                branch = "receive-request-initial-log-mismatch-nack"
            else:
                heartbeat_actions = {31, 34, 42}
                is_heartbeat = number in heartbeat_actions
                commit_targets = {
                    12: 0,
                    13: 2,
                    14: 2,
                    15: 2,
                    25: 4,
                    26: 4,
                    31: 6,
                    34: 6,
                    38: 6,
                    42: 7,
                }
                previous_log_ok = (
                    "true"
                    if request_previous == 0
                    else smt_and(
                        [
                            f"(<= {request_previous} {follower_length})",
                            smt_eq(
                                select(
                                    "log_term",
                                    step,
                                    log_slot(
                                        destination,
                                        request_previous,
                                        log_capacity,
                                    ),
                                ),
                                previous_term,
                            ),
                        ]
                    )
                )
                guards.extend(
                    [
                        smt_eq(request_term, select("term", step, destination)),
                        smt_eq(select("role", step, destination), ROLE_FOLLOWER),
                        f"(>= {request_previous} {follower_commit})",
                        previous_log_ok,
                        smt_eq(entry_present, not is_heartbeat),
                    ]
                )
                if is_heartbeat:
                    guards.append(f"(<= {request_previous} {follower_length})")
                    new_length = follower_length
                    new_log_term = state_name("log_term", step)
                    new_log_tag = state_name("log_tag", step)
                    new_log_tx = state_name("log_tx", step)
                    new_log_config = state_name("log_config", step)
                    response_last = str(request_previous)
                    branch = "receive-request-accepted-already-done-heartbeat"
                else:
                    guards.append(smt_eq(follower_length, request_previous))
                    new_index = str(request_previous + 1)
                    new_slot = log_slot(destination, new_index, log_capacity)
                    new_length = new_index
                    new_log_term = store(
                        state_name("log_term", step),
                        new_slot,
                        select("queue_entry_term", step, head),
                    )
                    new_log_tag = store(
                        state_name("log_tag", step),
                        new_slot,
                        select("queue_entry_tag", step, head),
                    )
                    new_log_tx = store(
                        state_name("log_tx", step),
                        new_slot,
                        select("queue_entry_tx", step, head),
                    )
                    config_changes = [
                        (
                            f"(+ (* {new_slot} {node_count}) {member})",
                            select(
                                "queue_entry_config",
                                step,
                                queue_config_slot(
                                    destination,
                                    0,
                                    member,
                                    node_count,
                                    certificate.queue_capacity,
                                ),
                            ),
                        )
                        for member in range(node_count)
                    ]
                    new_log_config = store_many(
                        state_name("log_config", step), config_changes
                    )
                    response_last = new_length
                    branch = "receive-request-accepted-no-conflict-one-entry"
                updates["log_term"] = new_log_term
                updates["log_tag"] = new_log_tag
                updates["log_tx"] = new_log_tx
                updates["log_config"] = new_log_config
                update_node_field(updates, "log_len", destination, new_length)
                commit_target = commit_targets[number]
                guards.append(
                    f"(<= {commit_target} "
                    f"{select('queue_leader_commit', step, head)})"
                )
                if commit_target > 0:
                    guards.append(
                        smt_eq(
                            f"(select {new_log_tag} "
                            f"{log_slot(destination, commit_target, log_capacity)})",
                            ENTRY_SIGNATURE,
                        )
                    )
                update_node_field(
                    updates,
                    "commit",
                    destination,
                    commit_target,
                )
                response_values, response_config = queue_message_values(
                    tag=MESSAGE_APPEND_RESPONSE,
                    source=destination,
                    destination=source,
                    term=select("term", step, destination),
                    response_success=True,
                    response_last_log_index=response_last,
                    node_count=node_count,
                )
            shift_queue(
                updates,
                step,
                destination,
                certificate,
                expected_queue_length,
            )
            guards.extend(
                enqueue_message(
                    updates,
                    step,
                    source,
                    response_values,
                    response_config,
                    certificate,
                    queue_lengths[source],
                )
            )
        else:
            require(
                destination == 0 and source == 1,
                f"action {number}: unsupported response lane",
            )
            guards.append(
                smt_eq(
                    select("queue_tag", step, head),
                    MESSAGE_APPEND_RESPONSE,
                )
            )
            success = select("queue_response_success", step, head)
            response_term = select("queue_term", step, head)
            response_last = select("queue_response_last_log_index", step, head)
            pair = node_pair(destination, source, node_count)
            if number == 7:
                guards.append(smt_not(success))
                possible = "0"
                new_sent = smt_max(
                    f"(ite (<= {possible} {select('sent_index', step, pair)}) "
                    f"{possible} {select('sent_index', step, pair)})",
                    select("match_index", step, pair),
                )
                update_pair_field(
                    updates,
                    "sent_index",
                    destination,
                    source,
                    new_sent,
                    certificate,
                )
                branch = "receive-response-nack-lowers-sent-index"
            else:
                guards.extend(
                    [
                        success,
                        smt_eq(response_term, select("term", step, destination)),
                        smt_eq(select("role", step, destination), ROLE_LEADER),
                    ]
                )
                update_pair_field(
                    updates,
                    "match_index",
                    destination,
                    source,
                    smt_max(select("match_index", step, pair), response_last),
                    certificate,
                )
                branch = "receive-response-ack-raises-match-index"
            shift_queue(
                updates,
                step,
                destination,
                certificate,
                expected_queue_length,
            )
    else:
        raise EncodingError(f"action {number}: unsupported fixed kind {kind}")

    return updates, guards, branch


def add_transitions(builder: SmtBuilder, certificate: Certificate) -> None:
    """Encode all 43 fixed action branches."""

    queue_lengths = [0] * certificate.node_count
    for action in certificate.actions:
        number = action["action"]
        step = number - 1
        updates, guards, branch = action_transition(
            action, step, certificate, tuple(queue_lengths)
        )
        equalities = [
            smt_eq(state_name(field, step + 1), expression)
            for field, expression in updates.items()
        ]
        transition_expression = smt_and([*guards, *equalities])
        required_action_symbols = [
            action_symbol(field, number)
            for field in (
                "kind",
                "source",
                "destination",
                "parameter",
                "transaction",
                "configuration",
            )
        ]
        require(
            all(symbol in transition_expression for symbol in required_action_symbols),
            f"action {number}: transition does not consume every declared action field",
        )
        reduction = certificate.action_reductions[number]
        builder.labelled(
            f"reduction{reduction['reduction']:02d}_action{number:02d}_{action['kind']}",
            f"reduction {reduction['name']} action {number}: {branch}",
            transition_expression,
        )
        if action["kind"] == "appendEntries":
            queue_lengths[action["parameters"]["destination"]] += 1
        elif action["kind"] == "receive":
            source = action["parameters"]["source"]
            destination = action["parameters"]["destination"]
            require(
                queue_lengths[destination] > 0,
                f"action {number}: expected queue underflow",
            )
            queue_lengths[destination] -= 1
            if (source, destination) == (0, 1):
                queue_lengths[0] += 1
    require(
        not any(queue_lengths),
        f"fixed action skeleton does not drain queues: {queue_lengths}",
    )


def role_value(value: str) -> int:
    """Map the C++ trace role spelling to the bounded role tag."""

    mapping = {
        "None": ROLE_NONE,
        "Follower": ROLE_FOLLOWER,
        "Candidate": ROLE_CANDIDATE,
        "Leader": ROLE_LEADER,
    }
    require(value in mapping, f"unsupported observed role {value!r}")
    return mapping[value]


def checkpoint_state_step(position: Mapping[str, Any]) -> int:
    """Resolve one explicit action-checkpoint position to a state number."""

    require(
        position.get("kind") == "action_checkpoint",
        f"position is not an action checkpoint: {position}",
    )
    action = position.get("action")
    relation = position.get("relation")
    require(
        isinstance(action, int) and 1 <= action <= EXPECTED_ACTIONS,
        f"checkpoint action is invalid: {position}",
    )
    if relation == "before":
        return action - 1
    if relation == "after":
        return action
    require(relation == "during", f"unsupported observation relation {relation}")
    if position.get("phase") == "pre-reconfiguration-send-hook":
        return action - 1
    return action


def field_state_step(decision: Mapping[str, Any]) -> int:
    """Resolve an explicitly positioned state-scalar field."""

    position = decision["field_position"]
    kind = position.get("kind")
    if kind == "action_checkpoint":
        return checkpoint_state_step(position)
    if kind == "span_start":
        action = position.get("before_action")
        require(
            isinstance(action, int) and 1 <= action <= EXPECTED_ACTIONS,
            f"span-start action is invalid: {position}",
        )
        return action - 1
    raise EncodingError(
        f"field {decision['path']} has no single state checkpoint: {position}"
    )


def positioned_action_range(position: Mapping[str, Any]) -> range:
    """Return the exact action range owned by a field position."""

    kind = position.get("kind")
    if kind == "action_checkpoint":
        action = position.get("action")
        require(
            isinstance(action, int) and 1 <= action <= EXPECTED_ACTIONS,
            f"field action checkpoint is invalid: {position}",
        )
        return range(action, action + 1)
    if kind == "whole_action_span":
        start = position.get("start_action")
        end = position.get("end_action")
        require(
            isinstance(start, int)
            and isinstance(end, int)
            and 1 <= start <= end <= EXPECTED_ACTIONS,
            f"whole-action span is invalid: {position}",
        )
        return range(start, end + 1)
    if kind == "span_start":
        action = position.get("before_action")
        require(
            isinstance(action, int) and 1 <= action <= EXPECTED_ACTIONS,
            f"span-start action is invalid: {position}",
        )
        return range(action, action + 1)
    raise EncodingError(f"unsupported explicit field position: {position}")


def queue_observation_slot(
    event_number: int, function: str, certificate: Certificate
) -> tuple[int, int, str]:
    """Select an exact single-action queue packet checkpoint."""

    if function == "recv_append_entries":
        if event_number == 5:
            return 1, 0, "source-log-reconstruction"
        return 1, 0, "exact-queue-message"
    if function == "recv_append_entries_response":
        return 0, 0, "exact-queue-message"
    if function == "send_append_entries_response":
        return 0, -1, "generated-response-tail"
    raise EncodingError(f"event {event_number}: no queue packet mapping for {function}")


def packet_field_expression(
    certificate: Certificate,
    event_number: int,
    decision: Mapping[str, Any],
    path: str,
    value: Any,
    state_step: int,
) -> tuple[str, str]:
    """Encode one projected packet leaf and report its correspondence mode."""

    message = certificate.events[event_number]["msg"]
    function = message["function"]
    packet = message["packet"]
    if function == "send_append_entries":
        destination = int(message["to_node_id"])
        pair = node_pair(0, destination, certificate.node_count)
        previous = select("sent_index", state_step, pair)
        endpoint = packet["idx"]
        mode = "exact-action-preview"
        if path == "msg.packet.msg":
            actions = positioned_action_range(decision["field_position"])
            require(len(actions) == 1, "wire packet field spans multiple actions")
            action_number = actions.start
            action_kind = certificate.actions[action_number - 1]["kind"]
            return (
                smt_eq(
                    action_symbol(
                        "kind",
                        action_number,
                    ),
                    ACTION_KINDS[action_kind],
                ),
                mode,
            )
        if path == "msg.packet.term":
            return smt_eq(select("term", state_step, 0), value), mode
        if path == "msg.packet.leader_commit_idx":
            return smt_eq(select("commit", state_step, 0), value), mode
        if path == "msg.packet.prev_idx":
            return smt_eq(previous, value), mode
        if path == "msg.packet.idx":
            return (
                smt_and(
                    [
                        f"(>= {value} {previous})",
                        f"(<= {value} {select('log_len', state_step, 0)})",
                    ]
                ),
                mode,
            )
        if path == "msg.packet.prev_term":
            if packet["prev_idx"] == 0:
                return smt_eq(value, 0), mode
            return (
                smt_eq(
                    select(
                        "log_term",
                        state_step,
                        log_slot(
                            0,
                            packet["prev_idx"],
                            certificate.log_capacity,
                        ),
                    ),
                    value,
                ),
                mode,
            )
        if path == "msg.packet.term_of_idx":
            return (
                smt_eq(
                    select(
                        "log_term",
                        state_step,
                        log_slot(0, endpoint, certificate.log_capacity),
                    ),
                    value,
                ),
                mode,
            )

    destination, slot_number, mode = queue_observation_slot(
        event_number, function, certificate
    )
    if slot_number == -1:
        slot = f"(- {select('queue_len', state_step, destination)} 1)"
    else:
        slot = str(slot_number)
    flattened = queue_slot(destination, slot, certificate.queue_capacity)
    if event_number == 5:
        # The reducer replaces the C++ pre-reconfiguration heartbeat with a
        # canonical request carrying entry 3. Reconstruct the raw packet from
        # the retained source log while retaining the queue source/term checks.
        mode = "source-log-reconstruction-event3-exception"
        if path == "msg.packet.msg":
            return smt_eq(select("queue_tag", state_step, flattened), 1), mode
        if path == "msg.packet.term":
            return smt_eq(select("queue_term", state_step, flattened), value), mode
        if path == "msg.packet.leader_commit_idx":
            return (
                smt_eq(select("queue_leader_commit", state_step, flattened), value),
                mode,
            )
        if path == "msg.packet.prev_idx":
            return (
                smt_eq(select("queue_prev_log_index", state_step, flattened), value),
                mode,
            )
        if path == "msg.packet.prev_term":
            return (
                smt_eq(select("queue_prev_log_term", state_step, flattened), value),
                mode,
            )
        if path == "msg.packet.idx":
            canonical_end = (
                f"(+ {select('queue_prev_log_index', state_step, flattened)} "
                f"(ite {select('queue_entry_present', state_step, flattened)} 1 0))"
            )
            return f"(<= {value} {canonical_end})", mode
        if path == "msg.packet.term_of_idx":
            return (
                smt_eq(
                    select(
                        "log_term",
                        state_step,
                        log_slot(0, packet["idx"], certificate.log_capacity),
                    ),
                    value,
                ),
                mode,
            )

    field_map = {
        "msg.packet.term": "queue_term",
        "msg.packet.prev_idx": "queue_prev_log_index",
        "msg.packet.prev_term": "queue_prev_log_term",
        "msg.packet.leader_commit_idx": "queue_leader_commit",
        "msg.packet.last_log_idx": "queue_response_last_log_index",
    }
    if path == "msg.packet.msg":
        expected_tag = (
            MESSAGE_APPEND_REQUEST
            if packet["msg"] == "raft_append_entries"
            else MESSAGE_APPEND_RESPONSE
        )
        return smt_eq(select("queue_tag", state_step, flattened), expected_tag), mode
    if path == "msg.packet.success":
        expected = value == "OK"
        return (
            smt_eq(
                select("queue_response_success", state_step, flattened),
                expected,
            ),
            mode,
        )
    if path in field_map:
        return smt_eq(select(field_map[path], state_step, flattened), value), mode
    if path == "msg.packet.idx":
        endpoint = (
            f"(+ {select('queue_prev_log_index', state_step, flattened)} "
            f"(ite {select('queue_entry_present', state_step, flattened)} 1 0))"
        )
        return smt_eq(endpoint, value), mode
    if path == "msg.packet.term_of_idx":
        entry_term = select("queue_entry_term", state_step, flattened)
        heartbeat_term = select("queue_prev_log_term", state_step, flattened)
        return (
            smt_eq(
                f"(ite {select('queue_entry_present', state_step, flattened)} "
                f"{entry_term} {heartbeat_term})",
                value,
            ),
            mode,
        )
    raise EncodingError(f"event {event_number}: unsupported packet path {path}")


def span_metadata(
    certificate: Certificate,
    event_number: int,
    decision: Mapping[str, Any],
) -> tuple[Mapping[str, Any], range, range]:
    """Validate and return one certificate-owned action/index span."""

    observation = certificate.observations[event_number]
    position = observation["position"]
    field_position = decision["field_position"]
    require(
        position.get("kind") == "action_span"
        and field_position.get("kind") == "whole_action_span",
        f"event {event_number} field {decision['path']} is not span-positioned",
    )
    actions = positioned_action_range(field_position)
    require(
        actions.start == position.get("start_action")
        and actions.stop - 1 == position.get("end_action"),
        f"event {event_number} field span differs from observation span",
    )
    absolute = position.get("absolute_index_range")
    require(
        isinstance(absolute, dict)
        and isinstance(absolute.get("start"), int)
        and isinstance(absolute.get("end"), int),
        f"event {event_number} absolute index range is absent",
    )
    indices = range(absolute["start"], absolute["end"] + 1)
    require(
        len(actions) == len(indices),
        f"event {event_number} action/index span lengths differ",
    )
    return position, actions, indices


def span_action_grammar(
    certificate: Certificate,
    actions: range,
    kind: str,
    source: int,
    destination: int,
) -> list[str]:
    """Constrain every action in an explicit reduction span."""

    return [
        constraint
        for action in actions
        for constraint in (
            smt_eq(action_symbol("kind", action), ACTION_KINDS[kind]),
            smt_eq(action_symbol("source", action), source),
            smt_eq(action_symbol("destination", action), destination),
        )
    ]


def aggregate_span_field_expression(
    certificate: Certificate,
    event_number: int,
    decision: Mapping[str, Any],
    value: Any,
) -> tuple[str, str]:
    """Encode one aggregate C++ field over its complete canonical action span."""

    path = decision["path"]
    position, actions, indices = span_metadata(certificate, event_number, decision)
    message = certificate.events[event_number]["msg"]
    span_kind = position["span_kind"]
    start_step = actions.start - 1

    if span_kind == "append_entries_batch_send":
        source = int(message["state"]["node_id"])
        destination = int(message["to_node_id"])
        grammar = span_action_grammar(
            certificate, actions, "appendEntries", source, destination
        )
        grammar.extend(
            smt_eq(action_symbol("parameter", action), index)
            for action, index in zip(actions, indices)
        )
        if path == "msg.function" or path == "msg.packet.msg":
            expression = smt_and(grammar)
        elif path == "msg.to_node_id":
            expression = smt_and(
                [
                    *grammar,
                    *[
                        smt_eq(action_symbol("destination", action), value)
                        for action in actions
                    ],
                ]
            )
        elif path == "msg.packet.term":
            expression = smt_and(
                [
                    *grammar,
                    *[
                        smt_eq(select("term", action - 1, source), value)
                        for action in actions
                    ],
                ]
            )
        elif path == "msg.packet.leader_commit_idx":
            expression = smt_and(
                [
                    *grammar,
                    *[
                        smt_eq(select("commit", action - 1, source), value)
                        for action in actions
                    ],
                ]
            )
        elif path == "msg.packet.prev_idx":
            expression = smt_and(
                [
                    *grammar,
                    smt_eq(
                        select(
                            "sent_index",
                            start_step,
                            node_pair(source, destination, certificate.node_count),
                        ),
                        value,
                    ),
                    smt_eq(value + 1, indices.start),
                ]
            )
        elif path == "msg.packet.idx":
            expression = smt_and(
                [
                    *grammar,
                    smt_eq(action_symbol("parameter", actions.stop - 1), value),
                    smt_eq(value, indices.stop - 1),
                ]
            )
        elif path == "msg.packet.prev_term":
            term = (
                "0"
                if message["packet"]["prev_idx"] == 0
                else select(
                    "log_term",
                    start_step,
                    log_slot(
                        source,
                        message["packet"]["prev_idx"],
                        certificate.log_capacity,
                    ),
                )
            )
            expression = smt_and([*grammar, smt_eq(term, value)])
        elif path == "msg.packet.term_of_idx":
            expression = smt_and(
                [
                    *grammar,
                    smt_eq(
                        select(
                            "log_term",
                            start_step,
                            log_slot(
                                source,
                                message["packet"]["idx"],
                                certificate.log_capacity,
                            ),
                        ),
                        value,
                    ),
                ]
            )
        else:
            raise EncodingError(
                f"event {event_number}: unsupported aggregate send field {path}"
            )
        return expression, "explicit-whole-action-span-send-endpoints"

    source = int(message["from_node_id"])
    destination = int(message["state"]["node_id"])
    grammar = span_action_grammar(certificate, actions, "receive", source, destination)
    queue_indices = [
        queue_slot(destination, slot, certificate.queue_capacity)
        for slot in range(len(actions))
    ]

    if span_kind == "append_entries_batch_receive":
        first = queue_indices[0]
        last = queue_indices[-1]
        if path in {"msg.function", "msg.from_node_id"}:
            expression = smt_and(grammar)
        elif path == "msg.packet.msg":
            expression = smt_and(
                [
                    *grammar,
                    *[
                        smt_eq(
                            select("queue_tag", start_step, slot),
                            MESSAGE_APPEND_REQUEST,
                        )
                        for slot in queue_indices
                    ],
                ]
            )
        elif path == "msg.packet.term":
            expression = smt_and(
                [
                    *grammar,
                    *[
                        smt_eq(select("queue_term", start_step, slot), value)
                        for slot in queue_indices
                    ],
                ]
            )
        elif path == "msg.packet.leader_commit_idx":
            expression = smt_and(
                [
                    *grammar,
                    *[
                        smt_eq(
                            select("queue_leader_commit", start_step, slot),
                            value,
                        )
                        for slot in queue_indices
                    ],
                ]
            )
        elif path == "msg.packet.prev_idx":
            expression = smt_and(
                [
                    *grammar,
                    smt_eq(
                        select("queue_prev_log_index", start_step, first),
                        value,
                    ),
                    smt_eq(value + 1, indices.start),
                ]
            )
        elif path == "msg.packet.idx":
            endpoint = (
                f"(+ {select('queue_prev_log_index', start_step, last)} "
                f"(ite {select('queue_entry_present', start_step, last)} 1 0))"
            )
            expression = smt_and(
                [
                    *grammar,
                    smt_eq(endpoint, value),
                    smt_eq(value, indices.stop - 1),
                ]
            )
        elif path == "msg.packet.prev_term":
            expression = smt_and(
                [
                    *grammar,
                    smt_eq(
                        select("queue_prev_log_term", start_step, first),
                        value,
                    ),
                ]
            )
        elif path == "msg.packet.term_of_idx":
            expression = smt_and(
                [
                    *grammar,
                    smt_eq(
                        select("queue_entry_term", start_step, last),
                        value,
                    ),
                ]
            )
        else:
            raise EncodingError(
                f"event {event_number}: unsupported aggregate request field {path}"
            )
        return expression, "explicit-whole-action-span-request-endpoints"

    require(
        span_kind == "append_entries_batch_response_receive",
        f"event {event_number}: unsupported span kind {span_kind}",
    )
    last = queue_indices[-1]
    if path in {"msg.function", "msg.from_node_id"}:
        expression = smt_and(grammar)
    elif path == "msg.packet.msg":
        expression = smt_and(
            [
                *grammar,
                *[
                    smt_eq(
                        select("queue_tag", start_step, slot),
                        MESSAGE_APPEND_RESPONSE,
                    )
                    for slot in queue_indices
                ],
            ]
        )
    elif path == "msg.packet.term":
        expression = smt_and(
            [
                *grammar,
                *[
                    smt_eq(select("queue_term", start_step, slot), value)
                    for slot in queue_indices
                ],
            ]
        )
    elif path == "msg.packet.success":
        expected = value == "OK"
        expression = smt_and(
            [
                *grammar,
                *[
                    smt_eq(
                        select("queue_response_success", start_step, slot),
                        expected,
                    )
                    for slot in queue_indices
                ],
            ]
        )
    elif path == "msg.packet.last_log_idx":
        expression = smt_and(
            [
                *grammar,
                smt_eq(
                    select(
                        "queue_response_last_log_index",
                        start_step,
                        last,
                    ),
                    value,
                ),
                smt_eq(value, indices.stop - 1),
            ]
        )
    else:
        raise EncodingError(
            f"event {event_number}: unsupported aggregate response field {path}"
        )
    return expression, "explicit-whole-action-span-response-endpoint"


def configuration_observation_expression(
    certificate: Certificate,
    event_number: int,
    decision: Mapping[str, Any],
    path: str,
    state_step: int,
) -> tuple[str, str]:
    """Encode a projected configuration argument."""

    message = certificate.events[event_number]["msg"]
    configuration = message["args"]["configuration"]
    index = configuration["idx"]
    members = {int(member) for member in configuration["nodes"]}
    actions = positioned_action_range(decision["field_position"])
    require(len(actions) == 1, "configuration event spans multiple actions")
    action_number = actions.start
    if event_number == 2:
        if path == "msg.args.configuration.idx":
            return (
                smt_eq(
                    f"(+ {select('log_len', state_step, 0)} 1)",
                    index,
                ),
                "configuration-action-parameter",
            )
        if path == "msg.args.configuration.nodes.<keys>":
            return (
                smt_and(
                    [
                        smt_eq(
                            action_config(action_number, member),
                            member in members,
                        )
                        for member in range(certificate.node_count)
                    ]
                ),
                "configuration-action-parameter",
            )
    node = int(message["state"]["node_id"])
    slot = log_slot(node, index, certificate.log_capacity)
    if path == "msg.args.configuration.idx":
        return (
            smt_and(
                [
                    f"(<= {index} {select('log_len', state_step, node)})",
                    smt_eq(
                        select("log_tag", state_step, slot),
                        ENTRY_RECONFIGURATION,
                    ),
                ]
            ),
            "retained-log-configuration",
        )
    if path == "msg.args.configuration.nodes.<keys>":
        return (
            smt_and(
                [
                    smt_eq(
                        select(
                            "log_config",
                            state_step,
                            log_config_slot(
                                node,
                                index,
                                member,
                                certificate.node_count,
                                certificate.log_capacity,
                            ),
                        ),
                        member in members,
                    )
                    for member in range(certificate.node_count)
                ]
            ),
            "retained-log-configuration",
        )
    raise EncodingError(f"event {event_number}: unsupported configuration path {path}")


def function_ownership_expression(
    certificate: Certificate,
    event_number: int,
    decision: Mapping[str, Any],
    function: str,
) -> str:
    """Tie a projected helper/function name to its owning fixed action grammar."""

    actions = positioned_action_range(decision["field_position"])
    require(len(actions) == 1, "single-action function field spans multiple actions")
    action_number = actions.start
    kind = certificate.actions[action_number - 1]["kind"]
    allowed: dict[str, set[str]] = {
        "bootstrap": {"advanceCommitIndex"},
        "commit": {"advanceCommitIndex", "receive"},
        "replicate": {"clientRequest", "signCommittableMessages"},
        "send_append_entries": {"appendEntries", "changeConfiguration"},
        "recv_append_entries": {"receive", "updateTerm"},
        "recv_append_entries_response": {"receive"},
    }
    require(
        function in allowed and kind in allowed[function],
        f"event {event_number}: function {function} is not owned by action {kind}",
    )
    return smt_eq(
        action_symbol("kind", action_number),
        ACTION_KINDS[kind],
    )


def observation_expression(
    certificate: Certificate,
    event_number: int,
    decision: Mapping[str, Any],
    mutation: str,
) -> tuple[str, str]:
    """Map one projected certificate leaf to a labelled SMT assertion."""

    row = certificate.events[event_number]
    message = row["msg"]
    path = decision["path"]
    field_position = decision["field_position"]
    field_kind = decision["field_kind"]
    if field_position.get("kind") == "whole_action_span":
        require(
            field_kind
            in {
                "aggregate-packet-range-constraint",
                "aggregate-response-constraint",
                "aggregate-span-constraint",
            },
            f"event {event_number} span field has invalid kind {field_kind}",
        )
        value = message
        for component in path.split(".")[1:]:
            value = value[component]
        return aggregate_span_field_expression(
            certificate, event_number, decision, value
        )

    step = field_state_step(decision)
    state = message["state"]
    node = int(state["node_id"])
    value_by_path: dict[str, Any] = {
        "msg.state.node_id": node,
        "msg.state.current_view": state["current_view"],
        "msg.state.last_idx": state["last_idx"],
        "msg.state.commit_idx": state["commit_idx"],
        "msg.state.leadership_state": state["leadership_state"],
    }
    if mutation == "conflicting-observed-commit" and (
        event_number,
        path,
    ) == (53, "msg.state.commit_idx"):
        value_by_path[path] = 6

    state_field_map = {
        "msg.state.current_view": "term",
        "msg.state.last_idx": "log_len",
        "msg.state.commit_idx": "commit",
    }
    if path in state_field_map:
        return (
            smt_eq(
                select(state_field_map[path], step, node),
                value_by_path[path],
            ),
            "exact-state-checkpoint",
        )
    if path == "msg.state.leadership_state":
        return (
            smt_eq(select("role", step, node), role_value(state["leadership_state"])),
            "exact-state-checkpoint",
        )
    if path == "msg.state.node_id":
        actions = positioned_action_range(field_position)
        require(len(actions) == 1, "state node ownership spans multiple actions")
        action_number = actions.start
        action = certificate.actions[action_number - 1]
        if action["kind"] in {"receive", "updateTerm"}:
            expression = smt_eq(action_symbol("destination", action_number), node)
        else:
            expression = smt_eq(action_symbol("source", action_number), node)
        return expression, "action-grammar-ownership"
    if path == "msg.function":
        return (
            function_ownership_expression(
                certificate, event_number, decision, message["function"]
            ),
            "action-grammar-ownership",
        )
    if path.startswith("msg.packet."):
        return packet_field_expression(
            certificate,
            event_number,
            decision,
            path,
            message["packet"][path.rsplit(".", 1)[1]],
            step,
        )
    if path == "msg.from_node_id":
        actions = positioned_action_range(field_position)
        require(len(actions) == 1, "message source spans multiple actions")
        action_number = actions.start
        return (
            smt_eq(
                action_symbol("source", action_number),
                int(message["from_node_id"]),
            ),
            "action-grammar-ownership",
        )
    if path == "msg.to_node_id":
        expected = int(message["to_node_id"])
        if message["function"] == "send_append_entries":
            actions = positioned_action_range(field_position)
            require(len(actions) == 1, "message destination spans multiple actions")
            action_number = actions.start
            if event_number == 3:
                return (
                    smt_eq(action_config(action_number, expected), True),
                    "pre-reconfiguration-hook-destination",
                )
            return (
                smt_eq(action_symbol("destination", action_number), expected),
                "action-grammar-ownership",
            )
        destination, slot_number, mode = queue_observation_slot(
            event_number, message["function"], certificate
        )
        require(slot_number == -1, "response send is not mapped to queue tail")
        flattened = queue_slot(
            destination,
            f"(- {select('queue_len', step, destination)} 1)",
            certificate.queue_capacity,
        )
        return (
            smt_eq(select("queue_destination", step, flattened), expected),
            mode,
        )
    if path in {"msg.sent_idx", "msg.match_idx"}:
        field = "sent_index" if path == "msg.sent_idx" else "match_index"
        return (
            smt_eq(
                select(
                    field,
                    step,
                    node_pair(node, 1, certificate.node_count),
                ),
                message[path.split(".")[1]],
            ),
            "explicit-state-field-position",
        )
    if path == "msg.view":
        return (
            smt_eq(select("term", step, node), message["view"]),
            "append-preview",
        )
    if path == "msg.seqno":
        actions = positioned_action_range(field_position)
        require(len(actions) == 1, "replicate sequence spans multiple actions")
        action_number = actions.start
        return (
            smt_and(
                [
                    smt_eq(
                        f"(+ {select('log_len', step, node)} 1)",
                        message["seqno"],
                    ),
                    smt_or(
                        [
                            smt_eq(
                                action_symbol("kind", action_number),
                                ACTION_KINDS["clientRequest"],
                            ),
                            smt_eq(
                                action_symbol("kind", action_number),
                                ACTION_KINDS["signCommittableMessages"],
                            ),
                        ]
                    ),
                ]
            ),
            "append-preview",
        )
    if path == "msg.globally_committable":
        actions = positioned_action_range(field_position)
        require(len(actions) == 1, "committable field spans multiple actions")
        action_number = actions.start
        expected_kind = (
            "signCommittableMessages"
            if message["globally_committable"]
            else "clientRequest"
        )
        return (
            smt_eq(
                action_symbol("kind", action_number),
                ACTION_KINDS[expected_kind],
            ),
            "append-preview",
        )
    if path.startswith("msg.args.configuration."):
        return configuration_observation_expression(
            certificate, event_number, decision, path, step
        )
    if path == "msg.args.idx":
        target = message["args"]["idx"]
        actions = positioned_action_range(field_position)
        require(len(actions) == 1, "commit target spans multiple actions")
        action_number = actions.start
        target_step = action_number
        target_node = node
        return (
            smt_eq(select("commit", target_step, target_node), target),
            "commit-target-or-callback-result",
        )
    raise EncodingError(f"event {event_number}: unsupported projected path {path}")


def add_observations(
    builder: SmtBuilder, certificate: Certificate, mutation: str
) -> list[dict[str, Any]]:
    """Consume every projection decision and label every encoded leaf."""

    provenance: list[dict[str, Any]] = []
    for event_number in range(1, EXPECTED_EVENTS + 1):
        observation = certificate.observations[event_number]
        encoded_fields: list[dict[str, str]] = []
        unencoded_fields: list[dict[str, str]] = []
        for decision in observation["field_decisions"]:
            path = decision["path"]
            if decision["status"] == "omitted":
                unencoded_fields.append(
                    {
                        "path": path,
                        "reason": decision["reason"],
                        "source": "reduction-certificate",
                        "certificate_field_kind": decision.get("field_kind"),
                        "certificate_field_position": decision.get("field_position"),
                    }
                )
                continue
            expression, mode = observation_expression(
                certificate, event_number, decision, mutation
            )
            label_path = re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_")
            label = f"event{event_number:02d}_{label_path}"
            builder.labelled(
                label,
                f"event {event_number} projected {path} as "
                f"{decision['field_kind']} at "
                f"{json.dumps(decision['field_position'], sort_keys=True)} via {mode}",
                expression,
            )
            encoded_fields.append(
                {
                    "path": path,
                    "label": label,
                    "mode": mode,
                    "certificate_reason": decision["reason"],
                    "certificate_field_kind": decision.get("field_kind"),
                    "certificate_field_position": decision.get("field_position"),
                }
            )
        require(
            encoded_fields,
            f"event {event_number}: no projected field was encoded",
        )
        provenance.append(
            {
                "event": event_number,
                "position": observation["position"],
                "exception_ids": observation["exception_ids"],
                "encoded_fields": encoded_fields,
                "unencoded_fields": unencoded_fields,
            }
        )
    return provenance


def alias_node(
    builder: SmtBuilder,
    prefix: str,
    step: int,
    node: int,
    certificate: Certificate,
) -> None:
    """Request one complete bounded node value."""

    for field in NODE_FIELDS:
        builder.alias(
            f"{prefix}_{field}",
            STATE_FIELDS[field],
            select(field, step, node),
        )
    for peer in range(certificate.node_count):
        pair = node_pair(node, peer, certificate.node_count)
        for field in PAIR_FIELDS:
            builder.alias(
                f"{prefix}_{field}_{peer:02d}",
                STATE_FIELDS[field],
                select(field, step, pair),
            )
    for index in range(1, certificate.log_capacity + 1):
        slot = log_slot(node, index, certificate.log_capacity)
        for field in LOG_FIELDS:
            builder.alias(
                f"{prefix}_{field}_{index:02d}",
                STATE_FIELDS[field],
                select(field, step, slot),
            )
        for member in range(certificate.node_count):
            builder.alias(
                f"{prefix}_log_config_{index:02d}_{member:02d}",
                "Bool",
                select(
                    "log_config",
                    step,
                    log_config_slot(
                        node,
                        index,
                        member,
                        certificate.node_count,
                        certificate.log_capacity,
                    ),
                ),
            )


def alias_queue(
    builder: SmtBuilder,
    prefix: str,
    step: int,
    destination: int,
    certificate: Certificate,
) -> None:
    """Request one complete bounded destination queue."""

    builder.alias(
        f"{prefix}_length",
        "Int",
        select("queue_len", step, destination),
    )
    for slot_number in range(certificate.queue_capacity):
        flattened = queue_slot(destination, slot_number, certificate.queue_capacity)
        for field in QUEUE_SLOT_FIELDS:
            builder.alias(
                f"{prefix}_{field}_{slot_number:02d}",
                STATE_FIELDS[field],
                select(field, step, flattened),
            )
        for member in range(certificate.node_count):
            builder.alias(
                f"{prefix}_queue_entry_config_{slot_number:02d}_{member:02d}",
                "Bool",
                select(
                    "queue_entry_config",
                    step,
                    queue_config_slot(
                        destination,
                        slot_number,
                        member,
                        certificate.node_count,
                        certificate.queue_capacity,
                    ),
                ),
            )


def add_witness_aliases(builder: SmtBuilder, certificate: Certificate) -> None:
    """Request complete S0, all actions, and selected complete intermediate data."""

    builder.alias("w_fresh_tx", "Int", "fresh_tx")
    for action in certificate.actions:
        number = action["action"]
        for field in ("kind", "source", "destination", "parameter", "transaction"):
            builder.alias(
                f"w_action_{number:02d}_{field}",
                "Int",
                action_symbol(field, number),
            )
        for member in range(certificate.node_count):
            builder.alias(
                f"w_action_{number:02d}_configuration_{member:02d}",
                "Bool",
                action_config(number, member),
            )

    for node in range(certificate.node_count):
        alias_node(builder, f"w_s00_node_{node:02d}", 0, node, certificate)
    for destination in range(certificate.node_count):
        alias_queue(
            builder,
            f"w_s00_queue_{destination:02d}",
            0,
            destination,
            certificate,
        )
    for tx_id in range(TX_COUNT):
        builder.alias(
            f"w_s00_submitted_{tx_id:02d}",
            "Bool",
            select("submitted", 0, tx_id),
        )
    for node in range(certificate.node_count):
        builder.alias(
            f"w_s00_joined_{node:02d}",
            "Bool",
            select("has_joined", 0, node),
        )

    for step in range(EXPECTED_ACTIONS + 1):
        for node in (0, 1):
            alias_node(
                builder,
                f"w_checkpoint_{step:02d}_node_{node:02d}",
                step,
                node,
                certificate,
            )
        for destination in (0, 1):
            alias_queue(
                builder,
                f"w_checkpoint_{step:02d}_queue_{destination:02d}",
                step,
                destination,
                certificate,
            )
        builder.alias(
            f"w_checkpoint_{step:02d}_fresh_tx_submitted",
            "Bool",
            select("submitted", step, "fresh_tx"),
        )
        for node in (0, 1):
            builder.alias(
                f"w_checkpoint_{step:02d}_joined_{node:02d}",
                "Bool",
                select("has_joined", step, node),
            )


def build_encoding(certificate: Certificate, mutation: str) -> Encoding:
    """Build the complete bounded QF formula and decoder metadata."""

    require(
        mutation
        in {
            "none",
            "conflicting-observed-commit",
            "wrong-destination-action-param",
        },
        f"unsupported mutation {mutation}",
    )
    builder = SmtBuilder()
    declare_states(builder, EXPECTED_ACTIONS)
    declare_actions(builder, certificate, mutation)
    add_structural_constraints(builder, certificate)
    add_bootstrap_constraints(builder, certificate)
    add_transitions(builder, certificate)
    observation_provenance = add_observations(builder, certificate, mutation)
    if mutation == "none":
        add_witness_aliases(builder, certificate)

    header = [
        "; Copyright (c) Microsoft Corporation. All rights reserved.",
        "; Licensed under the Apache 2.0 License.",
        ";",
        "; Generated naive full-state bounded encoding.",
        "; Prototype only: not proved equivalent to CCFRaft.Model.",
        f"; schema={ENCODING_SCHEMA}",
        f"; mutation={mutation}",
        "",
        "(set-logic QF_AUFLIA)",
        "(set-option :produce-models true)",
        "(set-option :produce-unsat-assumptions true)",
        "",
    ]
    query = [
        "",
        "(check-sat-assuming",
        "  (" + "\n   ".join(builder.assumptions) + "))",
    ]
    if mutation == "none":
        query.extend(
            [
                "(get-value",
                "  (" + "\n   ".join(builder.aliases) + "))",
            ]
        )
    else:
        query.append("(get-unsat-assumptions)")
    text = "\n".join(
        [
            *header,
            *builder.declarations,
            "",
            *builder.assertions,
            "",
            *builder.alias_definitions,
            *query,
            "",
        ]
    )
    dimensions = {
        "states": EXPECTED_ACTIONS + 1,
        "state_arrays": (EXPECTED_ACTIONS + 1) * len(STATE_FIELDS),
        "actions": EXPECTED_ACTIONS,
        "labels": len(builder.labels),
        "witness_aliases": len(builder.aliases),
        "smt_declarations": len(builder.declarations),
        "smt_assertions": len(builder.assertions),
        "formula_lines": text.count("\n"),
        "formula_bytes": len(text.encode("utf-8")),
    }
    return Encoding(
        text=text,
        labels=builder.labels,
        query_aliases=builder.aliases,
        observation_provenance=observation_provenance,
        dimensions=dimensions,
        mutation=mutation,
    )


def generate(certificate_path: Path, output_dir: Path, mutation: str) -> None:
    """Generate formula.smt2 from a validated certificate."""

    certificate = load_certificate(certificate_path)
    encoding = build_encoding(certificate, mutation)
    output_dir.mkdir(parents=True, exist_ok=True)
    formula = output_dir / "formula.smt2"
    formula.write_text(encoding.text, encoding="utf-8")
    print(
        f"generated mutation={mutation} states={encoding.dimensions['states']} "
        f"actions={encoding.dimensions['actions']} labels={encoding.dimensions['labels']} "
        f"aliases={encoding.dimensions['witness_aliases']} "
        f"bytes={encoding.dimensions['formula_bytes']}"
    )


def tokenize_sexpressions(text: str) -> list[str]:
    """Tokenize the restricted cvc5 output grammar."""

    return re.findall(r"\(|\)|[^()\s]+", text)


def parse_sexpressions(text: str) -> list[Any]:
    """Parse cvc5 output structurally into nested lists and atoms."""

    tokens = tokenize_sexpressions(text)
    position = 0

    def parse_one() -> Any:
        nonlocal position
        require(position < len(tokens), "unexpected end of solver output")
        token = tokens[position]
        position += 1
        if token != "(":
            require(token != ")", "unexpected ')' in solver output")
            return token
        result = []
        while True:
            require(position < len(tokens), "unclosed '(' in solver output")
            if tokens[position] == ")":
                position += 1
                return result
            result.append(parse_one())

    expressions = []
    while position < len(tokens):
        expressions.append(parse_one())
    return expressions


def atom_value(value: Any) -> int | bool:
    """Decode an integer or Boolean get-value atom."""

    if value == "true":
        return True
    if value == "false":
        return False
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value):
        return int(value)
    if (
        isinstance(value, list)
        and len(value) == 2
        and value[0] == "-"
        and isinstance(value[1], str)
        and value[1].isdigit()
    ):
        return -int(value[1])
    raise EncodingError(f"unsupported solver atom {value!r}")


def parse_sat_solver_output(
    path: Path, expected_aliases: Sequence[str]
) -> dict[str, int | bool]:
    """Parse an exact SAT plus get-value response."""

    expressions = parse_sexpressions(path.read_text(encoding="utf-8"))
    require(expressions, "solver output is empty")
    status = expressions[0]
    if status in ("unsat", "unknown"):
        raise EncodingError("INCONCLUSIVE_ENCODING")
    require(status == "sat", f"solver status is {status!r}, expected sat")
    require(
        len(expressions) == 2,
        f"SAT solver output has {len(expressions)} forms, expected 2",
    )
    raw_values = expressions[1]
    require(isinstance(raw_values, list), "get-value response is not a list")
    values: dict[str, int | bool] = {}
    for pair in raw_values:
        require(
            isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], str),
            f"malformed get-value pair {pair!r}",
        )
        require(pair[0] not in values, f"duplicate solver value {pair[0]}")
        values[pair[0]] = atom_value(pair[1])
    require(
        set(values) == set(expected_aliases),
        "solver get-value aliases differ from the generated witness contract",
    )
    return values


def parse_unsat_solver_output(path: Path) -> list[str]:
    """Parse an exact UNSAT plus unsat-assumptions response."""

    expressions = parse_sexpressions(path.read_text(encoding="utf-8"))
    require(
        len(expressions) == 2,
        f"UNSAT solver output has {len(expressions)} forms, expected 2",
    )
    require(expressions[0] == "unsat", "mutation query did not return UNSAT")
    core = expressions[1]
    require(
        isinstance(core, list) and all(isinstance(label, str) for label in core),
        "unsat assumptions are malformed",
    )
    require(core, "unsat assumptions are empty")
    return core


def require_value(
    values: Mapping[str, int | bool], name: str, expected_type: type
) -> int | bool:
    """Read a typed witness alias."""

    require(name in values, f"missing solver value {name}")
    value = values[name]
    require(type(value) is expected_type, f"solver value {name} has wrong type")
    return value


def decode_entry(
    values: Mapping[str, int | bool],
    prefix: str,
    index: int,
    active: bool,
    certificate: Certificate,
) -> dict[str, Any]:
    """Decode one complete bounded log slot."""

    term = require_value(values, f"{prefix}_log_term_{index:02d}", int)
    tag = require_value(values, f"{prefix}_log_tag_{index:02d}", int)
    tx_id = require_value(values, f"{prefix}_log_tx_{index:02d}", int)
    require(0 <= tag < len(ENTRY_NAMES), f"{prefix}: invalid entry tag {tag}")
    configuration = [
        bool(
            require_value(
                values,
                f"{prefix}_log_config_{index:02d}_{member:02d}",
                bool,
            )
        )
        for member in range(certificate.node_count)
    ]
    return {
        "index": index,
        "active": active,
        "term": term,
        "content": {
            "tag": ENTRY_NAMES[tag],
            "tag_value": tag,
            "transaction_id": tx_id,
            "configuration_membership": configuration,
            "configuration_nodes": [
                member for member, present in enumerate(configuration) if present
            ],
        },
    }


def decode_node(
    values: Mapping[str, int | bool],
    prefix: str,
    node: int,
    certificate: Certificate,
) -> dict[str, Any]:
    """Decode one complete bounded node."""

    role = require_value(values, f"{prefix}_role", int)
    require(0 <= role < len(ROLE_NAMES), f"{prefix}: invalid role {role}")
    log_length = require_value(values, f"{prefix}_log_len", int)
    voted_has = require_value(values, f"{prefix}_voted_for_has", bool)
    voted_value = require_value(values, f"{prefix}_voted_for_value", int)
    votes = [
        bool(require_value(values, f"{prefix}_votes_granted_{peer:02d}", bool))
        for peer in range(certificate.node_count)
    ]
    return {
        "node": node,
        "role": ROLE_NAMES[role],
        "role_value": role,
        "current_term": require_value(values, f"{prefix}_term", int),
        "log_length": log_length,
        "commit_index": require_value(values, f"{prefix}_commit", int),
        "is_new_follower": require_value(values, f"{prefix}_is_new_follower", bool),
        "voted_for": {
            "has_value": voted_has,
            "value": voted_value,
            "node": voted_value if voted_has else None,
        },
        "votes_granted_membership": votes,
        "votes_granted_nodes": [peer for peer, granted in enumerate(votes) if granted],
        "sent_index": [
            require_value(values, f"{prefix}_sent_index_{peer:02d}", int)
            for peer in range(certificate.node_count)
        ],
        "match_index": [
            require_value(values, f"{prefix}_match_index_{peer:02d}", int)
            for peer in range(certificate.node_count)
        ],
        "log_capacity": certificate.log_capacity,
        "log_slots": [
            decode_entry(
                values,
                prefix,
                index,
                index <= log_length,
                certificate,
            )
            for index in range(1, certificate.log_capacity + 1)
        ],
    }


def decode_queue_slot(
    values: Mapping[str, int | bool],
    prefix: str,
    destination: int,
    slot_number: int,
    active: bool,
    certificate: Certificate,
) -> dict[str, Any]:
    """Decode all fields of one bounded queue slot."""

    def field(name: str, expected_type: type) -> int | bool:
        return require_value(
            values,
            f"{prefix}_{name}_{slot_number:02d}",
            expected_type,
        )

    tag = field("queue_tag", int)
    require(0 <= tag < len(MESSAGE_NAMES), f"{prefix}: invalid message tag {tag}")
    entry_tag = field("queue_entry_tag", int)
    require(
        0 <= entry_tag < len(ENTRY_NAMES),
        f"{prefix}: invalid queued entry tag {entry_tag}",
    )
    configuration = [
        bool(
            require_value(
                values,
                f"{prefix}_queue_entry_config_{slot_number:02d}_{member:02d}",
                bool,
            )
        )
        for member in range(certificate.node_count)
    ]
    return {
        "slot": slot_number,
        "active": active,
        "tag": MESSAGE_NAMES[tag],
        "tag_value": tag,
        "source": field("queue_source", int),
        "destination": field("queue_destination", int),
        "term": field("queue_term", int),
        "append_entries_request": {
            "prev_log_index": field("queue_prev_log_index", int),
            "prev_log_term": field("queue_prev_log_term", int),
            "leader_commit": field("queue_leader_commit", int),
            "entry_present": field("queue_entry_present", bool),
            "entry": {
                "term": field("queue_entry_term", int),
                "content": {
                    "tag": ENTRY_NAMES[entry_tag],
                    "tag_value": entry_tag,
                    "transaction_id": field("queue_entry_tx", int),
                    "configuration_membership": configuration,
                    "configuration_nodes": [
                        member
                        for member, present in enumerate(configuration)
                        if present
                    ],
                },
            },
        },
        "append_entries_response": {
            "success": field("queue_response_success", bool),
            "last_log_index": field("queue_response_last_log_index", int),
        },
        "request_vote_request": {
            "last_committable_term": field("queue_vote_last_term", int),
            "last_committable_index": field("queue_vote_last_index", int),
        },
        "request_vote_response": {
            "vote_granted": field("queue_vote_granted", bool),
        },
    }


def decode_queue(
    values: Mapping[str, int | bool],
    prefix: str,
    destination: int,
    certificate: Certificate,
) -> dict[str, Any]:
    """Decode one complete bounded destination FIFO."""

    length = require_value(values, f"{prefix}_length", int)
    return {
        "destination": destination,
        "length": length,
        "capacity": certificate.queue_capacity,
        "slots": [
            decode_queue_slot(
                values,
                prefix,
                destination,
                slot_number,
                slot_number < length,
                certificate,
            )
            for slot_number in range(certificate.queue_capacity)
        ],
    }


def decode_action(
    values: Mapping[str, int | bool],
    number: int,
    certificate: Certificate,
) -> dict[str, Any]:
    """Decode one complete bounded action value."""

    prefix = f"w_action_{number:02d}"
    kind = require_value(values, f"{prefix}_kind", int)
    require(kind in ACTION_KIND_NAMES, f"action {number}: invalid kind {kind}")
    configuration = [
        require_value(values, f"{prefix}_configuration_{member:02d}", bool)
        for member in range(certificate.node_count)
    ]
    certificate_action = certificate.actions[number - 1]
    return {
        "action": number,
        "kind": ACTION_KIND_NAMES[kind],
        "kind_value": kind,
        "source": require_value(values, f"{prefix}_source", int),
        "destination": require_value(values, f"{prefix}_destination", int),
        "parameter": require_value(values, f"{prefix}_parameter", int),
        "transaction": require_value(values, f"{prefix}_transaction", int),
        "configuration_membership": configuration,
        "configuration_nodes": [
            member for member, present in enumerate(configuration) if present
        ],
        "certificate_template": certificate_action["template"],
        "certificate_parameters": certificate_action["parameters"],
        "reduction": certificate.action_reductions[number]["name"],
    }


def build_witness(
    certificate: Certificate,
    encoding: Encoding,
    values: Mapping[str, int | bool],
    formula_path: Path,
    solver_path: Path,
    generator_ms: int,
    solver_ms: int,
    decode_ms: int,
) -> dict[str, Any]:
    """Assemble the versioned complete-S0 SAT witness."""

    fresh_tx = require_value(values, "w_fresh_tx", int)
    initial_nodes = [
        decode_node(
            values,
            f"w_s00_node_{node:02d}",
            node,
            certificate,
        )
        for node in range(certificate.node_count)
    ]
    initial_queues = [
        decode_queue(
            values,
            f"w_s00_queue_{destination:02d}",
            destination,
            certificate,
        )
        for destination in range(certificate.node_count)
    ]
    submitted = [
        require_value(values, f"w_s00_submitted_{tx_id:02d}", bool)
        for tx_id in range(TX_COUNT)
    ]
    joined = [
        require_value(values, f"w_s00_joined_{node:02d}", bool)
        for node in range(certificate.node_count)
    ]
    checkpoints = []
    for step in range(EXPECTED_ACTIONS + 1):
        checkpoint_nodes = [
            decode_node(
                values,
                f"w_checkpoint_{step:02d}_node_{node:02d}",
                node,
                certificate,
            )
            for node in (0, 1)
        ]
        checkpoint_queues = [
            decode_queue(
                values,
                f"w_checkpoint_{step:02d}_queue_{destination:02d}",
                destination,
                certificate,
            )
            for destination in (0, 1)
        ]
        checkpoints.append(
            {
                "state": step,
                "after_action": step if step > 0 else None,
                "nodes": checkpoint_nodes,
                "network": checkpoint_queues,
                "fresh_transaction_submitted": require_value(
                    values,
                    f"w_checkpoint_{step:02d}_fresh_tx_submitted",
                    bool,
                ),
                "has_joined": {
                    "0": require_value(
                        values, f"w_checkpoint_{step:02d}_joined_00", bool
                    ),
                    "1": require_value(
                        values, f"w_checkpoint_{step:02d}_joined_01", bool
                    ),
                },
                "provenance": (
                    "selected complete nodes 0/1 and destination queues 0/1; "
                    "other intermediate nodes are constrained but not decoded"
                ),
            }
        )

    capacities = dict(certificate.data["capacities"])
    capacities["max_total_per_destination_queue"] = certificate.queue_capacity
    capacities["configuration_record_capacity"] = capacities.pop(
        "physical_configuration_record_capacity"
    )
    capacities["configuration_capacity_semantics"] = {
        "distinct_values": capacities["distinct_configuration_value_count"],
        "configuration_records": capacities["configuration_record_capacity"],
        "implicit_record_index": 0,
        "physical_record_indices": [1, 3],
        "max_active_history": capacities["max_active_configuration_history_length"],
    }
    bounds = {
        "node": [0, certificate.node_count - 1],
        "term": [0, certificate.max_term],
        "absolute_log_index": [0, certificate.log_capacity],
        "transaction": [0, TX_COUNT - 1],
        "role_tags": {name: value for value, name in enumerate(ROLE_NAMES)},
        "entry_tags": {name: value for value, name in enumerate(ENTRY_NAMES)},
        "message_tags": {name: value for value, name in enumerate(MESSAGE_NAMES)},
    }
    structural_checks = {
        "encoded_subset_at_all_44_states": [
            "finite role, term, node, index, log, queue, and transaction domains (direct for nodes/queues 0/1; framed from S0 for 2..14)",
            "canonical concrete values for unused log and queue slots (direct for nodes/queues 0/1; framed from S0 for 2..14)",
            "commitIndex <= logLength for all 15 nodes",
            "sentIndex and matchIndex <= source logLength for all 15x15 pairs",
            "active log entry term <= node currentTerm for all 15 nodes",
            "monotone log entry terms for all 15 nodes",
            "positive commit frontier points to a signature for all 15 nodes",
            "nonempty current configuration and bounded active physical configurations for all 15 nodes",
            "election safety for all 15 nodes",
            "committed-prefix consistency for all pairs at S0 and every successor pair touching nodes 0/1; framed-only pairs inherit S0",
            "log matching for all pairs at S0 and every successor pair touching nodes 0/1; framed-only pairs inherit S0",
        ],
        "omitted_from_executable_stateChecks": [],
        "additional_encoded_constraints": [
            "all physical reconfiguration entries are nonempty",
            "sentIndex and matchIndex are globally capacity- and source-log-bounded",
        ],
    }
    projection_categories = {
        "preprocessing_validated": 0,
        "redundant_grammar_bindings": 0,
        "state_constraints": 0,
        "exact_packet_or_span_constraints": 0,
        "weakened_exception_constraints": 0,
        "omissions": 0,
    }
    preprocessing_only_reasons = {
        "trace-envelope-only",
        "scenario-provenance-only",
        "implementation-configuration-metadata",
    }
    for observation in encoding.observation_provenance:
        for field in observation["encoded_fields"]:
            if field["mode"].startswith("source-log-reconstruction"):
                category = "weakened_exception_constraints"
            elif field["certificate_field_kind"] in {
                "event-grammar-constraint",
                "aggregate-span-constraint",
            }:
                category = "redundant_grammar_bindings"
            elif field["certificate_field_kind"] in {
                "wire-packet-constraint",
                "aggregate-packet-range-constraint",
                "aggregate-response-constraint",
            }:
                category = "exact_packet_or_span_constraints"
            else:
                category = "state_constraints"
            projection_categories[category] += 1
        for field in observation["unencoded_fields"]:
            category = (
                "preprocessing_validated"
                if field["reason"] in preprocessing_only_reasons
                else "omissions"
            )
            projection_categories[category] += 1
    source_field_count = sum(projection_categories.values())
    certificate_projected_count = sum(
        len(observation["encoded_fields"])
        for observation in encoding.observation_provenance
    )
    certificate_omitted_count = sum(
        len(observation["unencoded_fields"])
        for observation in encoding.observation_provenance
    )
    projection_summary = {
        "raw_event_rows": EXPECTED_EVENTS,
        "source_field_decisions": source_field_count,
        "category_counts": projection_categories,
        "certificate_status_counts": {
            "projected": certificate_projected_count,
            "omitted": certificate_omitted_count,
        },
        "independent_semantic_constraint_count_claimed": False,
        "all_raw_fields_projected": False,
        "action_span_events": [9, 11, 20, 25, 26, 31],
        "event8_sent_index": {
            "status": "omitted",
            "reason": "event8-sent-index-translation",
        },
        "contract": (
            "Only certificate fields marked projected are encoded, at each "
            "field's explicit field_position."
        ),
    }
    limitations = [
        "This generated bounded encoding is a prototype and is not proved equivalent to CCFRaft.Model.",
        (
            "S0 is an arbitrary existential synthetic pre-commit state, not "
            "initialState and not claimed Reachable."
        ),
        (
            "Unobserved nodes are not forced inert. Solver completions such as "
            "node 2 with role none and log length 7 are allowed by the encoded "
            "subset; canonical Lean stateChecks must decide full validity."
        ),
        "The term bound 0..2, log capacity 7, queue capacity, configurations, and action skeleton are trace-derived.",
        "Only nodes 0 and 1 and queues 0 and 1 are decoded at intermediate checkpoints; S0 is decoded completely.",
        (
            "Event 5's C++ heartbeat endpoint is reconstructed from the retained "
            "source log because the reduction's event-3 exception replaces that "
            "wire heartbeat with a canonical entry-3 request."
        ),
        (
            "C++ multi-entry packets and aggregate responses are related to the "
            "full corrected action span and its start/end packet members; they "
            "are not encoded as a single-action checkpoint."
        ),
        (
            "Event 8 sent_idx=2 is retained only as an explicit correspondence "
            "omission/translation because no canonical checkpoint has that value."
        ),
        "The encoding does not claim that every raw observation field projects.",
        "No Lean replay or equivalence theorem is produced by this task.",
    ]
    return {
        "schema_version": WITNESS_SCHEMA,
        "encoding_schema_version": ENCODING_SCHEMA,
        "sat_classification": "SAT_BOUNDED_PROTOTYPE",
        "solver_status": "sat",
        "hashes": {
            "certificate_sha256": sha256_file(certificate.path),
            "model_sha256": sha256_file(Path(__file__).with_name("Model.lean")),
            "generator_sha256": sha256_file(Path(__file__)),
            "formula_sha256": sha256_file(formula_path),
            "solver_output_sha256": sha256_file(solver_path),
            "input_trace_sha256": certificate.data["input"]["sha256"],
        },
        "capacities": capacities,
        "bounds": bounds,
        "counts": {
            **certificate.data["counts"],
            "states": EXPECTED_ACTIONS + 1,
            "decoded_intermediate_checkpoints": EXPECTED_ACTIONS + 1,
        },
        "formula_dimensions": encoding.dimensions,
        "timings_ms": {
            "formula_generation": generator_ms,
            "direct_smt": solver_ms,
            "decode": decode_ms,
            "under_60_second_prototype_target": solver_ms < 60_000,
        },
        "fresh_transaction_id": fresh_tx,
        "initial_state_semantics": {
            "canonical_initial_state": False,
            "reachable_claim": False,
            "arbitrary_existential_completion": True,
            "unobserved_nodes_forced_inert": False,
            "intended_checker": (
                "canonical Lean stateChecks, not Reachable; this task encodes "
                "only the structural subset listed in structural_checks"
            ),
        },
        "initial_state": {
            "state": 0,
            "synthetic_checkpoint": "event 1 pre-commit",
            "nodes": initial_nodes,
            "network": initial_queues,
            "submitted_transaction_membership": submitted,
            "submitted_transaction_ids": [
                tx_id for tx_id, present in enumerate(submitted) if present
            ],
            "has_joined_membership": joined,
            "has_joined_nodes": [
                node for node, present in enumerate(joined) if present
            ],
        },
        "actions": [
            decode_action(values, number, certificate)
            for number in range(1, EXPECTED_ACTIONS + 1)
        ],
        "reductions": [
            {
                "reduction": reduction["reduction"],
                "name": reduction["name"],
                "events": reduction["events"],
                "actions": [action["action"] for action in reduction["actions"]],
                "summary": reduction["summary"],
                "exception_ids": reduction["exception_ids"],
                "transition_labels": [
                    label
                    for label in encoding.labels
                    if label.startswith(f"reduction{reduction['reduction']:02d}_")
                ],
            }
            for reduction in certificate.data["reductions"]
        ],
        "intermediate_selected_states": checkpoints,
        "field_provenance": {
            "state_arrays": {
                field: {
                    "smt_sort": f"(Array Int {sort})",
                    "states": "S0..S43",
                }
                for field, sort in STATE_FIELDS.items()
            },
            "initial_state": (
                "all 15 nodes, all 15 destination queues and all queue slots, "
                "all 64 submitted transaction bits, and all 15 hasJoined bits"
            ),
            "intermediate_states": (
                "complete retained nodes 0/1, complete queues 0/1, fresh "
                "transaction membership, and hasJoined bits 0/1 at S0..S43"
            ),
            "projection_summary": projection_summary,
            "observations": encoding.observation_provenance,
        },
        "structural_checks": structural_checks,
        "limitations": limitations,
    }


def validate_witness_data(witness: Mapping[str, Any], certificate: Certificate) -> None:
    """Validate schema, counts, hashes, and complete field presence."""

    require(
        witness.get("schema_version") == WITNESS_SCHEMA,
        "witness schema is absent or unsupported",
    )
    require(
        witness.get("sat_classification") == "SAT_BOUNDED_PROTOTYPE",
        "witness is not classified SAT_BOUNDED_PROTOTYPE",
    )
    counts = witness.get("counts")
    require(isinstance(counts, dict), "witness counts are absent")
    require(counts.get("events") == EXPECTED_EVENTS, "witness event count differs")
    require(
        counts.get("reductions") == EXPECTED_REDUCTIONS,
        "witness reduction count differs",
    )
    require(counts.get("actions") == EXPECTED_ACTIONS, "witness action count differs")
    require(counts.get("states") == 44, "witness state count differs")
    capacity_semantics = witness.get("capacities", {}).get(
        "configuration_capacity_semantics"
    )
    require(
        capacity_semantics
        == {
            "distinct_values": 2,
            "configuration_records": 3,
            "implicit_record_index": 0,
            "physical_record_indices": [1, 3],
            "max_active_history": 2,
        },
        "witness conflates configuration values with configuration records",
    )
    initial = witness.get("initial_state")
    require(isinstance(initial, dict), "witness initial_state is absent")
    require(
        witness.get("initial_state_semantics")
        == {
            "canonical_initial_state": False,
            "reachable_claim": False,
            "arbitrary_existential_completion": True,
            "unobserved_nodes_forced_inert": False,
            "intended_checker": (
                "canonical Lean stateChecks, not Reachable; this task encodes "
                "only the structural subset listed in structural_checks"
            ),
        },
        "witness overstates S0 reachability or canonical validity",
    )
    nodes = initial.get("nodes")
    network = initial.get("network")
    submitted = initial.get("submitted_transaction_membership")
    joined = initial.get("has_joined_membership")
    require(
        isinstance(nodes, list) and len(nodes) == certificate.node_count,
        "witness S0 does not contain all nodes",
    )
    require(
        isinstance(network, list) and len(network) == certificate.node_count,
        "witness S0 does not contain all destination queues",
    )
    require(
        isinstance(submitted, list) and len(submitted) == TX_COUNT,
        "witness S0 does not contain all Fin 64 submitted bits",
    )
    require(
        isinstance(joined, list) and len(joined) == certificate.node_count,
        "witness S0 does not contain all hasJoined bits",
    )
    node_keys = {
        "node",
        "role",
        "role_value",
        "current_term",
        "log_length",
        "commit_index",
        "is_new_follower",
        "voted_for",
        "votes_granted_membership",
        "votes_granted_nodes",
        "sent_index",
        "match_index",
        "log_capacity",
        "log_slots",
    }
    for node in nodes:
        require(
            isinstance(node, dict) and node_keys <= set(node),
            "witness S0 node omits a required field",
        )
        require(
            len(node["votes_granted_membership"]) == certificate.node_count
            and len(node["sent_index"]) == certificate.node_count
            and len(node["match_index"]) == certificate.node_count
            and len(node["log_slots"]) == certificate.log_capacity,
            "witness S0 node has an incomplete bounded field",
        )
        for slot in node["log_slots"]:
            require(
                isinstance(slot, dict)
                and {
                    "index",
                    "active",
                    "term",
                    "content",
                }
                <= set(slot),
                "witness S0 log slot omits a required field",
            )
            require(
                isinstance(slot["content"], dict)
                and {
                    "tag",
                    "tag_value",
                    "transaction_id",
                    "configuration_membership",
                    "configuration_nodes",
                }
                <= set(slot["content"])
                and len(slot["content"]["configuration_membership"])
                == certificate.node_count,
                "witness S0 log content is incomplete",
            )
    for queue in network:
        require(
            isinstance(queue, dict)
            and len(queue.get("slots", [])) == certificate.queue_capacity,
            "witness S0 queue is incomplete",
        )
        for slot in queue["slots"]:
            require(
                isinstance(slot, dict)
                and {
                    "slot",
                    "active",
                    "tag",
                    "tag_value",
                    "source",
                    "destination",
                    "term",
                    "append_entries_request",
                    "append_entries_response",
                    "request_vote_request",
                    "request_vote_response",
                }
                <= set(slot),
                "witness S0 queue slot omits a required field",
            )
            request = slot["append_entries_request"]
            require(
                isinstance(request, dict)
                and {
                    "prev_log_index",
                    "prev_log_term",
                    "leader_commit",
                    "entry_present",
                    "entry",
                }
                <= set(request),
                "witness S0 queued request is incomplete",
            )
            entry = request["entry"]
            require(
                isinstance(entry, dict)
                and {"term", "content"} <= set(entry)
                and len(entry["content"]["configuration_membership"])
                == certificate.node_count,
                "witness S0 queued entry is incomplete",
            )
    require(
        isinstance(witness.get("actions"), list)
        and len(witness["actions"]) == EXPECTED_ACTIONS,
        "witness actions are incomplete",
    )
    require(
        isinstance(witness.get("intermediate_selected_states"), list)
        and len(witness["intermediate_selected_states"]) == 44,
        "witness intermediate checkpoints are incomplete",
    )
    for checkpoint in witness["intermediate_selected_states"]:
        require(
            isinstance(checkpoint, dict)
            and len(checkpoint.get("nodes", [])) == 2
            and len(checkpoint.get("network", [])) == 2
            and "fresh_transaction_submitted" in checkpoint
            and "has_joined" in checkpoint,
            "witness intermediate checkpoint is incomplete",
        )
    observations = witness.get("field_provenance", {}).get("observations")
    require(
        isinstance(observations, list) and len(observations) == EXPECTED_EVENTS,
        "witness observation provenance is incomplete",
    )
    require(
        all(observation.get("encoded_fields") for observation in observations),
        "an event has no encoded field provenance",
    )
    for event_number in (9, 11, 20, 25, 26, 31):
        observation = observations[event_number - 1]
        require(
            all(
                field.get("mode", "").startswith("explicit-whole-action-span-")
                for field in observation["encoded_fields"]
                if field.get("certificate_field_position", {}).get("kind")
                == "whole_action_span"
            ),
            f"event {event_number} aggregate fields are not span constraints",
        )
        require(
            all(
                field.get("certificate_field_position", {}).get("kind") == "span_start"
                for field in observation["encoded_fields"]
                if field.get("certificate_field_kind") == "pre-state-scalar"
            ),
            f"event {event_number} pre-state fields are not at span start",
        )
    projection_summary = witness.get("field_provenance", {}).get("projection_summary")
    require(
        isinstance(projection_summary, dict)
        and projection_summary.get("all_raw_fields_projected") is False
        and projection_summary.get("independent_semantic_constraint_count_claimed")
        is False
        and projection_summary.get("action_span_events") == [9, 11, 20, 25, 26, 31]
        and projection_summary.get("event8_sent_index", {}).get("status") == "omitted",
        "witness observation projection scope is overstated",
    )
    category_counts = projection_summary.get("category_counts")
    require(
        isinstance(category_counts, dict)
        and set(category_counts)
        == {
            "preprocessing_validated",
            "redundant_grammar_bindings",
            "state_constraints",
            "exact_packet_or_span_constraints",
            "weakened_exception_constraints",
            "omissions",
        }
        and sum(category_counts.values())
        == projection_summary.get("source_field_decisions"),
        "witness projection category breakdown is incomplete",
    )
    event8 = observations[7]
    require(
        event8.get("event") == 8
        and any(
            field.get("path") == "msg.sent_idx"
            and field.get("reason") == "event8-sent-index-translation"
            for field in event8.get("unencoded_fields", [])
        ),
        "witness omits event 8 sent-index translation provenance",
    )
    omitted = witness.get("structural_checks", {}).get(
        "omitted_from_executable_stateChecks"
    )
    require(omitted == [], "witness retains executable stateChecks omissions")


def render_report(witness: Mapping[str, Any]) -> str:
    """Render the deterministic Markdown report."""

    dimensions = witness["formula_dimensions"]
    timings = witness["timings_ms"]
    initial = witness["initial_state"]
    node0 = initial["nodes"][0]
    node1 = initial["nodes"][1]
    node2 = initial["nodes"][2]
    formula_size = dimensions["formula_bytes"]
    target = "yes" if timings["under_60_second_prototype_target"] else "no"
    projection = witness["field_provenance"]["projection_summary"]
    projection_counts = projection["category_counts"]
    return f"""# Naive full-state bounded SMT prototype

Result: `SAT_BOUNDED_PROTOTYPE`

- Formula: QF_AUFLIA, {dimensions['states']} complete states, {dimensions['state_arrays']} state arrays, {dimensions['labels']} labelled constraints, {dimensions['witness_aliases']} decoded atoms, {formula_size} bytes.
- Direct cvc5: {timings['direct_smt']} ms; under the soft 60 s target: {target}.
- Fresh `Fin 64` transaction: `{witness['fresh_transaction_id']}`.
- S0 node 0: role `{node0['role']}`, term {node0['current_term']}, log length {node0['log_length']}, commit {node0['commit_index']}.
- S0 node 1: role `{node1['role']}`, term {node1['current_term']}, log length {node1['log_length']}, commit {node1['commit_index']}.
- S0 network messages: {sum(queue['length'] for queue in initial['network'])}; submitted transactions: {len(initial['submitted_transaction_ids'])}; joined nodes: {initial['has_joined_nodes']}.
- Configuration capacity: 2 distinct values; three configuration records: implicit 0, physical 1 and 3; active history capacity 2.
- Observation field classes: preprocessing-validated {projection_counts['preprocessing_validated']}; redundant grammar bindings {projection_counts['redundant_grammar_bindings']}; state constraints {projection_counts['state_constraints']}; exact packet/span constraints {projection_counts['exact_packet_or_span_constraints']}; weakened exception constraints {projection_counts['weakened_exception_constraints']}; omissions {projection_counts['omissions']}.

## Structural scope

Encoded subset at every state: finite domains and canonical unused slots; commit/log, sent/log, and match/log bounds; monotone bounded log terms; committed-frontier signatures; nonempty bounded configurations; election safety, committed-prefix consistency, and log matching for all 15 nodes.

Omitted from executable `stateChecks`: none. Nodes 2 through 14 remain existential and are not hardcoded inert.

## Initial-state semantics

S0 is an arbitrary existential synthetic pre-commit state, not `initialState` and not claimed `Reachable`. Unobserved nodes are not forced inert. This model chose node 2 role `{node2['role']}` with log length {node2['log_length']}; the encoded subset allows that completion. A future canonical Lean `stateChecks` checker, not `Reachable`, must decide full validity.

## Limitations

This is a trace-derived generated prototype, not a proof of equivalence to `CCFRaft.Model` or full state validity. Event 5 uses source-log reconstruction under the recorded event-3 correspondence exception. Events 9, 11, 20, 25, 26, and 31 constrain explicit whole-action spans and their packet endpoints, not a single action checkpoint. Event 8 `sent_idx=2` remains an explicit omission/translation. The encoding does not claim all raw fields project. No Lean replay is included.
"""


def write_report(output_dir: Path, witness: Mapping[str, Any]) -> None:
    """Write the concise required Markdown report."""

    (output_dir / "report.md").write_text(render_report(witness), encoding="utf-8")


def decode(
    certificate_path: Path,
    output_dir: Path,
    generator_ms: int,
    solver_ms: int,
) -> int:
    """Decode solver.out into witness-v1.json and report.md."""

    started = time.perf_counter_ns()
    certificate = load_certificate(certificate_path)
    encoding = build_encoding(certificate, "none")
    formula_path = output_dir / "formula.smt2"
    solver_path = output_dir / "solver.out"
    require(formula_path.exists(), "formula.smt2 is absent")
    require(solver_path.exists(), "solver.out is absent")
    require(
        formula_path.read_text(encoding="utf-8") == encoding.text,
        "formula.smt2 differs from deterministic regeneration",
    )
    try:
        values = parse_sat_solver_output(solver_path, encoding.query_aliases)
    except EncodingError as error:
        if str(error) == "INCONCLUSIVE_ENCODING":
            print("classification=INCONCLUSIVE_ENCODING")
            return 3
        raise
    decode_ms = (time.perf_counter_ns() - started) // 1_000_000
    witness = build_witness(
        certificate,
        encoding,
        values,
        formula_path,
        solver_path,
        generator_ms,
        solver_ms,
        decode_ms,
    )
    validate_witness_data(witness, certificate)
    write_json(output_dir / "witness-v1.json", witness)
    write_report(output_dir, witness)
    print(
        f"decoded classification={witness['sat_classification']} "
        f"fresh_tx={witness['fresh_transaction_id']} decode_ms={decode_ms}"
    )
    return 0


def validate_witness(certificate_path: Path, output_dir: Path) -> None:
    """Reparse SAT output and compare the rebuilt witness and report."""

    certificate = load_certificate(certificate_path)
    encoding = build_encoding(certificate, "none")
    formula_path = output_dir / "formula.smt2"
    solver_path = output_dir / "solver.out"
    witness_path = output_dir / "witness-v1.json"
    try:
        witness = json.loads(witness_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise EncodingError(f"witness JSON is invalid: {error}") from error
    require(isinstance(witness, dict), "witness top level is not an object")
    validate_witness_data(witness, certificate)
    require(
        formula_path.read_text(encoding="utf-8") == encoding.text,
        "saved formula differs from deterministic regeneration",
    )
    values = parse_sat_solver_output(solver_path, encoding.query_aliases)
    timings = witness.get("timings_ms")
    require(
        isinstance(timings, dict)
        and all(
            isinstance(timings.get(field), int)
            for field in ("formula_generation", "direct_smt", "decode")
        ),
        "witness timings required for stable reconstruction are absent",
    )
    rebuilt = build_witness(
        certificate,
        encoding,
        values,
        formula_path,
        solver_path,
        timings["formula_generation"],
        timings["direct_smt"],
        timings["decode"],
    )
    validate_witness_data(rebuilt, certificate)
    require(
        witness == rebuilt,
        "saved witness semantic values differ from the reparsed SAT model",
    )
    report_path = output_dir / "report.md"
    require(
        report_path.read_text(encoding="utf-8") == render_report(rebuilt),
        "saved report differs from deterministic witness rendering",
    )
    hashes = witness["hashes"]
    require(
        hashes["certificate_sha256"] == sha256_file(certificate_path),
        "witness certificate hash differs",
    )
    require(
        hashes["formula_sha256"] == sha256_file(output_dir / "formula.smt2"),
        "witness formula hash differs",
    )
    require(
        hashes["solver_output_sha256"] == sha256_file(output_dir / "solver.out"),
        "witness solver output hash differs",
    )
    require(
        hashes["generator_sha256"] == sha256_file(Path(__file__)),
        "witness generator hash differs",
    )
    require(
        hashes["model_sha256"] == sha256_file(Path(__file__).with_name("Model.lean")),
        "witness model hash differs",
    )
    print(
        f"validated schema={WITNESS_SCHEMA} events={EXPECTED_EVENTS} "
        f"reductions={EXPECTED_REDUCTIONS} actions={EXPECTED_ACTIONS} states=44"
    )


def validate_mutation(
    certificate_path: Path,
    output_dir: Path,
    mutation: str,
) -> None:
    """Validate one intentionally UNSAT mutation and its diagnostic labels."""

    certificate = load_certificate(certificate_path)
    encoding = build_encoding(certificate, mutation)
    require(
        (output_dir / "formula.smt2").read_text(encoding="utf-8") == encoding.text,
        "mutation formula differs from deterministic regeneration",
    )
    core = parse_unsat_solver_output(output_dir / "solver.out")
    require(
        all(label in encoding.labels for label in core),
        "mutation core contains an unknown label",
    )
    if mutation == "conflicting-observed-commit":
        required = [
            "event53_msg_state_commit_idx",
            "reduction21_action40_advanceCommitIndex",
            "reduction22_action41_appendEntries",
            "reduction22_action42_receive",
        ]
        require(
            all(label in core for label in required),
            "in-domain commit core omits observation or transition/frame labels",
        )
    elif mutation == "wrong-destination-action-param":
        require(
            0 <= 2 < certificate.node_count, "mutation destination is not in-domain"
        )
        required = [
            "action03_certificate_skeleton",
            "reduction02_action03_appendEntries",
            "event05_msg_packet_msg",
        ]
        require(
            all(label in core for label in required),
            "wrong-destination core omits skeleton, transition, or observation labels",
        )
    else:
        raise EncodingError(f"unsupported mutation validation {mutation}")
    print(
        f"mutation={mutation} status=unsat core_labels={len(core)} "
        f"required_labels={','.join(required)}"
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse generator, decoder, and validator commands."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate")
    generate_parser.add_argument("--certificate", type=Path, required=True)
    generate_parser.add_argument("--output-dir", type=Path, required=True)
    generate_parser.add_argument(
        "--mutation",
        choices=(
            "none",
            "conflicting-observed-commit",
            "wrong-destination-action-param",
        ),
        default="none",
    )

    decode_parser = subparsers.add_parser("decode")
    decode_parser.add_argument("--certificate", type=Path, required=True)
    decode_parser.add_argument("--output-dir", type=Path, required=True)
    decode_parser.add_argument("--generator-ms", type=int, required=True)
    decode_parser.add_argument("--solver-ms", type=int, required=True)

    validate_parser = subparsers.add_parser("validate-witness")
    validate_parser.add_argument("--certificate", type=Path, required=True)
    validate_parser.add_argument("--output-dir", type=Path, required=True)

    mutation_parser = subparsers.add_parser("validate-mutation")
    mutation_parser.add_argument("--certificate", type=Path, required=True)
    mutation_parser.add_argument("--output-dir", type=Path, required=True)
    mutation_parser.add_argument(
        "--mutation",
        choices=(
            "conflicting-observed-commit",
            "wrong-destination-action-param",
        ),
        required=True,
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested generator operation."""

    args = parse_args(argv)
    try:
        if args.command == "generate":
            generate(args.certificate, args.output_dir, args.mutation)
        elif args.command == "decode":
            return decode(
                args.certificate,
                args.output_dir,
                args.generator_ms,
                args.solver_ms,
            )
        elif args.command == "validate-witness":
            validate_witness(args.certificate, args.output_dir)
        elif args.command == "validate-mutation":
            validate_mutation(args.certificate, args.output_dir, args.mutation)
        else:
            raise EncodingError(f"unknown command {args.command}")
        return 0
    except (EncodingError, KeyError, OSError, TypeError, ValueError) as error:
        print(f"naive-full-state-smt: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
