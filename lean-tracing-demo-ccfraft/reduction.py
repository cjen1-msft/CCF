#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Reduce captured CCF Raft NDJSON to canonical CCFRaft certificates."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from Shared.trace_io import NDJSONRecord, read_ndjson

SCHEMA_VERSION = "ccfraft-reduction-certificate/v2"

KNOWN_FUNCTIONS = {
    "add_configuration",
    "become_candidate",
    "become_follower",
    "become_leader",
    "commit",
    "drop_pending_to",
    "execute_append_entries_sync",
    "recv_append_entries",
    "recv_append_entries_response",
    "recv_request_vote",
    "recv_request_vote_response",
    "replicate",
    "send_append_entries",
    "send_append_entries_response",
    "send_request_vote",
}

IGNORED_RULES = {
    "associate-command": (
        "The command marker is associated with following trace events and has "
        "no CCFRaft transition."
    ),
    "remove-replicate-before-add-configuration": (
        "CCF emits replicate for the ledger write immediately consumed by "
        "add_configuration; changeConfiguration represents the write."
    ),
    "ignore-drop-pending-message": (
        "The captured demo model has no network-drop action; retain the drop "
        "explicitly as an audited omission."
    ),
}


class ReductionError(RuntimeError):
    """Report a trace shape outside the manually audited reduction."""


@dataclass(frozen=True)
class AssociatedEvent:
    record: NDJSONRecord
    function: str
    message: dict[str, Any]
    state: dict[str, Any]
    node: str
    command: str
    command_line: int


@dataclass
class PreprocessedEvent:
    kind: str
    rule: str
    events: tuple[AssociatedEvent, ...]
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def first_line(self) -> int:
        return min(event.record.line_number for event in self.events)


@dataclass(frozen=True)
class IgnoredEvent:
    rule: str
    reason: str
    records: tuple[NDJSONRecord, ...]
    function: str | None = None

    @property
    def first_line(self) -> int:
        return min(record.line_number for record in self.records)


@dataclass
class PreprocessedTrace:
    records: tuple[NDJSONRecord, ...]
    events: list[PreprocessedEvent]
    ignored_events: list[IgnoredEvent]
    groups: list[dict[str, Any]]
    command_associations: list[dict[str, Any]]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReductionError(message)


def _natural(value: Any, label: str) -> int:
    _require(
        type(value) is int and value >= 0,
        f"{label} must be a non-negative integer",
    )
    return value


def _node(value: Any, label: str) -> str:
    _require(
        (isinstance(value, str) and value != "") or (type(value) is int and value >= 0),
        f"{label} must be a non-empty string or natural number",
    )
    return str(value)


def _role(event: AssociatedEvent) -> str:
    raw = event.state.get("leadership_state")
    _require(
        raw in {"None", "Follower", "Candidate", "Leader"},
        f"line {event.record.line_number}: unsupported leadership_state {raw!r}",
    )
    return str(raw)


def _packet(event: AssociatedEvent, family: str) -> dict[str, Any]:
    packet = event.message.get("packet")
    _require(
        isinstance(packet, dict),
        f"line {event.record.line_number}: packet is not an object",
    )
    _require(
        packet.get("msg") == family,
        f"line {event.record.line_number}: expected packet family {family}",
    )
    return packet


def _append_range(event: AssociatedEvent) -> tuple[int, int]:
    packet = _packet(event, "raft_append_entries")
    previous = _natural(
        packet.get("prev_idx"),
        f"line {event.record.line_number}: packet.prev_idx",
    )
    end = _natural(
        packet.get("idx"),
        f"line {event.record.line_number}: packet.idx",
    )
    _require(
        previous <= end,
        f"line {event.record.line_number}: AppendEntries range is reversed",
    )
    _natural(packet.get("term"), f"line {event.record.line_number}: packet.term")
    return previous, end


def _split_ends(event: AssociatedEvent) -> list[int]:
    previous, end = _append_range(event)
    return [end] if previous == end else list(range(previous + 1, end + 1))


def _configuration(event: AssociatedEvent) -> tuple[int, list[str]]:
    args = event.message.get("args")
    _require(
        isinstance(args, dict) and isinstance(args.get("configuration"), dict),
        f"line {event.record.line_number}: configuration arguments are missing",
    )
    configuration = args["configuration"]
    index = _natural(
        configuration.get("idx"),
        f"line {event.record.line_number}: configuration.idx",
    )
    nodes = configuration.get("nodes")
    _require(
        isinstance(nodes, (dict, list)),
        f"line {event.record.line_number}: configuration.nodes is malformed",
    )
    raw_nodes = list(nodes) if isinstance(nodes, dict) else nodes
    normalized = sorted(
        {_node(value, "configuration node") for value in raw_nodes},
        key=_node_sort_key,
    )
    _require(
        normalized,
        f"line {event.record.line_number}: configuration is empty",
    )
    return index, normalized


def _node_sort_key(value: str) -> tuple[int, int | str]:
    return (0, int(value)) if value.isdigit() else (1, value)


def _provenance(
    events: Sequence[AssociatedEvent],
) -> list[dict[str, Any]]:
    entries = [
        {
            "function": event.function,
            "line": event.record.line_number,
            "timestamp": event.record.value["h_ts"],
        }
        for event in events
    ]
    unique = {entry["line"]: entry for entry in entries}
    return [unique[line] for line in sorted(unique)]


def _ignored(
    rule: str,
    records: Sequence[NDJSONRecord],
    *,
    function: str | None = None,
) -> IgnoredEvent:
    _require(rule in IGNORED_RULES, f"unknown ignored-event rule {rule}")
    return IgnoredEvent(
        rule=rule,
        reason=IGNORED_RULES[rule],
        records=tuple(records),
        function=function,
    )


def _associate_commands(
    records: Sequence[NDJSONRecord],
) -> tuple[list[AssociatedEvent], list[IgnoredEvent]]:
    events: list[AssociatedEvent] = []
    ignored: list[IgnoredEvent] = []
    command = ""
    command_line = 0
    previous_timestamp = -1
    for record in records:
        row = record.value
        if "cmd" in row:
            _require(
                set(row) == {"cmd", "tag"}
                and row.get("tag") == "raft_trace"
                and isinstance(row["cmd"], str)
                and bool(row["cmd"]),
                f"line {record.line_number}: malformed command marker",
            )
            command = row["cmd"]
            command_line = record.line_number
            ignored.append(_ignored("associate-command", [record]))
            continue

        _require(
            command_line != 0,
            f"line {record.line_number}: event precedes the first command",
        )
        _require(
            row.get("tag") == "raft_trace",
            f"line {record.line_number}: expected tag raft_trace",
        )
        message = row.get("msg")
        _require(
            isinstance(message, dict),
            f"line {record.line_number}: msg is not an object",
        )
        function = message.get("function")
        _require(
            isinstance(function, str),
            f"line {record.line_number}: msg.function is missing",
        )
        _require(
            function in KNOWN_FUNCTIONS,
            f"line {record.line_number}: unaudited function {function!r}",
        )
        state = message.get("state")
        _require(
            isinstance(state, dict),
            f"line {record.line_number}: msg.state is not an object",
        )
        node = _node(
            state.get("node_id"),
            f"line {record.line_number}: state.node_id",
        )
        _role_value = state.get("leadership_state")
        _require(
            _role_value in {"None", "Follower", "Candidate", "Leader"},
            f"line {record.line_number}: unsupported leadership_state "
            f"{_role_value!r}",
        )
        _natural(
            state.get("current_view"),
            f"line {record.line_number}: state.current_view",
        )
        _natural(
            state.get("last_idx"),
            f"line {record.line_number}: state.last_idx",
        )
        _natural(
            state.get("commit_idx"),
            f"line {record.line_number}: state.commit_idx",
        )
        _require(
            state.get("membership_state") == "Active",
            f"line {record.line_number}: unsupported membership_state",
        )
        timestamp = row.get("h_ts")
        _require(
            isinstance(timestamp, str) and timestamp.isdigit(),
            f"line {record.line_number}: h_ts is not a decimal string",
        )
        numeric_timestamp = int(timestamp)
        _require(
            numeric_timestamp > previous_timestamp,
            f"line {record.line_number}: h_ts is not strictly increasing",
        )
        previous_timestamp = numeric_timestamp
        events.append(
            AssociatedEvent(
                record,
                function,
                message,
                state,
                node,
                command,
                command_line,
            )
        )
    return events, ignored


def _remove_configuration_replicates(
    events: Sequence[AssociatedEvent],
    ignored: list[IgnoredEvent],
) -> list[AssociatedEvent]:
    retained: list[AssociatedEvent] = []
    for event in events:
        if event.function == "add_configuration" and _role(event) == "Leader":
            _require(
                bool(retained),
                f"line {event.record.line_number}: leader configuration has no "
                "paired replicate",
            )
            replicate = retained.pop()
            _require(
                replicate.function == "replicate"
                and replicate.node == event.node
                and replicate.message.get("globally_committable") is False,
                f"line {event.record.line_number}: preceding event is not the "
                "audited configuration replicate",
            )
            configuration_index, _ = _configuration(event)
            _require(
                replicate.message.get("seqno") == configuration_index,
                f"line {event.record.line_number}: configuration replicate "
                "index differs",
            )
            ignored.append(
                _ignored(
                    "remove-replicate-before-add-configuration",
                    [replicate.record],
                    function=replicate.function,
                )
            )
        retained.append(event)
    return retained


def _collapse_bootstrap(
    events: list[AssociatedEvent],
    groups: list[dict[str, Any]],
) -> list[PreprocessedEvent]:
    _require(len(events) >= 4, "trace is too short for the bootstrap sequence")
    bootstrap = events[:4]
    _require(
        [event.function for event in bootstrap]
        == [
            "become_leader",
            "add_configuration",
            "replicate",
            "commit",
        ],
        "trace does not begin with the audited bootstrap sequence",
    )
    leader = bootstrap[0].node
    _require(
        all(event.node == leader for event in bootstrap),
        "bootstrap events name different nodes",
    )
    _require(
        _role(bootstrap[0]) == "Leader"
        and _role(bootstrap[1]) == "Leader"
        and _role(bootstrap[2]) == "Leader"
        and _role(bootstrap[3]) == "Leader",
        "bootstrap events do not remain on the initial leader",
    )
    configuration_index, nodes = _configuration(bootstrap[1])
    _require(
        configuration_index == 1 and nodes == [leader],
        "bootstrap configuration is not the singleton leader at index 1",
    )
    _require(
        bootstrap[2].message.get("globally_committable") is True
        and bootstrap[2].message.get("seqno") == 2,
        "bootstrap signature is not the committable entry at index 2",
    )
    commit_args = bootstrap[3].message.get("args")
    _require(
        isinstance(commit_args, dict) and commit_args.get("idx") == 2,
        "bootstrap commit does not target index 2",
    )
    groups.append(
        {
            "functions": [event.function for event in bootstrap],
            "provenance": _provenance(bootstrap),
            "rule": "collapse-bootstrap-sequence",
        }
    )
    return [
        PreprocessedEvent(
            "bootstrap",
            "collapse-bootstrap-sequence",
            tuple(bootstrap),
            {"leader": leader, "commit_event": bootstrap[3]},
        ),
        *[
            PreprocessedEvent(event.function, "retain-audited-event", (event,))
            for event in events[4:]
        ],
    ]


def _is_newer_term_pair(
    receive: AssociatedEvent,
    follower: AssociatedEvent,
) -> bool:
    if follower.function != "become_follower" or follower.node != receive.node:
        return False
    packet = receive.message.get("packet")
    _require(
        isinstance(packet, dict),
        f"line {receive.record.line_number}: receive packet is missing",
    )
    packet_term = _natural(
        packet.get("term"),
        f"line {receive.record.line_number}: packet.term",
    )
    previous_term = _natural(
        receive.state.get("current_view"),
        f"line {receive.record.line_number}: state.current_view",
    )
    follower_term = _natural(
        follower.state.get("current_view"),
        f"line {follower.record.line_number}: state.current_view",
    )
    _require(
        packet_term > previous_term and follower_term == packet_term,
        f"lines {receive.record.line_number}-{follower.record.line_number}: "
        "become_follower does not prove a newer-term transition",
    )
    return True


def _group_events(
    initial: list[PreprocessedEvent],
    ignored: list[IgnoredEvent],
    groups: list[dict[str, Any]],
) -> list[PreprocessedEvent]:
    result = [initial[0]]
    raw = [event.events[0] for event in initial[1:]]
    index = 0
    receive_functions = {
        "recv_append_entries",
        "recv_request_vote",
        "recv_request_vote_response",
    }
    while index < len(raw):
        event = raw[index]
        if event.function == "drop_pending_to":
            ignored.append(
                _ignored(
                    "ignore-drop-pending-message",
                    [event.record],
                    function=event.function,
                )
            )
            index += 1
            continue

        if event.function == "recv_append_entries":
            grouped = [event]
            index += 1
            if index < len(raw) and raw[index].function == "become_follower":
                _require(
                    _is_newer_term_pair(event, raw[index]),
                    "internal newer-term grouping failure",
                )
                grouped.append(raw[index])
                groups.append(
                    {
                        "functions": [event.function, raw[index].function],
                        "provenance": _provenance([event, raw[index]]),
                        "rule": "group-newer-term-receive-become-follower",
                    }
                )
                index += 1
            helper_functions: list[str] = []
            while index < len(raw):
                helper = raw[index]
                if helper.function not in {
                    "execute_append_entries_sync",
                    "add_configuration",
                    "commit",
                    "send_append_entries_response",
                }:
                    break
                _require(
                    helper.node == event.node,
                    f"line {helper.record.line_number}: interleaved receive helper",
                )
                if helper.function in {"add_configuration", "commit"}:
                    _require(
                        _role(helper) != "Leader",
                        f"line {helper.record.line_number}: leader event cannot be "
                        "an AppendEntries helper",
                    )
                grouped.append(helper)
                helper_functions.append(helper.function)
                index += 1
                if helper.function == "send_append_entries_response":
                    break
            _require(
                grouped[-1].function == "send_append_entries_response",
                f"line {event.record.line_number}: AppendEntries receive lacks "
                "its response helper",
            )
            split_ends = _split_ends(event)
            preprocessed = PreprocessedEvent(
                "recv_append_entries_group",
                "group-append-entries-receive",
                tuple(grouped),
                {
                    "receive": event,
                    "become_follower": next(
                        (
                            candidate
                            for candidate in grouped
                            if candidate.function == "become_follower"
                        ),
                        None,
                    ),
                    "response": grouped[-1],
                    "split_ends": split_ends,
                },
            )
            result.append(preprocessed)
            groups.append(
                {
                    "functions": [item.function for item in grouped],
                    "helper_functions": helper_functions,
                    "provenance": _provenance(grouped),
                    "rule": "group-append-entries-receive",
                }
            )
            continue

        if event.function in receive_functions:
            grouped = [event]
            index += 1
            if index < len(raw) and raw[index].function == "become_follower":
                _require(
                    _is_newer_term_pair(event, raw[index]),
                    "internal newer-term grouping failure",
                )
                grouped.append(raw[index])
                index += 1
                groups.append(
                    {
                        "functions": [item.function for item in grouped],
                        "provenance": _provenance(grouped),
                        "rule": "group-newer-term-receive-become-follower",
                    }
                )
            result.append(
                PreprocessedEvent(
                    event.function,
                    (
                        "group-newer-term-receive-become-follower"
                        if len(grouped) == 2
                        else "retain-audited-event"
                    ),
                    tuple(grouped),
                    {
                        "receive": event,
                        "become_follower": (grouped[1] if len(grouped) == 2 else None),
                    },
                )
            )
            continue

        _require(
            event.function
            not in {
                "become_follower",
                "execute_append_entries_sync",
                "send_append_entries_response",
            },
            f"line {event.record.line_number}: ungrouped helper " f"{event.function!r}",
        )
        _require(
            not (event.function == "add_configuration" and _role(event) != "Leader"),
            f"line {event.record.line_number}: ungrouped follower configuration",
        )
        _require(
            not (event.function == "commit" and _role(event) != "Leader"),
            f"line {event.record.line_number}: ungrouped follower commit",
        )
        result.append(
            PreprocessedEvent(
                event.function,
                "retain-audited-event",
                (event,),
            )
        )
        index += 1
    return result


def _response_fingerprint(event: AssociatedEvent) -> tuple[Any, ...]:
    packet = _packet(event, "raft_append_entries_response")
    success = packet.get("success")
    _require(
        success in {"OK", "FAIL"},
        f"line {event.record.line_number}: unsupported response success value",
    )
    return (
        _natural(packet.get("term"), "response packet.term"),
        _natural(packet.get("last_log_idx"), "response packet.last_log_idx"),
        success,
    )


def _response_lane(event: AssociatedEvent, *, receiving: bool) -> tuple[str, str]:
    if receiving:
        source = _node(
            event.message.get("from_node_id"),
            f"line {event.record.line_number}: from_node_id",
        )
        return source, event.node
    destination = _node(
        event.message.get("to_node_id"),
        f"line {event.record.line_number}: to_node_id",
    )
    return event.node, destination


def _correlate_response_batches(trace: PreprocessedTrace) -> None:
    pending: dict[tuple[str, str], list[dict[str, Any]]] = {}
    items: list[tuple[int, str, Any]] = [
        (event.first_line, "event", event) for event in trace.events
    ]
    items.extend(
        (ignored.first_line, "ignored", ignored)
        for ignored in trace.ignored_events
        if ignored.function == "drop_pending_to"
    )
    for _, kind, item in sorted(items, key=lambda value: value[0]):
        if kind == "event":
            event: PreprocessedEvent = item
            if event.kind == "recv_append_entries_group":
                response = event.data["response"]
                lane = _response_lane(response, receiving=False)
                pending.setdefault(lane, []).append(
                    {
                        "count": len(event.data["split_ends"]),
                        "fingerprint": _response_fingerprint(response),
                        "provenance": _provenance(event.events),
                        "split_ends": event.data["split_ends"],
                    }
                )
            elif event.kind == "recv_append_entries_response":
                receive = event.events[0]
                lane = _response_lane(receive, receiving=True)
                queue = pending.get(lane, [])
                fingerprint = _response_fingerprint(receive)
                match = next(
                    (
                        position
                        for position, candidate in enumerate(queue)
                        if candidate["fingerprint"] == fingerprint
                    ),
                    None,
                )
                _require(
                    match is not None,
                    f"line {receive.record.line_number}: response has no "
                    "matching audited receive batch",
                )
                matched = queue.pop(match)
                event.data["split_count"] = matched["count"]
                event.data["matching_receive_provenance"] = matched["provenance"]
                event.data["split_ends"] = matched["split_ends"]
        else:
            ignored: IgnoredEvent = item
            record = ignored.records[0]
            message = record.value.get("msg")
            if not isinstance(message, dict):
                continue
            packet = message.get("packet")
            if not (
                isinstance(packet, dict)
                and packet.get("msg") == "raft_append_entries_response"
            ):
                continue
            state = message.get("state")
            _require(
                isinstance(state, dict),
                f"line {record.line_number}: dropped response state is missing",
            )
            source = _node(
                state.get("node_id"),
                f"line {record.line_number}: state.node_id",
            )
            destination = _node(
                message.get("to_node_id"),
                f"line {record.line_number}: to_node_id",
            )
            fingerprint = (
                _natural(packet.get("term"), "dropped response packet.term"),
                _natural(
                    packet.get("last_log_idx"),
                    "dropped response packet.last_log_idx",
                ),
                packet.get("success"),
            )
            queue = pending.get((source, destination), [])
            match = next(
                (
                    position
                    for position, candidate in enumerate(queue)
                    if candidate["fingerprint"] == fingerprint
                ),
                None,
            )
            _require(
                match is not None,
                f"line {record.line_number}: dropped response has no matching "
                "receive batch",
            )
            queue.pop(match)


def preprocess(records: Sequence[NDJSONRecord]) -> PreprocessedTrace:
    """Apply the manually audited implementation-event preprocessing rules."""

    associated, ignored = _associate_commands(records)
    command_associations = [
        {
            "command": event.command,
            "command_line": event.command_line,
            "event_line": event.record.line_number,
            "event_timestamp": event.record.value["h_ts"],
            "implementation_function": event.function,
            "rule": "associate-command",
        }
        for event in associated
    ]
    retained = _remove_configuration_replicates(associated, ignored)
    groups: list[dict[str, Any]] = []
    initial = _collapse_bootstrap(retained, groups)
    events = _group_events(initial, ignored, groups)
    trace = PreprocessedTrace(
        tuple(records),
        events,
        ignored,
        groups,
        command_associations,
    )
    _correlate_response_batches(trace)
    return trace


def _state_facts(event: AssociatedEvent) -> list[tuple[str, Any]]:
    role = {
        "None": "none",
        "Follower": "follower",
        "Candidate": "candidate",
        "Leader": "leader",
    }[_role(event)]
    return [
        ("allocated", True),
        ("joined", True),
        ("role", role),
        (
            "currentTerm",
            _natural(
                event.state.get("current_view"),
                f"line {event.record.line_number}: state.current_view",
            ),
        ),
        (
            "commitIndex",
            _natural(
                event.state.get("commit_idx"),
                f"line {event.record.line_number}: state.commit_idx",
            ),
        ),
        (
            "logLength",
            _natural(
                event.state.get("last_idx"),
                f"line {event.record.line_number}: state.last_idx",
            ),
        ),
    ]


class _CertificateBuilder:
    def __init__(self) -> None:
        self.steps: list[dict[str, Any]] = []
        self.action_count = 0

    def observe_state(
        self,
        event: AssociatedEvent,
        *,
        rule: str,
    ) -> None:
        provenance = _provenance([event])
        for variable, value in _state_facts(event):
            self.steps.append(
                {
                    "kind": "observation",
                    "node": event.node,
                    "provenance": provenance,
                    "rule": rule,
                    "value": value,
                    "variable": variable,
                }
            )

    def observe_message(
        self,
        event: AssociatedEvent,
        *,
        source: str,
        destination: str,
        rule: str,
        batch_position: int,
        batch_count: int,
        batch_end: int | None,
    ) -> None:
        self.steps.append(
            {
                "kind": "observation",
                "node": destination,
                "provenance": _provenance([event]),
                "rule": rule,
                "value": _message_summary(
                    event,
                    source=source,
                    batch_position=batch_position,
                    batch_count=batch_count,
                    batch_end=batch_end,
                ),
                "variable": "firstMessageFrom",
            }
        )

    def action(
        self,
        action: str,
        node: str,
        *,
        rule: str,
        events: Sequence[AssociatedEvent],
        evidence: Mapping[str, Any] | None = None,
        **parameters: Any,
    ) -> int:
        instruction = {
            "action": action,
            "kind": "action",
            "node": node,
            "provenance": _provenance(events),
            "rule": rule,
            **parameters,
        }
        if evidence is not None:
            instruction["evidence"] = dict(evidence)
        self.steps.append(instruction)
        self.action_count += 1
        return self.action_count


def _peer(event: AssociatedEvent, field: str) -> str:
    return _node(
        event.message.get(field),
        f"line {event.record.line_number}: {field}",
    )


def _message_summary(
    event: AssociatedEvent,
    *,
    source: str,
    batch_position: int,
    batch_count: int,
    batch_end: int | None,
) -> dict[str, Any]:
    packet = event.message.get("packet")
    _require(
        isinstance(packet, dict),
        f"line {event.record.line_number}: receive packet is missing",
    )
    family = packet.get("msg")
    _require(
        family
        in {
            "raft_append_entries",
            "raft_append_entries_response",
            "raft_request_vote",
            "raft_request_vote_response",
        },
        f"line {event.record.line_number}: unsupported receive packet {family!r}",
    )
    summary: dict[str, Any] = {
        "batchCount": batch_count,
        "batchPosition": batch_position,
        "messageType": family,
        "source": source,
        "term": _natural(
            packet.get("term"),
            f"line {event.record.line_number}: packet.term",
        ),
    }
    if family == "raft_append_entries":
        _require(
            batch_end is not None,
            f"line {event.record.line_number}: AppendEntries batch end is missing",
        )
        previous, end = _append_range(event)
        selected_previous = previous if previous == end else batch_end - 1
        summary.update(
            {
                "batchEnd": batch_end,
                "leaderCommitIndex": _natural(
                    packet.get("leader_commit_idx"),
                    f"line {event.record.line_number}: packet.leader_commit_idx",
                ),
                "previousIndex": selected_previous,
            }
        )
    elif family == "raft_append_entries_response":
        _require(
            packet.get("success") in {"OK", "FAIL"},
            f"line {event.record.line_number}: response success is unsupported",
        )
        summary.update(
            {
                "lastLogIndex": (
                    batch_end
                    if packet["success"] == "OK" and batch_end is not None
                    else _natural(
                        packet.get("last_log_idx"),
                        f"line {event.record.line_number}: packet.last_log_idx",
                    )
                ),
                "success": packet["success"],
            }
        )
    elif family == "raft_request_vote":
        summary["lastCommittableIndex"] = _natural(
            packet.get("last_committable_idx"),
            f"line {event.record.line_number}: packet.last_committable_idx",
        )
    else:
        _require(
            type(packet.get("vote_granted")) is bool,
            f"line {event.record.line_number}: vote_granted is not Boolean",
        )
        summary["voteGranted"] = packet["vote_granted"]
    return summary


def _reduce_receive_with_optional_term_update(
    builder: _CertificateBuilder,
    event: PreprocessedEvent,
    *,
    receive_count: int,
    source: str,
    destination: str,
    receive_rule: str,
    post_event: AssociatedEvent | None = None,
    matching_receive_provenance: list[dict[str, Any]] | None = None,
    batch_ends: Sequence[int] | None = None,
) -> None:
    receive = event.data.get("receive", event.events[0])
    follower = event.data.get("become_follower")
    builder.observe_state(
        receive,
        rule=receive_rule,
    )
    if follower is not None:
        builder.action(
            "updateTerm",
            destination,
            source=source,
            rule="newer-term-receive-transition",
            events=[receive, follower],
        )
        builder.observe_state(
            follower,
            rule="newer-term-receive-transition",
        )
    _require(
        batch_ends is None or len(batch_ends) == receive_count,
        f"line {receive.record.line_number}: receive batch summary is inconsistent",
    )
    for position in range(1, receive_count + 1):
        builder.observe_message(
            receive,
            source=source,
            destination=destination,
            rule="observe-selected-message-before-receive",
            batch_position=position,
            batch_count=receive_count,
            batch_end=(batch_ends[position - 1] if batch_ends is not None else None),
        )
        evidence = None
        if matching_receive_provenance is not None and position == 1:
            evidence = {
                "batchCorrelation": {
                    "matchingReceiveProvenance": matching_receive_provenance,
                    "splitCount": receive_count,
                }
            }
        builder.action(
            "receive",
            destination,
            source=source,
            rule=receive_rule,
            events=[receive],
            evidence=evidence,
        )
    if post_event is not None:
        builder.observe_state(
            post_event,
            rule=receive_rule,
        )


def reduce(preprocessed: PreprocessedTrace) -> dict[str, Any]:
    """Reduce preprocessed implementation events to CCFRaft actions."""

    _require(
        isinstance(preprocessed, PreprocessedTrace),
        "reduce expects the result of preprocess",
    )
    builder = _CertificateBuilder()
    pending_configuration: PreprocessedEvent | None = None

    def emit_pending_configuration() -> None:
        nonlocal pending_configuration
        if pending_configuration is None:
            return
        configuration_event = pending_configuration.events[0]
        _, nodes = _configuration(configuration_event)
        builder.action(
            "changeConfiguration",
            configuration_event.node,
            configuration=nodes,
            rule="leader-add-configuration",
            events=pending_configuration.events,
        )
        pending_configuration = None

    for event in preprocessed.events:
        primary = event.events[0]
        if pending_configuration is not None and event.kind != "send_append_entries":
            emit_pending_configuration()

        if event.kind == "bootstrap":
            commit = event.data["commit_event"]
            builder.observe_state(
                commit,
                rule="observe-bootstrap-entry-state",
            )
            builder.action(
                "advanceCommitIndex",
                commit.node,
                rule="bootstrap-leader-commit",
                events=event.events,
            )
        elif event.kind == "replicate":
            _require(
                _role(primary) == "Leader",
                f"line {primary.record.line_number}: replicate is not on a leader",
            )
            committable = primary.message.get("globally_committable")
            _require(
                type(committable) is bool,
                f"line {primary.record.line_number}: replicate committable flag "
                "is missing",
            )
            if committable:
                rule = "replicate-signature"
                builder.observe_state(primary, rule=rule)
                builder.action(
                    "signCommittableMessages",
                    primary.node,
                    rule=rule,
                    events=event.events,
                )
            else:
                rule = "replicate-client-request"
                builder.observe_state(primary, rule=rule)
                builder.action(
                    "clientRequest",
                    primary.node,
                    transaction=f"trace-line-{primary.record.line_number}",
                    rule=rule,
                    events=event.events,
                )
        elif event.kind == "add_configuration":
            _require(
                _role(primary) == "Leader",
                f"line {primary.record.line_number}: configuration is not leader "
                "initiated",
            )
            _configuration(primary)
            builder.observe_state(
                primary,
                rule="leader-add-configuration",
            )
            _require(
                pending_configuration is None,
                f"line {primary.record.line_number}: nested configuration callback",
            )
            pending_configuration = event
        elif event.kind == "send_append_entries":
            destination = _peer(primary, "to_node_id")
            builder.observe_state(
                primary,
                rule="split-append-entries-batch",
            )
            for batch_end in _split_ends(primary):
                builder.action(
                    "appendEntries",
                    primary.node,
                    destination=destination,
                    batchEnd=batch_end,
                    rule="split-append-entries-batch",
                    events=event.events,
                )
        elif event.kind == "recv_append_entries_group":
            receive = event.data["receive"]
            source = _peer(receive, "from_node_id")
            _reduce_receive_with_optional_term_update(
                builder,
                event,
                receive_count=len(event.data["split_ends"]),
                source=source,
                destination=receive.node,
                receive_rule="split-append-entries-receive",
                post_event=event.data["response"],
                batch_ends=event.data["split_ends"],
            )
        elif event.kind == "recv_append_entries_response":
            source = _peer(primary, "from_node_id")
            count = event.data.get("split_count")
            _require(
                type(count) is int and count > 0,
                f"line {primary.record.line_number}: response batch is uncorrelated",
            )
            _reduce_receive_with_optional_term_update(
                builder,
                event,
                receive_count=count,
                source=source,
                destination=primary.node,
                receive_rule="split-append-entries-response-receive",
                matching_receive_provenance=event.data["matching_receive_provenance"],
                batch_ends=event.data["split_ends"],
            )
        elif event.kind in {
            "recv_request_vote",
            "recv_request_vote_response",
        }:
            _packet(
                primary,
                (
                    "raft_request_vote"
                    if event.kind == "recv_request_vote"
                    else "raft_request_vote_response"
                ),
            )
            source = _peer(primary, "from_node_id")
            family = (
                "receive-request-vote"
                if event.kind == "recv_request_vote"
                else "receive-request-vote-response"
            )
            _reduce_receive_with_optional_term_update(
                builder,
                event,
                receive_count=1,
                source=source,
                destination=primary.node,
                receive_rule=family,
            )
        elif event.kind == "commit":
            _require(
                _role(primary) == "Leader",
                f"line {primary.record.line_number}: only leader commit callbacks "
                "map to advanceCommitIndex",
            )
            args = primary.message.get("args")
            _require(
                isinstance(args, dict)
                and type(args.get("idx")) is int
                and args["idx"] >= 0,
                f"line {primary.record.line_number}: commit target is missing",
            )
            builder.observe_state(
                primary,
                rule="leader-commit-callback",
            )
            builder.action(
                "advanceCommitIndex",
                primary.node,
                rule="leader-commit-callback",
                events=event.events,
            )
        elif event.kind == "become_candidate":
            builder.action(
                "timeout",
                primary.node,
                rule="candidate-timeout",
                events=event.events,
            )
            builder.observe_state(
                primary,
                rule="candidate-timeout",
            )
        elif event.kind == "send_request_vote":
            _require(
                _role(primary) == "Candidate",
                f"line {primary.record.line_number}: RequestVote sender is not a "
                "candidate",
            )
            destination = _peer(primary, "to_node_id")
            _packet(primary, "raft_request_vote")
            builder.observe_state(
                primary,
                rule="send-request-vote",
            )
            builder.action(
                "requestVote",
                primary.node,
                destination=destination,
                rule="send-request-vote",
                events=event.events,
            )
        elif event.kind == "become_leader":
            _require(
                _role(primary) == "Leader",
                f"line {primary.record.line_number}: promotion did not produce a "
                "leader",
            )
            builder.action(
                "becomeLeader",
                primary.node,
                rule="candidate-became-leader",
                events=event.events,
            )
            builder.observe_state(
                primary,
                rule="candidate-became-leader",
            )
        else:
            raise ReductionError(
                f"line {primary.record.line_number}: no reduction rule for "
                f"{event.kind!r}"
            )

    emit_pending_configuration()

    ignored_events = [
        {
            "function": ignored.function,
            "provenance": [
                {
                    "line": record.line_number,
                    **(
                        {"timestamp": record.value["h_ts"]}
                        if "h_ts" in record.value
                        else {}
                    ),
                    **(
                        {"function": record.value["msg"]["function"]}
                        if isinstance(record.value.get("msg"), dict)
                        and isinstance(record.value["msg"].get("function"), str)
                        else {}
                    ),
                }
                for record in ignored.records
            ],
            "reason": ignored.reason,
            "rule": ignored.rule,
        }
        for ignored in sorted(
            preprocessed.ignored_events,
            key=lambda item: item.first_line,
        )
    ]
    observation_count = sum(
        instruction["kind"] == "observation" for instruction in builder.steps
    )
    canonical_text = "\n".join(record.raw for record in preprocessed.records) + "\n"
    return {
        "artifact_kind": "ccfraft_reduction_certificate",
        "counts": {
            "actions": builder.action_count,
            "ignored_events": len(ignored_events),
            "observations": observation_count,
            "preprocessed_events": len(preprocessed.events),
            "raw_records": len(preprocessed.records),
        },
        "input": {
            "canonical_ndjson_sha256": hashlib.sha256(
                canonical_text.encode("utf-8")
            ).hexdigest(),
        },
        "preprocessing": {
            "command_associations": preprocessed.command_associations,
            "groups": preprocessed.groups,
            "ignored_events": ignored_events,
        },
        "schema_version": SCHEMA_VERSION,
        "steps": builder.steps,
    }


def build_certificate(records: Sequence[NDJSONRecord]) -> dict[str, Any]:
    """Preprocess and reduce parsed NDJSON records."""

    return reduce(preprocess(records))


def write_certificate(path: Path, certificate: Mapping[str, Any]) -> None:
    """Write deterministic, reviewable JSON."""

    path.write_text(
        json.dumps(certificate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="captured NDJSON input")
    parser.add_argument("output", type=Path, help="canonical JSON certificate")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    certificate = build_certificate(read_ndjson(args.input))
    write_certificate(args.output, certificate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
