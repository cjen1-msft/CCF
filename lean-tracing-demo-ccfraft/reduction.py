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
    "become_pre_vote_candidate",
    "commit",
    "drop_pending_to",
    "execute_append_entries_sync",
    "recv_append_entries",
    "recv_append_entries_response",
    "recv_propose_request_vote",
    "recv_request_vote",
    "recv_request_vote_response",
    "replicate",
    "send_append_entries",
    "send_append_entries_response",
    "send_request_vote",
    "step_down_and_nominate_successor",
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
        raw in {"None", "Follower", "PreVoteCandidate", "Candidate", "Leader"},
        f"line {event.record.line_number}: unsupported leadership_state {raw!r}",
    )
    return str(raw)


def _membership_state(event: AssociatedEvent) -> str:
    membership = event.state.get("membership_state")
    phase = event.state.get("retirement_phase")
    if membership == "Active":
        _require(
            phase is None,
            f"line {event.record.line_number}: active node has retirement phase",
        )
        return "active"
    _require(
        membership == "Retired",
        f"line {event.record.line_number}: unsupported membership_state "
        f"{membership!r}",
    )
    phases = {
        "Ordered": "retirementOrdered",
        "Signed": "retirementSigned",
        "Completed": "retirementCompleted",
        "RetiredCommitted": "retiredCommitted",
    }
    _require(
        phase in phases,
        f"line {event.record.line_number}: unsupported retirement_phase {phase!r}",
    )
    return phases[phase]


def _optional_natural(value: Any, label: str) -> int | None:
    if value is None:
        return None
    return _natural(value, label)


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
            _role_value
            in {"None", "Follower", "PreVoteCandidate", "Candidate", "Leader"},
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
        _membership_state(
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
        _require(
            type(state.get("pre_vote_enabled")) is bool,
            f"line {record.line_number}: pre_vote_enabled is not Boolean",
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


def _follower_transition(
    receive: AssociatedEvent,
    follower: AssociatedEvent,
) -> str | None:
    if follower.function != "become_follower" or follower.node != receive.node:
        return None
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
        follower_term == packet_term,
        f"lines {receive.record.line_number}-{follower.record.line_number}: "
        "become_follower term differs from the selected message",
    )
    if packet_term > previous_term:
        return "newer"
    if (
        packet_term == previous_term
        and receive.function == "recv_append_entries"
        and _role(receive) in {"Candidate", "PreVoteCandidate"}
    ):
        return "same-term-fallback"
    raise ReductionError(
        f"lines {receive.record.line_number}-{follower.record.line_number}: "
        "become_follower is neither a newer-term update nor same-term "
        "AppendEntries fallback"
    )


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
        "recv_append_entries_response",
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
            follower_transition = None
            index += 1
            if index < len(raw) and raw[index].function == "become_follower":
                follower_transition = _follower_transition(event, raw[index])
                _require(follower_transition is not None, "internal grouping failure")
                grouped.append(raw[index])
                groups.append(
                    {
                        "functions": [event.function, raw[index].function],
                        "provenance": _provenance([event, raw[index]]),
                        "rule": f"group-{follower_transition}-receive-become-follower",
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
                    "follower_transition": follower_transition,
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

        if event.function == "recv_propose_request_vote":
            _require(
                index + 1 < len(raw),
                f"line {event.record.line_number}: propose vote lacks "
                "become_candidate",
            )
            candidate = raw[index + 1]
            _require(
                candidate.function == "become_candidate"
                and candidate.node == event.node,
                f"line {event.record.line_number}: propose vote is not followed "
                "by matching become_candidate",
            )
            result.append(
                PreprocessedEvent(
                    "recv_propose_request_vote_group",
                    "group-propose-vote-receive",
                    (event, candidate),
                    {
                        "candidate": candidate,
                        "receive": event,
                    },
                )
            )
            groups.append(
                {
                    "functions": [event.function, candidate.function],
                    "provenance": _provenance([event, candidate]),
                    "rule": "group-propose-vote-receive",
                }
            )
            index += 2
            continue

        if event.function in receive_functions:
            grouped = [event]
            follower_transition = None
            index += 1
            if index < len(raw) and raw[index].function == "become_follower":
                follower_transition = _follower_transition(event, raw[index])
                _require(follower_transition is not None, "internal grouping failure")
                grouped.append(raw[index])
                index += 1
                groups.append(
                    {
                        "functions": [item.function for item in grouped],
                        "provenance": _provenance(grouped),
                        "rule": f"group-{follower_transition}-receive-become-follower",
                    }
                )
            result.append(
                PreprocessedEvent(
                    event.function,
                    (
                        f"group-{follower_transition}-receive-become-follower"
                        if len(grouped) == 2
                        else "retain-audited-event"
                    ),
                    tuple(grouped),
                    {
                        "receive": event,
                        "become_follower": (grouped[1] if len(grouped) == 2 else None),
                        "follower_transition": follower_transition,
                    },
                )
            )
            continue

        _require(
            event.function
            not in {
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


def _correlate_nominations(trace: PreprocessedTrace) -> None:
    pending: dict[str, list[PreprocessedEvent]] = {}
    dropped: dict[str, list[AssociatedEvent]] = {}
    for ignored in trace.ignored_events:
        if ignored.function != "drop_pending_to":
            continue
        record = ignored.records[0]
        message = record.value.get("msg")
        if not isinstance(message, dict):
            continue
        packet = message.get("packet")
        state = message.get("state")
        if not (
            isinstance(packet, dict)
            and packet.get("msg") == "raft_propose_request_vote"
            and isinstance(state, dict)
        ):
            continue
        source = _node(
            state.get("node_id"),
            f"line {record.line_number}: dropped proposal source",
        )
        destination = _node(
            message.get("to_node_id"),
            f"line {record.line_number}: dropped proposal destination",
        )
        dropped.setdefault(source, []).append(
            AssociatedEvent(
                record,
                "drop_pending_to",
                message,
                state,
                source,
                "",
                0,
            )
        )
        dropped[source][-1].message["_proposal_destination"] = destination

    for event in trace.events:
        if event.kind == "step_down_and_nominate_successor":
            source = event.events[0].node
            pending.setdefault(source, []).append(event)
        elif event.kind == "recv_propose_request_vote_group":
            receive = event.data["receive"]
            source = _peer(receive, "from_node_id")
            nominations = pending.get(source, [])
            if nominations:
                nomination = nominations.pop(0)
                nomination.data["destination"] = receive.node
                event.data["matching_nomination_provenance"] = _provenance(
                    nomination.events
                )
    for source, nominations in pending.items():
        for nomination, dropped_event in zip(nominations, dropped.get(source, [])):
            nomination.data["destination"] = dropped_event.message[
                "_proposal_destination"
            ]
            nomination.data["matching_drop_provenance"] = _provenance([dropped_event])


def _mark_configuration_callback_sends(trace: PreprocessedTrace) -> None:
    pending_source: str | None = None
    for event in trace.events:
        if event.kind == "add_configuration":
            pending_source = event.events[0].node
            continue
        if (
            pending_source is not None
            and event.kind == "send_append_entries"
            and event.events[0].node == pending_source
        ):
            event.data["configuration_callback"] = True
            trace.groups.append(
                {
                    "functions": [event.events[0].function],
                    "omitted_observations": ["logLength"],
                    "provenance": _provenance(event.events),
                    "rule": "configuration-callback-mixed-snapshot",
                }
            )
            continue
        pending_source = None


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
    _correlate_nominations(trace)
    _mark_configuration_callback_sends(trace)
    return trace


def _state_facts(event: AssociatedEvent) -> list[tuple[str, Any]]:
    membership_state = _membership_state(event)
    role = {
        "None": "none",
        "Follower": "follower",
        "PreVoteCandidate": "preVoteCandidate",
        "Candidate": "candidate",
        "Leader": "leader",
    }[_role(event)]
    if membership_state == "retiredCommitted" and role == "none":
        role = "follower"
    return [
        ("allocated", True),
        ("joined", True),
        ("role", role),
        (
            "preVoteStatus",
            "enabled" if event.state.get("pre_vote_enabled") is True else "capable",
        ),
        ("membershipState", membership_state),
        (
            "retirementIndex",
            _optional_natural(
                event.state.get("retirement_idx"),
                f"line {event.record.line_number}: state.retirement_idx",
            ),
        ),
        (
            "retirementCommittableIndex",
            _optional_natural(
                event.state.get("retirement_committable_idx"),
                "line "
                f"{event.record.line_number}: "
                "state.retirement_committable_idx",
            ),
        ),
        (
            "retiredCommittedIndex",
            _optional_natural(
                event.state.get("retired_committed_idx"),
                f"line {event.record.line_number}: state.retired_committed_idx",
            ),
        ),
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
        omit: frozenset[str] = frozenset(),
    ) -> None:
        provenance = _provenance([event])
        for variable, value in _state_facts(event):
            if variable in omit:
                continue
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
            "raft_propose_request_vote",
            "raft_request_pre_vote",
            "raft_request_pre_vote_response",
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
    elif family in {"raft_request_vote", "raft_request_pre_vote"}:
        summary.update(
            {
                "lastCommittableIndex": _natural(
                    packet.get("last_committable_idx"),
                    f"line {event.record.line_number}: packet.last_committable_idx",
                ),
                "lastCommittableTerm": _natural(
                    packet.get("term_of_last_committable_idx"),
                    "line "
                    f"{event.record.line_number}: "
                    "packet.term_of_last_committable_idx",
                ),
            }
        )
    elif family in {
        "raft_request_vote_response",
        "raft_request_pre_vote_response",
    }:
        _require(
            type(packet.get("vote_granted")) is bool,
            f"line {event.record.line_number}: vote_granted is not Boolean",
        )
        summary["voteGranted"] = packet["vote_granted"]
    else:
        _require(
            family == "raft_propose_request_vote",
            f"line {event.record.line_number}: unexpected packet {family}",
        )
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
    follower_transition = event.data.get("follower_transition")
    builder.observe_state(
        receive,
        rule=receive_rule,
    )
    _require(
        batch_ends is None or len(batch_ends) == receive_count,
        f"line {receive.record.line_number}: receive batch summary is inconsistent",
    )
    if follower is not None:
        if follower_transition == "newer":
            builder.action(
                "updateTerm",
                destination,
                source=source,
                rule="newer-term-receive-transition",
                events=[receive, follower],
            )
        elif follower_transition == "same-term-fallback":
            fallback_packet = receive.message.get("packet")
            _require(
                isinstance(fallback_packet, dict)
                and isinstance(fallback_packet.get("msg"), str),
                f"line {receive.record.line_number}: fallback packet is missing",
            )
            builder.observe_message(
                receive,
                source=source,
                destination=destination,
                rule="same-term-append-entries-fallback",
                batch_position=1,
                batch_count=receive_count,
                batch_end=(batch_ends[0] if batch_ends is not None else None),
            )
            builder.action(
                "receive",
                destination,
                source=source,
                rule="same-term-append-entries-fallback",
                events=[receive, follower],
                evidence={"messageType": fallback_packet["msg"]},
            )
        else:
            raise ReductionError(
                f"line {receive.record.line_number}: follower transition is missing"
            )
        builder.observe_state(
            follower,
            rule=(
                "newer-term-receive-transition"
                if follower_transition == "newer"
                else "same-term-append-entries-fallback"
            ),
        )
    for position in range(1, receive_count + 1):
        packet = receive.message.get("packet")
        _require(
            isinstance(packet, dict) and isinstance(packet.get("msg"), str),
            f"line {receive.record.line_number}: receive packet family is missing",
        )
        builder.observe_message(
            receive,
            source=source,
            destination=destination,
            rule="observe-selected-message-before-receive",
            batch_position=position,
            batch_count=receive_count,
            batch_end=(batch_ends[position - 1] if batch_ends is not None else None),
        )
        evidence: dict[str, Any] = {"messageType": packet["msg"]}
        if matching_receive_provenance is not None and position == 1:
            evidence.update(
                {
                    "batchCorrelation": {
                        "matchingReceiveProvenance": matching_receive_provenance,
                        "splitCount": receive_count,
                    }
                }
            )
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

    for event in preprocessed.events:
        primary = event.events[0]

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
                retirement_append = primary.command.startswith("cleanup_nodes,")
                rule = (
                    "append-retired-committed"
                    if retirement_append
                    else "replicate-client-request"
                )
                builder.observe_state(primary, rule=rule)
                builder.action(
                    "appendRetiredCommitted" if retirement_append else "clientRequest",
                    primary.node,
                    **(
                        {}
                        if retirement_append
                        else {
                            "transaction": (f"trace-line-{primary.record.line_number}")
                        }
                    ),
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
            _, nodes = _configuration(primary)
            builder.action(
                "changeConfiguration",
                primary.node,
                configuration=nodes,
                rule="leader-add-configuration",
                events=event.events,
            )
        elif event.kind == "send_append_entries":
            destination = _peer(primary, "to_node_id")
            builder.observe_state(
                primary,
                rule="split-append-entries-batch",
                omit=(
                    frozenset({"logLength"})
                    if event.data.get("configuration_callback") is True
                    else frozenset()
                ),
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
            packet = primary.message.get("packet")
            _require(
                isinstance(packet, dict),
                f"line {primary.record.line_number}: vote packet is missing",
            )
            packet_family = packet.get("msg")
            allowed_families = (
                {"raft_request_vote", "raft_request_pre_vote"}
                if event.kind == "recv_request_vote"
                else {
                    "raft_request_vote_response",
                    "raft_request_pre_vote_response",
                }
            )
            _require(
                packet_family in allowed_families,
                f"line {primary.record.line_number}: unsupported vote packet "
                f"{packet_family!r}",
            )
            source = _peer(primary, "from_node_id")
            family = {
                "raft_request_vote": "receive-request-vote",
                "raft_request_pre_vote": "receive-request-pre-vote",
                "raft_request_vote_response": "receive-request-vote-response",
                "raft_request_pre_vote_response": ("receive-request-pre-vote-response"),
            }[packet_family]
            _reduce_receive_with_optional_term_update(
                builder,
                event,
                receive_count=1,
                source=source,
                destination=primary.node,
                receive_rule=family,
            )
        elif event.kind == "recv_propose_request_vote_group":
            receive = event.data["receive"]
            candidate = event.data["candidate"]
            packet = _packet(receive, "raft_propose_request_vote")
            _natural(
                packet.get("term"),
                f"line {receive.record.line_number}: packet.term",
            )
            source = _peer(receive, "from_node_id")
            _reduce_receive_with_optional_term_update(
                builder,
                event,
                receive_count=1,
                source=source,
                destination=receive.node,
                receive_rule="receive-propose-vote",
            )
            builder.observe_state(candidate, rule="receive-propose-vote")
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
            pre_vote_enabled = primary.state["pre_vote_enabled"]
            action = "becomeCandidate" if pre_vote_enabled else "timeout"
            rule = (
                "pre-vote-majority-became-candidate"
                if pre_vote_enabled
                else "candidate-timeout"
            )
            builder.action(
                action,
                primary.node,
                rule=rule,
                events=event.events,
            )
            builder.observe_state(
                primary,
                rule=rule,
            )
        elif event.kind == "become_pre_vote_candidate":
            builder.action(
                "becomePreVoteCandidate",
                primary.node,
                rule="pre-vote-timeout",
                events=event.events,
            )
            builder.observe_state(primary, rule="pre-vote-timeout")
        elif event.kind == "become_follower":
            _require(
                _role(primary) == "Follower",
                f"line {primary.record.line_number}: step-down did not produce "
                "a follower",
            )
            builder.action(
                "checkQuorum",
                primary.node,
                rule="check-quorum-step-down",
                events=event.events,
            )
            builder.observe_state(primary, rule="check-quorum-step-down")
        elif event.kind == "send_request_vote":
            packet = primary.message.get("packet")
            _require(
                isinstance(packet, dict),
                f"line {primary.record.line_number}: vote packet is missing",
            )
            packet_family = packet.get("msg")
            _require(
                packet_family in {"raft_request_vote", "raft_request_pre_vote"},
                f"line {primary.record.line_number}: unsupported vote request "
                f"{packet_family!r}",
            )
            pre_vote = packet_family == "raft_request_pre_vote"
            expected_role = "PreVoteCandidate" if pre_vote else "Candidate"
            _require(
                _role(primary) == expected_role,
                f"line {primary.record.line_number}: vote sender role does not "
                f"match {packet_family}",
            )
            destination = _peer(primary, "to_node_id")
            action = "requestPreVote" if pre_vote else "requestVote"
            rule = "send-request-pre-vote" if pre_vote else "send-request-vote"
            builder.observe_state(
                primary,
                rule=rule,
            )
            builder.action(
                action,
                primary.node,
                destination=destination,
                rule=rule,
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
        elif event.kind == "step_down_and_nominate_successor":
            destination = event.data.get("destination")
            _require(
                isinstance(destination, str),
                f"line {primary.record.line_number}: nomination has no observed "
                "receive or dropped packet",
            )
            builder.observe_state(primary, rule="propose-successor-vote")
            builder.action(
                "proposeVote",
                primary.node,
                destination=destination,
                rule="propose-successor-vote",
                events=event.events,
            )
        else:
            raise ReductionError(
                f"line {primary.record.line_number}: no reduction rule for "
                f"{event.kind!r}"
            )

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
