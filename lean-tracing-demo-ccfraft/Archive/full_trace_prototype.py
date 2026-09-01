#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Build a proposed deterministic action mapping for the 53-event replicate trace."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

SCHEMA_VERSION = "ccfraft-proposed-deterministic-mapping/v2"
EXPECTED_EVENT_COUNT = 53
EXPECTED_REDUCTION_COUNT = 22
EXPECTED_ACTION_COUNT = 43
NODE_WORLD_CAPACITY = 15

STATE_KEYS = {
    "commit_idx",
    "committable_indices",
    "current_view",
    "last_idx",
    "leadership_state",
    "membership_state",
    "node_id",
    "pre_vote_enabled",
}
TOP_LEVEL_KEYS = {
    "cmd",
    "cmd_prefix",
    "file",
    "h_ts",
    "level",
    "msg",
    "number",
    "tag",
    "thread_id",
}

CONFIGURATION_0 = {
    "idx": 1,
    "nodes": {"0": {"address": ":"}},
    "rid": 1,
}
CONFIGURATION_01 = {
    "idx": 3,
    "nodes": {
        "0": {"address": ":"},
        "1": {"address": ":"},
    },
    "rid": 3,
}


class ReductionError(RuntimeError):
    """Report a trace or certificate mismatch."""


@dataclass(frozen=True)
class Event:
    """One numbered raw NDJSON event and its parsed value."""

    number: int
    raw: str
    row: dict[str, Any]

    @property
    def message(self) -> dict[str, Any]:
        """Return the raft_trace message."""

        message = self.row["msg"]
        if not isinstance(message, dict):
            raise ReductionError(f"event {self.number}: msg is not an object")
        return message


@dataclass(frozen=True)
class ExpectedEvent:
    """Exact function, node-state, and scenario-command fields for an event."""

    function: str
    node: str
    role: str
    term: int
    last_index: int
    commit_index: int
    committable_indices: tuple[int, ...]
    command: str


@dataclass(frozen=True)
class ActionSpec:
    """A proposed model-action template and its structured parameters."""

    kind: str
    template: str
    parameters: Mapping[str, Any]


@dataclass(frozen=True)
class ReductionSpec:
    """One deterministic event group and its proposed action expansion."""

    name: str
    events: tuple[int, ...]
    actions: tuple[ActionSpec, ...]
    summary: str
    exception_ids: tuple[str, ...] = ()


def require(condition: bool, message: str) -> None:
    """Raise a reduction error when an invariant does not hold."""

    if not condition:
        raise ReductionError(message)


def _expected_command(number: int) -> str:
    """Return the scenario command inherited by a preprocessed event."""

    if number == 1 or number == 4 or number == 24:
        return "emit_signature,2"
    if number in (2, 3):
        return "trust_node,2,1"
    if (
        5 <= number <= 8
        or 11 <= number <= 22
        or 26 <= number <= 32
        or 34 <= number <= 37
        or 39 <= number <= 41
    ):
        return "dispatch_all"
    if number in (9, 10, 25, 33, 38):
        return "periodic_all,10"
    if number == 23:
        return "replicate,2,helloworld"
    if 42 <= number <= 53:
        return "assert_state_sync"
    raise ReductionError(f"event {number}: no expected scenario command")


def _expected_events() -> dict[int, ExpectedEvent]:
    """Build the exact scalar expectation table for all 53 events."""

    scalar_rows: tuple[tuple[str, str, str, int, int, int, tuple[int, ...]], ...] = (
        ("bootstrap", "0", "Leader", 2, 2, 0, (2,)),
        ("add_configuration", "0", "Leader", 2, 2, 2, ()),
        ("send_append_entries", "0", "Leader", 2, 2, 2, ()),
        ("replicate", "0", "Leader", 2, 3, 2, ()),
        ("recv_append_entries", "1", "None", 0, 0, 0, ()),
        ("become_follower", "1", "Follower", 2, 0, 0, ()),
        ("send_append_entries_response", "1", "Follower", 2, 0, 0, ()),
        ("recv_append_entries_response", "0", "Leader", 2, 4, 2, (4,)),
        ("send_append_entries", "0", "Leader", 2, 4, 2, (4,)),
        ("send_append_entries", "0", "Leader", 2, 4, 2, (4,)),
        ("recv_append_entries", "1", "Follower", 2, 0, 0, ()),
        ("add_configuration", "1", "Follower", 2, 1, 0, ()),
        ("execute_append_entries_sync", "1", "Follower", 2, 1, 0, ()),
        ("commit", "1", "Follower", 2, 2, 0, (2,)),
        ("add_configuration", "1", "Follower", 2, 3, 2, ()),
        ("send_append_entries_response", "1", "Follower", 2, 3, 2, ()),
        ("recv_append_entries", "1", "Follower", 2, 3, 2, ()),
        ("execute_append_entries_sync", "1", "Follower", 2, 3, 2, ()),
        ("send_append_entries_response", "1", "Follower", 2, 4, 2, (4,)),
        ("recv_append_entries_response", "0", "Leader", 2, 4, 2, (4,)),
        ("recv_append_entries_response", "0", "Leader", 2, 4, 2, (4,)),
        ("commit", "0", "Leader", 2, 4, 2, (4,)),
        ("replicate", "0", "Leader", 2, 4, 4, ()),
        ("replicate", "0", "Leader", 2, 5, 4, ()),
        ("send_append_entries", "0", "Leader", 2, 6, 4, (6,)),
        ("recv_append_entries", "1", "Follower", 2, 4, 2, (4,)),
        ("execute_append_entries_sync", "1", "Follower", 2, 4, 2, (4,)),
        ("execute_append_entries_sync", "1", "Follower", 2, 5, 2, (4,)),
        ("commit", "1", "Follower", 2, 6, 2, (4, 6)),
        ("send_append_entries_response", "1", "Follower", 2, 6, 4, (6,)),
        ("recv_append_entries_response", "0", "Leader", 2, 6, 4, (6,)),
        ("commit", "0", "Leader", 2, 6, 4, (6,)),
        ("send_append_entries", "0", "Leader", 2, 6, 6, ()),
        ("recv_append_entries", "1", "Follower", 2, 6, 4, (6,)),
        ("commit", "1", "Follower", 2, 6, 4, (6,)),
        ("send_append_entries_response", "1", "Follower", 2, 6, 6, ()),
        ("recv_append_entries_response", "0", "Leader", 2, 6, 6, ()),
        ("send_append_entries", "0", "Leader", 2, 6, 6, ()),
        ("recv_append_entries", "1", "Follower", 2, 6, 6, ()),
        ("send_append_entries_response", "1", "Follower", 2, 6, 6, ()),
        ("recv_append_entries_response", "0", "Leader", 2, 6, 6, ()),
        ("replicate", "0", "Leader", 2, 6, 6, ()),
        ("send_append_entries", "0", "Leader", 2, 7, 6, (7,)),
        ("recv_append_entries", "1", "Follower", 2, 6, 6, ()),
        ("execute_append_entries_sync", "1", "Follower", 2, 6, 6, ()),
        ("send_append_entries_response", "1", "Follower", 2, 7, 6, (7,)),
        ("recv_append_entries_response", "0", "Leader", 2, 7, 6, (7,)),
        ("commit", "0", "Leader", 2, 7, 6, (7,)),
        ("send_append_entries", "0", "Leader", 2, 7, 7, ()),
        ("recv_append_entries", "1", "Follower", 2, 7, 6, (7,)),
        ("commit", "1", "Follower", 2, 7, 6, (7,)),
        ("send_append_entries_response", "1", "Follower", 2, 7, 7, ()),
        ("recv_append_entries_response", "0", "Leader", 2, 7, 7, ()),
    )
    require(
        len(scalar_rows) == EXPECTED_EVENT_COUNT,
        "internal expected-event table has the wrong length",
    )
    return {
        number: ExpectedEvent(*row, command=_expected_command(number))
        for number, row in enumerate(scalar_rows, 1)
    }


EXPECTED_EVENTS = _expected_events()


def _append_packet(
    previous: int,
    index: int,
    leader_commit: int,
    previous_term: int = 2,
) -> dict[str, Any]:
    """Construct one exact C++ AppendEntries packet expectation."""

    return {
        "contains_new_view": False,
        "idx": index,
        "leader_commit_idx": leader_commit,
        "msg": "raft_append_entries",
        "prev_idx": previous,
        "prev_term": previous_term,
        "term": 2,
        "term_of_idx": 2,
    }


def _response_packet(last_index: int, success: str) -> dict[str, Any]:
    """Construct one exact C++ AppendEntries response expectation."""

    return {
        "last_log_idx": last_index,
        "msg": "raft_append_entries_response",
        "success": success,
        "term": 2,
    }


SEND_APPEND: dict[int, tuple[int, int, int, int, int, int]] = {
    3: (3, 0, 2, 2, 2, 2),
    9: (0, 0, 0, 3, 2, 0),
    10: (3, 0, 3, 4, 2, 2),
    25: (4, 4, 4, 6, 4, 2),
    33: (6, 6, 6, 6, 6, 2),
    38: (6, 6, 6, 6, 6, 2),
    43: (6, 6, 6, 7, 6, 2),
    49: (7, 7, 7, 7, 7, 2),
}
RECEIVE_APPEND: dict[int, tuple[int, int, int, int]] = {
    5: (2, 2, 2, 2),
    11: (0, 3, 2, 0),
    17: (3, 4, 2, 2),
    26: (4, 6, 4, 2),
    34: (6, 6, 6, 2),
    39: (6, 6, 6, 2),
    44: (6, 7, 6, 2),
    50: (7, 7, 7, 2),
}
SEND_RESPONSE: dict[int, tuple[int, str]] = {
    7: (0, "FAIL"),
    16: (3, "OK"),
    19: (4, "OK"),
    30: (6, "OK"),
    36: (6, "OK"),
    40: (6, "OK"),
    46: (7, "OK"),
    52: (7, "OK"),
}
RECEIVE_RESPONSE: dict[int, tuple[int, str, int, int]] = {
    8: (0, "FAIL", 2, 0),
    20: (3, "OK", 4, 0),
    21: (4, "OK", 4, 3),
    31: (6, "OK", 6, 4),
    37: (6, "OK", 6, 6),
    41: (6, "OK", 6, 6),
    47: (7, "OK", 7, 6),
    53: (7, "OK", 7, 7),
}
ADD_CONFIGURATION: dict[int, dict[str, Any]] = {
    2: CONFIGURATION_01,
    12: CONFIGURATION_0,
    15: CONFIGURATION_01,
}
CONFIGURATION_OBSERVATIONS: dict[int, list[dict[str, Any]]] = {
    1: [CONFIGURATION_0],
    2: [CONFIGURATION_0],
    6: [],
    12: [],
    14: [CONFIGURATION_0],
    15: [CONFIGURATION_0],
    22: [CONFIGURATION_0, CONFIGURATION_01],
    29: [CONFIGURATION_0, CONFIGURATION_01],
    32: [CONFIGURATION_01],
    35: [CONFIGURATION_01],
    48: [CONFIGURATION_01],
    51: [CONFIGURATION_01],
}
COMMIT_TARGETS: dict[int, int] = {
    1: 2,
    14: 2,
    22: 4,
    29: 4,
    32: 6,
    35: 6,
    48: 7,
    51: 7,
}
REPLICATES: dict[int, tuple[int, int, bool]] = {
    4: (2, 4, True),
    23: (2, 5, False),
    24: (2, 6, True),
    42: (2, 7, True),
}
EXECUTE_APPEND = {13, 18, 27, 28, 45}


def _expected_state(expected: ExpectedEvent) -> dict[str, Any]:
    """Expand an expected scalar row to the exact C++ state object."""

    return {
        "commit_idx": expected.commit_index,
        "committable_indices": list(expected.committable_indices),
        "current_view": expected.term,
        "last_idx": expected.last_index,
        "leadership_state": expected.role,
        "membership_state": "Active",
        "node_id": expected.node,
        "pre_vote_enabled": True,
    }


def _expected_message(number: int) -> dict[str, Any]:
    """Build the complete exact message expected at one event number."""

    expected = EXPECTED_EVENTS[number]
    message: dict[str, Any] = {
        "function": expected.function,
        "state": _expected_state(expected),
    }
    if number in CONFIGURATION_OBSERVATIONS:
        message["configurations"] = CONFIGURATION_OBSERVATIONS[number]
    if number in COMMIT_TARGETS:
        message["args"] = {"idx": COMMIT_TARGETS[number]}
    if number in ADD_CONFIGURATION:
        message["args"] = {"configuration": ADD_CONFIGURATION[number]}
    if number in REPLICATES:
        view, sequence, committable = REPLICATES[number]
        message.update(
            {
                "globally_committable": committable,
                "seqno": sequence,
                "view": view,
            }
        )
    if number in SEND_APPEND:
        sent, matched, previous, index, commit, previous_term = SEND_APPEND[number]
        message.update(
            {
                "match_idx": matched,
                "packet": _append_packet(previous, index, commit, previous_term),
                "sent_idx": sent,
                "to_node_id": "1",
            }
        )
    if number in RECEIVE_APPEND:
        previous, index, commit, previous_term = RECEIVE_APPEND[number]
        message.update(
            {
                "from_node_id": "0",
                "packet": _append_packet(previous, index, commit, previous_term),
            }
        )
    if number in SEND_RESPONSE:
        last_index, success = SEND_RESPONSE[number]
        message.update(
            {
                "packet": _response_packet(last_index, success),
                "to_node_id": "0",
            }
        )
    if number in RECEIVE_RESPONSE:
        last_index, success, sent, matched = RECEIVE_RESPONSE[number]
        message.update(
            {
                "from_node_id": "1",
                "match_idx": matched,
                "packet": _response_packet(last_index, success),
                "sent_idx": sent,
            }
        )
    if number in EXECUTE_APPEND:
        message["from_node_id"] = "0"
    return message


def read_events(path: Path) -> list[Event]:
    """Read NDJSON while retaining each input line byte-for-byte as text."""

    events: list[Event] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        require(bool(raw.strip()), f"raw NDJSON event {number} is empty")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ReductionError(f"raw NDJSON event {number}: {error}") from error
        require(isinstance(parsed, dict), f"event {number}: top level is not an object")
        events.append(Event(number, raw, parsed))
    return events


def validate_events(events: Sequence[Event]) -> None:
    """Strictly validate every event field consumed by this fixture reducer."""

    require(
        len(events) == EXPECTED_EVENT_COUNT,
        f"real trace has {len(events)} events, expected {EXPECTED_EVENT_COUNT}",
    )
    previous_timestamp = -1
    for event in events:
        expected = EXPECTED_EVENTS[event.number]
        row = event.row
        require(
            set(row) == TOP_LEVEL_KEYS,
            f"event {event.number}: top-level keys are {sorted(row)}, "
            f"expected {sorted(TOP_LEVEL_KEYS)}",
        )
        require(row["tag"] == "raft_trace", f"event {event.number}: wrong tag")
        require(row["level"] == "debug", f"event {event.number}: wrong level")
        require(
            row["file"] == "CCF/src/consensus/aft/raft.h",
            f"event {event.number}: wrong source file",
        )
        require(
            isinstance(row["number"], str) and row["number"].isdigit(),
            f"event {event.number}: source line is not a decimal string",
        )
        require(row["thread_id"] == "0", f"event {event.number}: wrong thread")
        require(
            isinstance(row["h_ts"], str) and row["h_ts"].isdigit(),
            f"event {event.number}: h_ts is not a decimal string",
        )
        timestamp = int(row["h_ts"])
        require(
            timestamp > previous_timestamp,
            f"event {event.number}: h_ts is not strictly increasing",
        )
        previous_timestamp = timestamp
        require(
            row["cmd"] == expected.command,
            f"event {event.number}: cmd is {row['cmd']!r}, "
            f"expected {expected.command!r}",
        )
        expected_prefix = expected.command.split(",", 1)[0]
        require(
            row["cmd_prefix"] == expected_prefix,
            f"event {event.number}: cmd_prefix is {row['cmd_prefix']!r}, "
            f"expected {expected_prefix!r}",
        )
        expected_message = _expected_message(event.number)
        require(
            event.message == expected_message,
            f"event {event.number}: msg differs from the pinned fixture:\n"
            f"actual={json.dumps(event.message, sort_keys=True)}\n"
            f"expected={json.dumps(expected_message, sort_keys=True)}",
        )
        require(
            set(event.message["state"]) == STATE_KEYS,
            f"event {event.number}: state keys changed",
        )


def _action(kind: str, template: str, **parameters: Any) -> ActionSpec:
    """Create one structured proposed action specification."""

    return ActionSpec(kind, template, parameters)


def _append(end: int) -> ActionSpec:
    """Create a leader-zero to follower-one AppendEntries action."""

    return _action(
        "appendEntries",
        f"appendEntries 0 1 {end}",
        source=0,
        destination=1,
        batch_end=end,
    )


def _receive(source: int, destination: int) -> ActionSpec:
    """Create one proposed FIFO receive action."""

    return _action(
        "receive",
        f"receive {source} {destination}",
        source=source,
        destination=destination,
    )


def reduction_specs() -> tuple[ReductionSpec, ...]:
    """Return the pinned 22-group, 43-action full-trace reduction."""

    append = _append
    receive = _receive
    sign = _action(
        "signCommittableMessages",
        "signCommittableMessages 0",
        node=0,
    )
    commit = _action(
        "advanceCommitIndex",
        "advanceCommitIndex 0",
        node=0,
    )
    return (
        ReductionSpec(
            "bootstrap-commit",
            (1,),
            (commit,),
            "Synthetic bootstrap exposes the pre-commit state at index 2.",
        ),
        ReductionSpec(
            "add-node-one",
            (2, 3),
            (
                _action(
                    "changeConfiguration",
                    "changeConfiguration 0 {0,1}",
                    source=0,
                    new_configuration=[0, 1],
                ),
                append(3),
            ),
            "Append configuration {0,1}, then propose replication of entry 3.",
            ("event3-pre-reconfiguration-hook",),
        ),
        ReductionSpec(
            "signature-four",
            (4,),
            (sign,),
            "Append the committable signature at absolute index 4.",
        ),
        ReductionSpec(
            "initial-follower-nack",
            (5, 6, 7),
            (
                _action(
                    "updateTerm",
                    "updateTerm 0 1",
                    source=0,
                    destination=1,
                ),
                receive(0, 1),
            ),
            "Node 1 observes term 2, then rejects the unmatched request.",
        ),
        ReductionSpec(
            "leader-receives-nack",
            (8,),
            (receive(1, 0),),
            "The leader consumes node 1's NACK.",
            ("event8-sent-index-translation",),
        ),
        ReductionSpec(
            "split-prefix-send",
            (9, 10),
            (append(1), append(2), append(3), append(4)),
            "Split C++ batches 1..3 and 4 into proposed one-entry sends.",
            ("split-request-batches",),
        ),
        ReductionSpec(
            "split-prefix-receive",
            tuple(range(11, 17)),
            (receive(0, 1), receive(0, 1), receive(0, 1)),
            "Propose receives for entries 1, 2, and 3; helper events are assertions.",
            (
                "split-receive-batches",
                "helper-events-are-assertions",
                "follower-commit-callback-atomicity",
            ),
        ),
        ReductionSpec(
            "signature-four-receive",
            (17, 18, 19),
            (receive(0, 1),),
            "Propose receipt of entry 4; execute/send-response are assertions.",
            ("helper-events-are-assertions",),
        ),
        ReductionSpec(
            "split-prefix-responses",
            (20, 21),
            (
                receive(1, 0),
                receive(1, 0),
                receive(1, 0),
                receive(1, 0),
            ),
            "Propose responses 1..4 for C++ batch ends 3 and 4.",
            ("synthetic-responses-1-2",),
        ),
        ReductionSpec(
            "leader-commit-four",
            (22,),
            (commit,),
            "Advance the leader commit index to 4.",
        ),
        ReductionSpec(
            "client-entry-five",
            (23,),
            (
                _action(
                    "clientRequest",
                    "clientRequest 0 <fresh-tx-1>",
                    node=0,
                    transaction="fresh-tx-1",
                ),
            ),
            "Append the scenario's only fresh client transaction.",
        ),
        ReductionSpec(
            "signature-six",
            (24,),
            (sign,),
            "Append the committable signature at absolute index 6.",
        ),
        ReductionSpec(
            "split-five-six-send",
            (25,),
            (append(5), append(6)),
            "Split the C++ 5..6 batch into two proposed sends.",
            ("split-request-batches",),
        ),
        ReductionSpec(
            "split-five-six-receive",
            tuple(range(26, 31)),
            (receive(0, 1), receive(0, 1)),
            "Receive entries 5 and 6; helper/commit/response events are assertions.",
            (
                "split-receive-batches",
                "helper-events-are-assertions",
                "event28-batched-follower-commit",
            ),
        ),
        ReductionSpec(
            "split-five-six-responses",
            (31,),
            (receive(1, 0), receive(1, 0)),
            "Propose responses at 5 and 6 for the C++ response at 6.",
            ("synthetic-response-5",),
        ),
        ReductionSpec(
            "leader-commit-six",
            (32,),
            (commit,),
            "Advance the leader commit index to 6.",
        ),
        ReductionSpec(
            "first-heartbeat-six",
            tuple(range(33, 38)),
            (append(6), receive(0, 1), receive(1, 0)),
            "Send and round-trip the first heartbeat at index 6.",
            (
                "helper-events-are-assertions",
                "follower-commit-callback-atomicity",
            ),
        ),
        ReductionSpec(
            "second-heartbeat-six",
            tuple(range(38, 42)),
            (append(6), receive(0, 1), receive(1, 0)),
            "Send and round-trip the second heartbeat at index 6.",
            ("helper-events-are-assertions",),
        ),
        ReductionSpec(
            "signature-seven",
            (42,),
            (sign,),
            "Append the assert_state_sync signature at index 7.",
        ),
        ReductionSpec(
            "entry-seven-round-trip",
            tuple(range(43, 48)),
            (append(7), receive(0, 1), receive(1, 0)),
            "Replicate and acknowledge signature entry 7.",
            ("helper-events-are-assertions",),
        ),
        ReductionSpec(
            "leader-commit-seven",
            (48,),
            (commit,),
            "Advance the leader commit index to 7.",
        ),
        ReductionSpec(
            "final-heartbeat-seven",
            tuple(range(49, 54)),
            (append(7), receive(0, 1), receive(1, 0)),
            "Propagate commit 7 and consume the final heartbeat response.",
            (
                "helper-events-are-assertions",
                "follower-commit-callback-atomicity",
            ),
        ),
    )


OBSERVATION_POSITIONS: dict[int, tuple[str, int, str | None]] = {
    1: ("before", 1, None),
    2: ("before", 2, None),
    3: ("during", 2, "pre-reconfiguration-send-hook"),
    4: ("before", 4, None),
    5: ("before", 5, None),
    6: ("after", 5, None),
    7: ("after", 6, None),
    8: ("before", 7, None),
    10: ("before", 11, None),
    12: ("after", 12, None),
    13: ("after", 12, None),
    14: ("during", 13, "pre-follower-commit-callback"),
    15: ("after", 14, None),
    16: ("after", 14, None),
    17: ("before", 15, None),
    18: ("before", 15, None),
    19: ("after", 15, None),
    21: ("before", 19, None),
    22: ("before", 20, None),
    23: ("before", 21, None),
    24: ("before", 22, None),
    27: ("before", 25, None),
    28: ("before", 26, None),
    29: ("during", 26, "pre-follower-commit-callback"),
    30: ("after", 26, None),
    32: ("before", 29, None),
    33: ("before", 30, None),
    34: ("before", 31, None),
    35: ("during", 31, "pre-follower-commit-callback"),
    36: ("after", 31, None),
    37: ("before", 32, None),
    38: ("before", 33, None),
    39: ("before", 34, None),
    40: ("after", 34, None),
    41: ("before", 35, None),
    42: ("before", 36, None),
    43: ("before", 37, None),
    44: ("before", 38, None),
    45: ("before", 38, None),
    46: ("after", 38, None),
    47: ("before", 39, None),
    48: ("before", 40, None),
    49: ("before", 41, None),
    50: ("before", 42, None),
    51: ("during", 42, "pre-follower-commit-callback"),
    52: ("after", 42, None),
    53: ("before", 43, None),
}

ACTION_SPANS: dict[int, dict[str, Any]] = {
    9: {
        "span_kind": "append_entries_batch_send",
        "start_action": 8,
        "end_action": 10,
        "absolute_index_range": {"start": 1, "end": 3},
        "post_state_observation_event": 10,
    },
    11: {
        "span_kind": "append_entries_batch_receive",
        "start_action": 12,
        "end_action": 14,
        "absolute_index_range": {"start": 1, "end": 3},
        "post_state_observation_event": 15,
    },
    20: {
        "span_kind": "append_entries_batch_response_receive",
        "start_action": 16,
        "end_action": 18,
        "absolute_index_range": {"start": 1, "end": 3},
        "post_state_observation_event": 21,
    },
    25: {
        "span_kind": "append_entries_batch_send",
        "start_action": 23,
        "end_action": 24,
        "absolute_index_range": {"start": 5, "end": 6},
        "post_state_observation_event": 26,
    },
    26: {
        "span_kind": "append_entries_batch_receive",
        "start_action": 25,
        "end_action": 26,
        "absolute_index_range": {"start": 5, "end": 6},
        "post_state_observation_event": 30,
    },
    31: {
        "span_kind": "append_entries_batch_response_receive",
        "start_action": 27,
        "end_action": 28,
        "absolute_index_range": {"start": 5, "end": 6},
        "post_state_observation_event": 32,
    },
}

EVENT_EXCEPTIONS: dict[int, tuple[str, ...]] = {
    3: ("event3-pre-reconfiguration-hook",),
    8: ("event8-sent-index-translation",),
    9: ("split-request-batches",),
    11: ("split-receive-batches",),
    12: ("helper-events-are-assertions",),
    13: ("helper-events-are-assertions",),
    14: (
        "helper-events-are-assertions",
        "follower-commit-callback-atomicity",
    ),
    15: ("helper-events-are-assertions",),
    16: ("helper-events-are-assertions",),
    18: ("helper-events-are-assertions",),
    19: ("helper-events-are-assertions",),
    20: ("synthetic-responses-1-2",),
    25: ("split-request-batches",),
    26: ("split-receive-batches",),
    27: ("helper-events-are-assertions",),
    28: (
        "helper-events-are-assertions",
        "event28-batched-follower-commit",
    ),
    29: (
        "helper-events-are-assertions",
        "event28-batched-follower-commit",
    ),
    30: ("helper-events-are-assertions",),
    31: ("synthetic-response-5",),
    35: (
        "helper-events-are-assertions",
        "follower-commit-callback-atomicity",
    ),
    36: ("helper-events-are-assertions",),
    40: ("helper-events-are-assertions",),
    45: ("helper-events-are-assertions",),
    46: ("helper-events-are-assertions",),
    51: (
        "helper-events-are-assertions",
        "follower-commit-callback-atomicity",
    ),
    52: ("helper-events-are-assertions",),
}

EXCEPTIONS: dict[str, dict[str, Any]] = {
    "event3-pre-reconfiguration-hook": {
        "events": [3],
        "decision": (
            "C++ event 3 runs inside add_configuration before the visible state "
            "publishes log index 3. Its wire packet is a heartbeat ending at 2, "
            "while the proposed changeConfiguration action appends entry 3 and the "
            "following appendEntries action sends that configuration entry."
        ),
        "omitted_fields": [
            "msg.state.last_idx",
            "msg.sent_idx",
            "msg.packet.idx",
            "msg.packet.prev_idx",
            "msg.packet.prev_term",
            "msg.packet.term_of_idx",
        ],
    },
    "event8-sent-index-translation": {
        "events": [8],
        "decision": (
            "C++ event 8 reports sent_idx=2 after its special heartbeat/configuration "
            "hook sequence. The proposed mapping has sent index 3 before consuming "
            "the NACK and 0 afterward, so no action checkpoint has value 2."
        ),
        "omitted_fields": ["event8.msg.sent_idx"],
        "translation": {
            "implementation_value": 2,
            "proposed_pre_nack_value": 3,
            "proposed_post_nack_value": 0,
        },
    },
    "event28-batched-follower-commit": {
        "events": [28, 29],
        "decision": (
            "C++ applies the two-entry batch before one follower commit callback. "
            "Proposed one-entry receives advance commit after entry 5, so event "
            "28's commit_idx=2 is not imposed after proposed action 25. Event 29 "
            "is an intra-action callback and is not treated as an atomic checkpoint."
        ),
        "omitted_fields": [
            "event28.msg.state.commit_idx",
            "event29.msg.state.last_idx",
            "event29.msg.state.commit_idx",
        ],
    },
    "synthetic-responses-1-2": {
        "events": [20],
        "decision": (
            "Splitting C++ batch 1..3 creates proposed responses at indices 1, 2, "
            "and 3. Event 20 observes only the aggregate C++ response at index 3; "
            "the responses at 1 and 2 are explicit proposed messages."
        ),
        "synthetic_actions": [16, 17],
    },
    "synthetic-response-5": {
        "events": [31],
        "decision": (
            "Splitting C++ batch 5..6 creates proposed responses at indices 5 and "
            "6. Event 31 observes only the aggregate response at index 6; the "
            "response at 5 is an explicit proposed message."
        ),
        "synthetic_actions": [27],
    },
    "split-request-batches": {
        "events": [9, 25],
        "decision": (
            "C++ packets may contain several entries. The proposed appendEntries "
            "mapping sends at most one next entry, so event 9 expands to ends 1, 2, "
            "and 3, and "
            "event 25 expands to ends 5 and 6."
        ),
    },
    "split-receive-batches": {
        "events": [11, 26],
        "decision": (
            "C++ events 11 and 26 each receive one multi-entry packet. Their state "
            "fields constrain the start of the proposed receive span, while packet "
            "range fields constrain the full span. They are not single-action "
            "checkpoints."
        ),
    },
    "helper-events-are-assertions": {
        "events": [
            12,
            13,
            14,
            15,
            16,
            18,
            19,
            27,
            28,
            29,
            30,
            35,
            36,
            40,
            45,
            46,
            51,
            52,
        ],
        "decision": (
            "add_configuration, execute_append_entries_sync, commit, and "
            "send_append_entries_response records inside a C++ receive are assigned "
            "to that mapping group as timing/state assertions. They do not add "
            "actions because the proposed receive performs these effects atomically."
        ),
    },
    "follower-commit-callback-atomicity": {
        "events": [14, 35, 51],
        "decision": (
            "These C++ commit hooks expose the pre-commit state during an atomic "
            "proposed receive. Their commit_idx fields are validated against the "
            "fixture but omitted from atomic action checkpoints."
        ),
        "omitted_fields": [
            "event14.msg.state.last_idx",
            "event14.msg.state.commit_idx",
            "event35.msg.state.commit_idx",
            "event51.msg.state.commit_idx",
        ],
    },
}

FIELD_OMISSIONS: dict[tuple[int, str], str] = {
    (3, "msg.state.last_idx"): "event3-hook-timing",
    (3, "msg.sent_idx"): "event3-hook-timing",
    (3, "msg.packet.idx"): "event3-hook-timing",
    (3, "msg.packet.prev_idx"): "event3-hook-timing",
    (3, "msg.packet.prev_term"): "event3-hook-timing",
    (3, "msg.packet.term_of_idx"): "event3-hook-timing",
    (8, "msg.sent_idx"): "event8-sent-index-translation",
    (14, "msg.state.last_idx"): "atomicity-exception",
    (14, "msg.state.commit_idx"): "atomicity-exception",
    (28, "msg.state.commit_idx"): "atomicity-exception",
    (29, "msg.state.last_idx"): "atomicity-exception",
    (29, "msg.state.commit_idx"): "atomicity-exception",
    (35, "msg.state.commit_idx"): "atomicity-exception",
    (51, "msg.state.commit_idx"): "atomicity-exception",
}


def _leaf_paths(value: Any, prefix: str = "") -> Iterator[str]:
    """Yield every leaf path in a JSON-compatible value."""

    if isinstance(value, dict):
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else key
            yield from _leaf_paths(value[key], child)
    elif isinstance(value, list):
        if not value:
            yield prefix
        else:
            for index, item in enumerate(value):
                yield from _leaf_paths(item, f"{prefix}[{index}]")
    else:
        yield prefix


def _configuration_membership_paths(value: Any, prefix: str = "") -> Iterator[str]:
    """Yield explicit paths for configuration membership encoded as object keys."""

    if isinstance(value, dict):
        if "nodes" in value and isinstance(value["nodes"], dict):
            yield f"{prefix}.nodes.<keys>" if prefix else "nodes.<keys>"
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else key
            yield from _configuration_membership_paths(value[key], child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _configuration_membership_paths(item, f"{prefix}[{index}]")


def _field_status(event_number: int, path: str) -> tuple[str, str]:
    """Classify one raw field as projected or explicitly omitted."""

    omission_reason = FIELD_OMISSIONS.get((event_number, path))
    if omission_reason is not None:
        return "omitted", omission_reason
    if path.startswith(("h_ts", "file", "level", "number", "thread_id", "tag")):
        return "omitted", "trace-envelope-only"
    if path.startswith(("cmd", "cmd_prefix")):
        return "omitted", "scenario-provenance-only"
    if ".address" in path or path.endswith(".rid"):
        return "omitted", "implementation-configuration-metadata"
    if path.startswith("msg.configurations"):
        return "omitted", "configuration-history-assertion-only"
    if path == "msg.state.membership_state":
        return "omitted", "model-membership-is-derived-from-log"
    if path == "msg.state.pre_vote_enabled":
        return "omitted", "pre-vote-out-of-scope"
    if path.startswith("msg.state.committable_indices"):
        return "omitted", "model-committable-frontier-is-derived"
    if path == "msg.packet.contains_new_view":
        return "omitted", "model-packet-has-no-corresponding-field"
    if (
        EXPECTED_EVENTS[event_number].function
        in {
            "add_configuration",
            "become_follower",
            "execute_append_entries_sync",
            "send_append_entries_response",
        }
        and path == "msg.function"
    ):
        return "omitted", "helper-event-assigned-as-assertion"
    return "projected", "proposed-action-or-observation"


def _field_semantics(
    event_number: int,
    path: str,
    status: str,
) -> tuple[str, dict[str, Any]]:
    """Assign an explicit semantic kind and action-relative field position."""

    if status == "omitted":
        return "validated-input-only", {
            "kind": "input_event",
            "event": event_number,
        }

    span = ACTION_SPANS.get(event_number)
    state_scalar = path.startswith("msg.state.") or path in {
        "msg.sent_idx",
        "msg.match_idx",
    }
    if span is not None:
        if state_scalar:
            return "pre-state-scalar", {
                "kind": "span_start",
                "before_action": span["start_action"],
            }
        if path.startswith("msg.packet."):
            packet_kind = (
                "aggregate-response-constraint"
                if "response" in span["span_kind"]
                else "aggregate-packet-range-constraint"
            )
            return packet_kind, {
                "kind": "whole_action_span",
                "start_action": span["start_action"],
                "end_action": span["end_action"],
            }
        return "aggregate-span-constraint", {
            "kind": "whole_action_span",
            "start_action": span["start_action"],
            "end_action": span["end_action"],
        }

    relation, action_number, phase = OBSERVATION_POSITIONS[event_number]
    field_position: dict[str, Any] = {
        "kind": "action_checkpoint",
        "relation": relation,
        "action": action_number,
    }
    if phase is not None:
        field_position["phase"] = phase
    if state_scalar:
        scalar_kind = {
            "before": "pre-state-scalar",
            "after": "post-state-scalar",
            "during": "intra-action-state-scalar",
        }[relation]
        return scalar_kind, field_position
    if path.startswith("msg.packet."):
        return "wire-packet-constraint", field_position
    if path == "msg.function":
        return "event-grammar-constraint", field_position
    return "event-field-constraint", field_position


def _field_decision(event_number: int, path: str) -> dict[str, Any]:
    """Build one exhaustive field projection decision."""

    status, reason = _field_status(event_number, path)
    field_kind, field_position = _field_semantics(
        event_number,
        path,
        status,
    )
    return {
        "path": path,
        "status": status,
        "reason": reason,
        "field_kind": field_kind,
        "field_position": field_position,
    }


def _observation(event: Event) -> dict[str, Any]:
    """Build one action-relative observation with exhaustive field decisions."""

    span = ACTION_SPANS.get(event.number)
    if span is None:
        relation, action_number, phase = OBSERVATION_POSITIONS[event.number]
        position: dict[str, Any] = {
            "kind": "action_checkpoint",
            "relation": relation,
            "action": action_number,
        }
        if phase is not None:
            position["phase"] = phase
    else:
        position = {
            "kind": "action_span",
            **span,
            "pre_state_position": {
                "kind": "before_action",
                "action": span["start_action"],
            },
            "aggregate_constraint_position": {
                "kind": "whole_action_span",
                "start_action": span["start_action"],
                "end_action": span["end_action"],
            },
            "post_state_position": {
                "kind": "referenced_event_after_span",
                "event": span["post_state_observation_event"],
                "after_action": span["end_action"],
            },
            "post_state_fields": [
                "msg.state.node_id",
                "msg.state.leadership_state",
                "msg.state.current_view",
                "msg.state.last_idx",
                "msg.state.commit_idx",
            ],
        }
    paths = sorted(
        set(_leaf_paths(event.row)) | set(_configuration_membership_paths(event.row))
    )
    return {
        "event": event.number,
        "position": position,
        "field_decisions": [_field_decision(event.number, path) for path in paths],
        "exception_ids": list(EVENT_EXCEPTIONS.get(event.number, ())),
    }


def _serialize_action(number: int, action: ActionSpec) -> dict[str, Any]:
    """Convert one proposed action specification to certificate JSON."""

    return {
        "action": number,
        "kind": action.kind,
        "template": action.template,
        "parameters": dict(action.parameters),
    }


def _serialize_reductions(
    events: Sequence[Event],
    specs: Sequence[ReductionSpec],
) -> list[dict[str, Any]]:
    """Assign global action numbers and observations to every reduction."""

    by_number = {event.number: event for event in events}
    serialized: list[dict[str, Any]] = []
    next_action = 1
    for reduction_number, spec in enumerate(specs, 1):
        actions = [
            _serialize_action(next_action + offset, action)
            for offset, action in enumerate(spec.actions)
        ]
        next_action += len(actions)
        serialized.append(
            {
                "reduction": reduction_number,
                "name": spec.name,
                "events": list(spec.events),
                "actions": actions,
                "observations": [
                    _observation(by_number[event_number])
                    for event_number in spec.events
                ],
                "summary": spec.summary,
                "exception_ids": list(spec.exception_ids),
            }
        )
    require(
        next_action - 1 == EXPECTED_ACTION_COUNT,
        f"internal action count is {next_action - 1}, expected {EXPECTED_ACTION_COUNT}",
    )
    return serialized


def _all_actions(reductions: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Flatten certificate actions in reduction order."""

    return [action for reduction in reductions for action in reduction["actions"]]


def infer_capacities(
    events: Sequence[Event],
    reductions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Infer bounded-state capacities and check the abstract network drains."""

    actions = _all_actions(reductions)
    occupancy: dict[tuple[int, int], int] = {(0, 1): 0, (1, 0): 0}
    maximum = dict(occupancy)
    for action in actions:
        kind = action["kind"]
        parameters = action["parameters"]
        if kind == "appendEntries":
            lane = (parameters["source"], parameters["destination"])
            occupancy[lane] = occupancy.get(lane, 0) + 1
            maximum[lane] = max(maximum.get(lane, 0), occupancy[lane])
        elif kind == "receive":
            lane = (parameters["source"], parameters["destination"])
            occupancy[lane] = occupancy.get(lane, 0) - 1
            require(
                occupancy[lane] >= 0,
                f"action {action['action']}: modeled lane {lane} became negative",
            )
            if lane == (0, 1):
                response_lane = (1, 0)
                occupancy[response_lane] = occupancy.get(response_lane, 0) + 1
                maximum[response_lane] = max(
                    maximum.get(response_lane, 0),
                    occupancy[response_lane],
                )
            else:
                require(
                    lane == (1, 0),
                    f"action {action['action']}: unsupported receive lane {lane}",
                )
    nonzero = {lane: value for lane, value in occupancy.items() if value != 0}
    require(not nonzero, f"terminal modeled queues are nonzero: {nonzero}")

    absolute_indices: list[int] = []
    configurations: set[tuple[str, ...]] = set()
    configuration_record_indices = {0}
    max_active_configuration_history_length = 0
    for event in events:
        message = event.message
        state = message["state"]
        absolute_indices.extend(
            [state["last_idx"], state["commit_idx"], *state["committable_indices"]]
        )
        packet = message.get("packet", {})
        for key in ("idx", "prev_idx", "leader_commit_idx", "last_log_idx"):
            value = packet.get(key)
            if isinstance(value, int):
                absolute_indices.append(value)
        for key in ("seqno",):
            value = message.get(key)
            if isinstance(value, int):
                absolute_indices.append(value)
        args = message.get("args", {})
        if isinstance(args.get("idx"), int):
            absolute_indices.append(args["idx"])
        configuration = args.get("configuration")
        if isinstance(configuration, dict):
            configurations.add(tuple(sorted(configuration["nodes"])))
            absolute_indices.append(configuration["idx"])
            configuration_record_indices.add(configuration["idx"])
        observed_configurations = message.get("configurations", [])
        max_active_configuration_history_length = max(
            max_active_configuration_history_length,
            len(observed_configurations),
        )
        for observed in observed_configurations:
            configurations.add(tuple(sorted(observed["nodes"])))
            absolute_indices.append(observed["idx"])
            configuration_record_indices.add(observed["idx"])

    lane_values = [
        {
            "source": source,
            "destination": destination,
            "maximum_occupancy": maximum[(source, destination)],
            "terminal_occupancy": occupancy[(source, destination)],
        }
        for source, destination in sorted(occupancy)
    ]
    return {
        "node_world_capacity": NODE_WORLD_CAPACITY,
        "observed_nodes": [0, 1],
        "max_absolute_log_index": max(absolute_indices),
        "fresh_transaction_id_capacity": sum(
            action["kind"] == "clientRequest" for action in actions
        ),
        "network_lanes": lane_values,
        "max_per_source_destination_lane": max(maximum.values()),
        "action_capacity": len(actions),
        "distinct_configuration_value_count": len(configurations),
        "physical_configuration_record_capacity": len(configuration_record_indices),
        "configuration_record_indices": sorted(configuration_record_indices),
        "max_active_configuration_history_length": (
            max_active_configuration_history_length
        ),
        "configurations": [
            list(configuration) for configuration in sorted(configurations)
        ],
    }


def _input_digest(events: Sequence[Event]) -> str:
    """Hash the exact NDJSON text represented by the certificate."""

    text = "\n".join(event.raw for event in events) + "\n"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_certificate(events: Sequence[Event]) -> dict[str, Any]:
    """Build the versioned proposed deterministic mapping certificate."""

    specs = reduction_specs()
    reductions = _serialize_reductions(events, specs)
    capacities = infer_capacities(events, reductions)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": "proposed_deterministic_mapping_certificate",
        "prototype": {
            "name": "naive-full-state",
            "scope": "proposed-deterministic-full-53-event-mapping",
            "semantic_status": "unchecked-by-lean",
            "canonical_replay_performed": False,
            "smt_performed": False,
            "bootstrap_entry_state": {
                "configuration": [0],
                "leader": 0,
                "term": 2,
                "absolute_log_entries": [
                    {"index": 1, "kind": "reconfiguration", "nodes": [0]},
                    {"index": 2, "kind": "signature"},
                ],
                "commit_index": 0,
                "network": "empty",
            },
            "trace_derived_capacity_coupling": {
                "coupled": True,
                "decision": (
                    "The naive bounded full-state shape is derived from this trace's "
                    "absolute indices, fresh transaction count, deterministic action "
                    "expansion, source/destination lane occupancy, and configurations."
                ),
                "consequence": (
                    "A reduction bug can under-allocate the prototype; the certificate "
                    "therefore records the derivation and the checker recomputes it."
                ),
            },
        },
        "input": {
            "scenario": "tests/raft_scenarios/replicate",
            "preprocessor": "tests/raft_scenarios_runner.py",
            "event_count": len(events),
            "sha256": _input_digest(events),
        },
        "raw_events": [
            {
                "event": event.number,
                "sha256": hashlib.sha256(event.raw.encode("utf-8")).hexdigest(),
                "raw": event.raw,
            }
            for event in events
        ],
        "reductions": reductions,
        "correspondence_exceptions": EXCEPTIONS,
        "counts": {
            "events": len(events),
            "consumed_events": sum(len(spec.events) for spec in specs),
            "reductions": len(specs),
            "actions": len(_all_actions(reductions)),
            "observations": sum(
                len(reduction["observations"]) for reduction in reductions
            ),
            "action_span_observations": len(ACTION_SPANS),
            "action_checkpoint_observations": (len(events) - len(ACTION_SPANS)),
        },
        "capacities": capacities,
    }


def _validate_exception_references(
    reductions: Sequence[Mapping[str, Any]],
    registry: Mapping[str, Any],
) -> None:
    """Require exception registry and event/reduction references to agree both ways."""

    observation_refs: dict[int, set[str]] = {}
    for reduction in reductions:
        reduction_event_refs: set[str] = set()
        for observation in reduction.get("observations", []):
            event_number = observation.get("event")
            references = observation.get("exception_ids")
            require(
                isinstance(event_number, int) and isinstance(references, list),
                "observation exception references are malformed",
            )
            require(
                len(references) == len(set(references)),
                f"event {event_number}: duplicate exception reference",
            )
            for exception_id in references:
                require(
                    exception_id in registry,
                    f"event {event_number}: unknown exception {exception_id}",
                )
            observation_refs[event_number] = set(references)
            reduction_event_refs.update(references)
        reduction_refs = reduction.get("exception_ids")
        require(
            isinstance(reduction_refs, list),
            f"reduction {reduction.get('reduction')}: exception_ids is not an array",
        )
        require(
            set(reduction_refs) == reduction_event_refs,
            f"reduction {reduction.get('reduction')}: exception references "
            "do not equal its event references",
        )

    registry_refs: dict[int, set[str]] = {}
    for exception_id, exception in registry.items():
        require(
            isinstance(exception_id, str) and isinstance(exception, dict),
            "exception registry entry is malformed",
        )
        exception_events = exception.get("events")
        require(
            isinstance(exception_events, list)
            and exception_events
            and len(exception_events) == len(set(exception_events)),
            f"exception {exception_id}: events must be a nonempty unique array",
        )
        for event_number in exception_events:
            require(
                isinstance(event_number, int)
                and 1 <= event_number <= EXPECTED_EVENT_COUNT,
                f"exception {exception_id}: invalid event {event_number}",
            )
            registry_refs.setdefault(event_number, set()).add(exception_id)

    referenced_ids = {
        exception_id
        for references in observation_refs.values()
        for exception_id in references
    }
    require(
        referenced_ids == set(registry),
        "exception registry contains an unreferenced or missing exception",
    )
    for event_number in range(1, EXPECTED_EVENT_COUNT + 1):
        require(
            observation_refs.get(event_number, set())
            == registry_refs.get(event_number, set()),
            f"event {event_number}: exception registry and references disagree",
        )


def validate_certificate_invariants(
    events: Sequence[Event],
    certificate: Mapping[str, Any],
) -> None:
    """Validate schema, exact input retention, coverage, actions, and capacities."""

    require(
        certificate.get("schema_version") == SCHEMA_VERSION,
        "certificate schema_version is absent or unsupported",
    )
    require(
        certificate.get("artifact_kind")
        == "proposed_deterministic_mapping_certificate",
        "certificate artifact_kind is absent or unsupported",
    )
    raw_events = certificate.get("raw_events")
    reductions = certificate.get("reductions")
    exceptions = certificate.get("correspondence_exceptions")
    counts = certificate.get("counts")
    capacities = certificate.get("capacities")
    require(isinstance(raw_events, list), "certificate raw_events is not an array")
    require(isinstance(reductions, list), "certificate reductions is not an array")
    require(isinstance(exceptions, dict), "exception registry is not an object")
    require(isinstance(counts, dict), "certificate counts is not an object")
    require(isinstance(capacities, dict), "certificate capacities is not an object")
    require(
        len(raw_events) == EXPECTED_EVENT_COUNT,
        f"certificate retains {len(raw_events)} raw events, expected {EXPECTED_EVENT_COUNT}",
    )
    for event, retained in zip(events, raw_events):
        require(
            retained.get("event") == event.number,
            f"raw event slot {event.number} has the wrong number",
        )
        require(
            retained.get("raw") == event.raw,
            f"raw event {event.number} is not retained exactly",
        )
        expected_hash = hashlib.sha256(event.raw.encode("utf-8")).hexdigest()
        require(
            retained.get("sha256") == expected_hash,
            f"raw event {event.number} hash differs",
        )

    require(
        len(reductions) == EXPECTED_REDUCTION_COUNT,
        f"certificate has {len(reductions)} reductions, "
        f"expected {EXPECTED_REDUCTION_COUNT}",
    )
    consumed = [
        number for reduction in reductions for number in reduction.get("events", [])
    ]
    require(
        consumed == list(range(1, EXPECTED_EVENT_COUNT + 1)),
        "reduction event groups do not consume events 1..53 exactly once in order",
    )
    actions = _all_actions(reductions)
    require(
        len(actions) == EXPECTED_ACTION_COUNT,
        f"certificate has {len(actions)} actions, expected {EXPECTED_ACTION_COUNT}",
    )
    require(
        [action.get("action") for action in actions]
        == list(range(1, EXPECTED_ACTION_COUNT + 1)),
        "proposed action numbers are not contiguous",
    )
    observations = [
        observation
        for reduction in reductions
        for observation in reduction.get("observations", [])
    ]
    event_reduction_actions = {
        event_number: {action["action"] for action in reduction.get("actions", [])}
        for reduction in reductions
        for event_number in reduction.get("events", [])
    }
    require(
        [observation.get("event") for observation in observations]
        == list(range(1, EXPECTED_EVENT_COUNT + 1)),
        "observations do not cover every event exactly once",
    )
    observed_span_events: set[int] = set()
    for observation in observations:
        event_number = observation.get("event")
        position = observation.get("position")
        require(isinstance(position, dict), "observation position is not an object")
        if position.get("kind") == "action_span":
            require(
                event_number in ACTION_SPANS,
                f"event {event_number}: unexpected action span",
            )
            expected_span = ACTION_SPANS[event_number]
            require(
                set(
                    range(
                        expected_span["start_action"],
                        expected_span["end_action"] + 1,
                    )
                ).issubset(event_reduction_actions[event_number]),
                f"event {event_number}: action span escapes its mapping group",
            )
            for key, value in expected_span.items():
                require(
                    position.get(key) == value,
                    f"event {event_number}: action span {key} differs",
                )
            require(
                position.get("pre_state_position")
                == {
                    "kind": "before_action",
                    "action": expected_span["start_action"],
                },
                f"event {event_number}: invalid span pre-state position",
            )
            require(
                position.get("aggregate_constraint_position")
                == {
                    "kind": "whole_action_span",
                    "start_action": expected_span["start_action"],
                    "end_action": expected_span["end_action"],
                },
                f"event {event_number}: invalid aggregate constraint position",
            )
            require(
                position.get("post_state_position")
                == {
                    "kind": "referenced_event_after_span",
                    "event": expected_span["post_state_observation_event"],
                    "after_action": expected_span["end_action"],
                },
                f"event {event_number}: invalid span post-state position",
            )
            require(
                isinstance(position.get("post_state_fields"), list)
                and position["post_state_fields"],
                f"event {event_number}: span post-state fields are absent",
            )
            observed_span_events.add(event_number)
        else:
            require(
                position.get("kind") == "action_checkpoint"
                and event_number not in ACTION_SPANS,
                f"event {event_number}: invalid point observation kind",
            )
            require(
                position.get("relation") in {"before", "after", "during"},
                f"event {event_number}: invalid action relation",
            )
            action_number = position.get("action")
            require(
                isinstance(action_number, int)
                and 1 <= action_number <= EXPECTED_ACTION_COUNT,
                f"event {event_number}: invalid action checkpoint",
            )
        decisions = observation.get("field_decisions")
        require(
            isinstance(decisions, list) and decisions,
            f"event {event_number}: field decisions are absent",
        )
        require(
            all(
                decision.get("status") in {"projected", "omitted"}
                and isinstance(decision.get("reason"), str)
                and isinstance(decision.get("field_kind"), str)
                and isinstance(decision.get("field_position"), dict)
                for decision in decisions
            ),
            f"event {event_number}: malformed field decision",
        )
        for decision in decisions:
            if decision["status"] == "omitted":
                require(
                    decision["field_kind"] == "validated-input-only"
                    and decision["field_position"]
                    == {"kind": "input_event", "event": event_number},
                    f"event {event_number}: omitted field position is not explicit",
                )
        if event_number in ACTION_SPANS:
            span = ACTION_SPANS[event_number]
            projected_state = [
                decision
                for decision in decisions
                if decision["status"] == "projected"
                and (
                    decision["path"].startswith("msg.state.")
                    or decision["path"] in {"msg.sent_idx", "msg.match_idx"}
                )
            ]
            require(
                projected_state
                and all(
                    decision["field_kind"] == "pre-state-scalar"
                    and decision["field_position"]
                    == {
                        "kind": "span_start",
                        "before_action": span["start_action"],
                    }
                    for decision in projected_state
                ),
                f"event {event_number}: span state fields are not at span start",
            )
            projected_packet = [
                decision
                for decision in decisions
                if decision["status"] == "projected"
                and decision["path"].startswith("msg.packet.")
            ]
            expected_packet_kind = (
                "aggregate-response-constraint"
                if "response" in span["span_kind"]
                else "aggregate-packet-range-constraint"
            )
            require(
                projected_packet
                and all(
                    decision["field_kind"] == expected_packet_kind
                    and decision["field_position"]
                    == {
                        "kind": "whole_action_span",
                        "start_action": span["start_action"],
                        "end_action": span["end_action"],
                    }
                    for decision in projected_packet
                ),
                f"event {event_number}: aggregate packet fields do not constrain "
                "the whole span",
            )
    require(
        observed_span_events == set(ACTION_SPANS),
        "action-span observations do not match the pinned aggregate events",
    )
    _validate_exception_references(reductions, exceptions)

    expected_counts = {
        "events": EXPECTED_EVENT_COUNT,
        "consumed_events": EXPECTED_EVENT_COUNT,
        "reductions": EXPECTED_REDUCTION_COUNT,
        "actions": EXPECTED_ACTION_COUNT,
        "observations": EXPECTED_EVENT_COUNT,
        "action_span_observations": len(ACTION_SPANS),
        "action_checkpoint_observations": (EXPECTED_EVENT_COUNT - len(ACTION_SPANS)),
    }
    require(counts == expected_counts, f"certificate counts differ: {counts}")
    inferred = infer_capacities(events, reductions)
    require(capacities == inferred, "certificate capacities do not recompute")
    require(
        capacities["node_world_capacity"] == 15
        and capacities["max_absolute_log_index"] == 7
        and capacities["fresh_transaction_id_capacity"] == 1
        and capacities["max_per_source_destination_lane"] == 4
        and capacities["action_capacity"] == 43
        and capacities["distinct_configuration_value_count"] == 2
        and capacities["physical_configuration_record_capacity"] == 3
        and capacities["max_active_configuration_history_length"] == 2,
        f"unexpected inferred capacities: {capacities}",
    )


def write_certificate(path: Path, certificate: Mapping[str, Any]) -> None:
    """Write stable, reviewable JSON without a wall-clock field."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(certificate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def reduce_trace(raw_path: Path, certificate_path: Path, quiet: bool) -> None:
    """Validate the real trace and emit its proposed mapping certificate."""

    events = read_events(raw_path)
    validate_events(events)
    certificate = build_certificate(events)
    validate_certificate_invariants(events, certificate)
    write_certificate(certificate_path, certificate)
    if not quiet:
        print(
            f"generated certificate={certificate_path} "
            f"events={certificate['counts']['events']} "
            f"reductions={certificate['counts']['reductions']} "
            f"actions={certificate['counts']['actions']}"
        )


def validate_saved_certificate(raw_path: Path, certificate_path: Path) -> None:
    """Rebuild expectations and validate a saved certificate exactly."""

    events = read_events(raw_path)
    validate_events(events)
    try:
        loaded = json.loads(certificate_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ReductionError(f"certificate JSON is invalid: {error}") from error
    require(isinstance(loaded, dict), "certificate top level is not an object")
    validate_certificate_invariants(events, loaded)
    expected = build_certificate(events)
    require(
        loaded == expected,
        "certificate differs from the deterministic reduction of its input",
    )
    counts = loaded["counts"]
    capacities = loaded["capacities"]
    print(
        f"mapping events={counts['events']} consumed={counts['consumed_events']} "
        f"reductions={counts['reductions']} actions={counts['actions']} "
        f"observations={counts['observations']} "
        f"spans={counts['action_span_observations']} "
        f"checkpoints={counts['action_checkpoint_observations']}"
    )
    print(
        "capacities "
        f"nodes={capacities['node_world_capacity']} "
        f"max_log_index={capacities['max_absolute_log_index']} "
        f"fresh_tx_ids={capacities['fresh_transaction_id_capacity']} "
        f"max_lane={capacities['max_per_source_destination_lane']} "
        f"actions={capacities['action_capacity']} "
        f"distinct_configurations={capacities['distinct_configuration_value_count']} "
        "configuration_records="
        f"{capacities['physical_configuration_record_capacity']} "
        "max_active_configuration_history="
        f"{capacities['max_active_configuration_history_length']}"
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse reducer and certificate-validation commands."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    reduce_parser = subparsers.add_parser(
        "reduce",
        help="validate NDJSON and write the proposed mapping certificate",
    )
    reduce_parser.add_argument("--raw", required=True, type=Path)
    reduce_parser.add_argument("--certificate", required=True, type=Path)
    reduce_parser.add_argument("--quiet", action="store_true")

    validate_parser = subparsers.add_parser(
        "validate",
        help="validate a saved certificate against its exact NDJSON input",
    )
    validate_parser.add_argument("--raw", required=True, type=Path)
    validate_parser.add_argument("--certificate", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested reduction operation."""

    args = parse_args(argv)
    try:
        if args.command == "reduce":
            reduce_trace(args.raw, args.certificate, args.quiet)
        else:
            validate_saved_certificate(args.raw, args.certificate)
    except (OSError, ReductionError) as error:
        print(f"full-trace prototype failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
