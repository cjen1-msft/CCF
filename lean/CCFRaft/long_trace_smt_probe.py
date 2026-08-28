#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate and validate the throwaway long real-trace SMT probe."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class Event:
    number: int
    raw: str
    row: dict[str, Any]

    @property
    def message(self) -> dict[str, Any]:
        return self.row["msg"]

    @property
    def state(self) -> dict[str, Any]:
        return self.message["state"]

    @property
    def function(self) -> str:
        return self.message["function"]


@dataclass(frozen=True)
class Action:
    line: str
    events: tuple[int, ...]
    reduction: str
    effect: dict[str, str]


FIELDS = (
    "n0_term",
    "n0_last",
    "n0_commit",
    "n1_term",
    "n1_last",
    "n1_commit",
    "sent01",
    "match01",
    "request_queue",
    "response_queue",
)

EXPECTED_FUNCTIONS = {
    1: "bootstrap",
    2: "add_configuration",
    3: "send_append_entries",
    4: "replicate",
    5: "recv_append_entries",
    6: "become_follower",
    7: "send_append_entries_response",
    8: "recv_append_entries_response",
    9: "send_append_entries",
    10: "send_append_entries",
    11: "recv_append_entries",
    12: "add_configuration",
    13: "execute_append_entries_sync",
    14: "commit",
    15: "add_configuration",
    16: "send_append_entries_response",
    17: "recv_append_entries",
    18: "execute_append_entries_sync",
    19: "send_append_entries_response",
    20: "recv_append_entries_response",
    21: "recv_append_entries_response",
    22: "commit",
    23: "replicate",
    24: "replicate",
    25: "send_append_entries",
    26: "recv_append_entries",
    27: "execute_append_entries_sync",
    28: "execute_append_entries_sync",
    29: "commit",
    30: "send_append_entries_response",
    31: "recv_append_entries_response",
    32: "commit",
    33: "send_append_entries",
    34: "recv_append_entries",
    35: "commit",
    36: "send_append_entries_response",
    37: "recv_append_entries_response",
    38: "send_append_entries",
    39: "recv_append_entries",
    40: "send_append_entries_response",
    41: "recv_append_entries_response",
    42: "replicate",
    43: "send_append_entries",
    44: "recv_append_entries",
    45: "execute_append_entries_sync",
    46: "send_append_entries_response",
    47: "recv_append_entries_response",
    48: "commit",
    49: "send_append_entries",
    50: "recv_append_entries",
    51: "commit",
    52: "send_append_entries_response",
    53: "recv_append_entries_response",
}

EXPECTED_STATES = {
    20: (0, "Leader", 2, 4, 2),
    21: (0, "Leader", 2, 4, 2),
    22: (0, "Leader", 2, 4, 2),
    23: (0, "Leader", 2, 4, 4),
    24: (0, "Leader", 2, 5, 4),
    25: (0, "Leader", 2, 6, 4),
    26: (1, "Follower", 2, 4, 2),
    27: (1, "Follower", 2, 4, 2),
    28: (1, "Follower", 2, 5, 2),
    29: (1, "Follower", 2, 6, 2),
    30: (1, "Follower", 2, 6, 4),
    31: (0, "Leader", 2, 6, 4),
    32: (0, "Leader", 2, 6, 4),
    33: (0, "Leader", 2, 6, 6),
    34: (1, "Follower", 2, 6, 4),
    35: (1, "Follower", 2, 6, 4),
    36: (1, "Follower", 2, 6, 6),
    37: (0, "Leader", 2, 6, 6),
    38: (0, "Leader", 2, 6, 6),
    39: (1, "Follower", 2, 6, 6),
    40: (1, "Follower", 2, 6, 6),
    41: (0, "Leader", 2, 6, 6),
    42: (0, "Leader", 2, 6, 6),
    43: (0, "Leader", 2, 7, 6),
    44: (1, "Follower", 2, 6, 6),
    45: (1, "Follower", 2, 6, 6),
    46: (1, "Follower", 2, 7, 6),
    47: (0, "Leader", 2, 7, 6),
    48: (0, "Leader", 2, 7, 6),
    49: (0, "Leader", 2, 7, 7),
    50: (1, "Follower", 2, 7, 6),
    51: (1, "Follower", 2, 7, 6),
    52: (1, "Follower", 2, 7, 7),
    53: (0, "Leader", 2, 7, 7),
}

EXPECTED_SENDS = {
    25: (4, 6, 4, 4, 4),
    33: (6, 6, 6, 6, 6),
    38: (6, 6, 6, 6, 6),
    43: (6, 7, 6, 6, 6),
    49: (7, 7, 7, 7, 7),
}

EXPECTED_REQUEST_RECEIVES = {
    26: (4, 6, 4),
    34: (6, 6, 6),
    39: (6, 6, 6),
    44: (6, 7, 6),
    50: (7, 7, 7),
}

EXPECTED_RESPONSES = {
    20: (3, 4, 0),
    21: (4, 4, 3),
    31: (6, 6, 4),
    37: (6, 6, 6),
    41: (6, 6, 6),
    47: (7, 7, 6),
    53: (7, 7, 7),
}

OBSERVATIONS = (
    (20, 0, "n0", ("term", "last", "commit", "sent", "match")),
    (21, 1, "n0", ("term", "last", "commit", "sent", "match")),
    (22, 2, "n0", ("term", "last", "commit")),
    (23, 3, "n0", ("term", "last", "commit")),
    (24, 4, "n0", ("term", "last", "commit")),
    (25, 5, "n0", ("term", "last", "commit", "sent", "match")),
    (26, 7, "n1", ("term", "last", "commit")),
    (27, 7, "n1", ("term", "last", "commit")),
    # C++ defers the group commit until event 29. The split Lean receive
    # commits after its first one-entry request, so event 28 constrains only
    # the fields that still correspond at the intermediate reduction point.
    (28, 8, "n1", ("term", "last")),
    (30, 9, "n1", ("term", "last", "commit")),
    (31, 9, "n0", ("term", "last", "commit", "sent", "match")),
    (32, 11, "n0", ("term", "last", "commit")),
    (33, 12, "n0", ("term", "last", "commit", "sent", "match")),
    (34, 13, "n1", ("term", "last", "commit")),
    (36, 14, "n1", ("term", "last", "commit")),
    (37, 14, "n0", ("term", "last", "commit", "sent", "match")),
    (38, 15, "n0", ("term", "last", "commit", "sent", "match")),
    (39, 16, "n1", ("term", "last", "commit")),
    (40, 17, "n1", ("term", "last", "commit")),
    (41, 17, "n0", ("term", "last", "commit", "sent", "match")),
    (42, 18, "n0", ("term", "last", "commit")),
    (43, 19, "n0", ("term", "last", "commit", "sent", "match")),
    (44, 20, "n1", ("term", "last", "commit")),
    (46, 21, "n1", ("term", "last", "commit")),
    (47, 21, "n0", ("term", "last", "commit", "sent", "match")),
    (48, 22, "n0", ("term", "last", "commit")),
    (49, 23, "n0", ("term", "last", "commit", "sent", "match")),
    (50, 24, "n1", ("term", "last", "commit")),
    (52, 25, "n1", ("term", "last", "commit")),
    (53, 25, "n0", ("term", "last", "commit", "sent", "match")),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def read_events(path: Path) -> list[Event]:
    raw_lines = path.read_text(encoding="utf-8").splitlines()
    events: list[Event] = []
    for number, raw in enumerate(raw_lines, 1):
        require(bool(raw.strip()), f"raw NDJSON event {number} is empty")
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ProbeError(f"raw NDJSON event {number}: {error}") from error
        require(isinstance(row, dict), f"raw NDJSON event {number} is not an object")
        require(
            row.get("tag") == "raft_trace", f"event {number}: tag is not raft_trace"
        )
        require(
            isinstance(row.get("msg"), dict), f"event {number}: msg is not an object"
        )
        require(
            isinstance(row["msg"].get("state"), dict),
            f"event {number}: msg.state is not an object",
        )
        events.append(Event(number, raw, row))
    return events


def configuration_nodes(event: Event) -> tuple[int, set[str]]:
    configuration = event.message.get("args", {}).get("configuration")
    require(
        isinstance(configuration, dict),
        f"event {event.number}: add_configuration has no args.configuration",
    )
    index = configuration.get("idx")
    nodes = configuration.get("nodes")
    require(
        isinstance(index, int), f"event {event.number}: configuration idx is absent"
    )
    require(
        isinstance(nodes, dict), f"event {event.number}: configuration nodes absent"
    )
    return index, set(nodes)


def detect_cut(events: list[Event]) -> tuple[int, int]:
    reconfigurations = [
        event
        for event in events
        if event.function == "add_configuration"
        and configuration_nodes(event) == (3, {"0", "1"})
    ]
    require(
        len(reconfigurations) == 2,
        "expected leader and follower observations of reconfiguration index 3 to {0,1}",
    )
    last_reconfiguration = max(event.number for event in reconfigurations)
    candidates: list[int] = []
    for first, second in zip(events, events[1:]):
        if first.number <= last_reconfiguration:
            continue
        if (
            first.function == "recv_append_entries_response"
            and second.function == "recv_append_entries_response"
            and first.state.get("node_id") == "0"
            and second.state.get("node_id") == "0"
            and first.state.get("leadership_state") == "Leader"
            and second.state.get("leadership_state") == "Leader"
            and first.message.get("from_node_id") == "1"
            and second.message.get("from_node_id") == "1"
        ):
            first_index = first.message.get("packet", {}).get("last_log_idx")
            second_index = second.message.get("packet", {}).get("last_log_idx")
            if first_index == 3 and second_index == 4:
                candidates.append(first.number)
    require(
        candidates,
        "no consecutive leader response pair for indices 3 and 4 follows reconfiguration",
    )
    return candidates[0], last_reconfiguration


def check_packet(
    event: Event,
    *,
    previous: int,
    index: int,
    leader_commit: int,
    previous_term: int = 2,
) -> None:
    packet = event.message.get("packet")
    require(isinstance(packet, dict), f"event {event.number}: packet is absent")
    expected = {
        "msg": "raft_append_entries",
        "term": 2,
        "prev_term": previous_term,
        "term_of_idx": 2,
        "prev_idx": previous,
        "idx": index,
        "leader_commit_idx": leader_commit,
    }
    for field, value in expected.items():
        require(
            packet.get(field) == value,
            f"event {event.number}: packet.{field} is {packet.get(field)!r}, "
            f"expected {value!r}",
        )


def validate_real_trace(events: list[Event]) -> tuple[int, int]:
    require(len(events) == 53, f"real trace has {len(events)} events, expected 53")
    cut, reconfiguration = detect_cut(events)
    require(cut == 20, f"structural cut resolved to event {cut}, expected event 20")

    by_number = {event.number: event for event in events}
    for number, function in EXPECTED_FUNCTIONS.items():
        event = by_number[number]
        require(
            event.function == function,
            f"event {number}: function is {event.function}, expected {function}",
        )

    bootstrap = by_number[1]
    require(
        bootstrap.message.get("args") == {"idx": 2}
        and bootstrap.message.get("configurations", [{}])[0].get("idx") == 1
        and set(
            bootstrap.message.get("configurations", [{}])[0].get("nodes", {}).keys()
        )
        == {"0"},
        "event 1 does not establish the one-node scenario bootstrap at index 2",
    )
    require(
        (
            bootstrap.state["current_view"],
            bootstrap.state["last_idx"],
            bootstrap.state["commit_idx"],
            bootstrap.state.get("committable_indices"),
        )
        == (2, 2, 0, [2]),
        "event 1 has unexpected bootstrap state",
    )
    require(
        configuration_nodes(by_number[2]) == (3, {"0", "1"}),
        "event 2 does not append reconfiguration index 3 to nodes {0,1}",
    )
    require(
        (
            by_number[4].message.get("view"),
            by_number[4].message.get("seqno"),
            by_number[4].message.get("globally_committable"),
        )
        == (2, 4, True),
        "event 4 does not identify the retained signature at index 4",
    )
    check_packet(by_number[3], previous=2, index=2, leader_commit=2)
    check_packet(by_number[5], previous=2, index=2, leader_commit=2)
    require(
        by_number[7].message.get("packet")
        == {
            "last_log_idx": 0,
            "msg": "raft_append_entries_response",
            "success": "FAIL",
            "term": 2,
        }
        and by_number[8].message.get("packet") == by_number[7].message.get("packet"),
        "events 7 and 8 do not pair the initial NACK",
    )
    check_packet(
        by_number[9],
        previous=0,
        index=3,
        leader_commit=2,
        previous_term=0,
    )
    check_packet(
        by_number[11],
        previous=0,
        index=3,
        leader_commit=2,
        previous_term=0,
    )
    check_packet(by_number[10], previous=3, index=4, leader_commit=2)
    check_packet(by_number[17], previous=3, index=4, leader_commit=2)
    require(
        configuration_nodes(by_number[12]) == (1, {"0"})
        and configuration_nodes(by_number[15]) == (3, {"0", "1"}),
        "follower prefix does not reconstruct retained configurations 1 and 3",
    )
    for number, index in ((16, 3), (19, 4)):
        packet = by_number[number].message.get("packet")
        require(
            by_number[number].message.get("to_node_id") == "0"
            and packet
            == {
                "last_log_idx": index,
                "msg": "raft_append_entries_response",
                "success": "OK",
                "term": 2,
            },
            f"event {number} does not produce expected pending response {index}",
        )
    require(
        all(
            event.function != "recv_append_entries_response" for event in events[15:19]
        ),
        "a pending response is consumed before the selected cut",
    )

    for number, expected in EXPECTED_STATES.items():
        state = by_number[number].state
        actual = (
            int(state["node_id"]),
            state["leadership_state"],
            state["current_view"],
            state["last_idx"],
            state["commit_idx"],
        )
        require(
            actual == expected, f"event {number}: state {actual}, expected {expected}"
        )

    for number, (previous, index, commit, sent, matched) in EXPECTED_SENDS.items():
        event = by_number[number]
        require(
            event.message.get("to_node_id") == "1",
            f"event {number}: append destination is not node 1",
        )
        require(
            (event.message.get("sent_idx"), event.message.get("match_idx"))
            == (sent, matched),
            f"event {number}: unexpected sent/match indices",
        )
        check_packet(event, previous=previous, index=index, leader_commit=commit)

    for number, packet_shape in EXPECTED_REQUEST_RECEIVES.items():
        event = by_number[number]
        require(
            event.message.get("from_node_id") == "0",
            f"event {number}: append source is not node 0",
        )
        check_packet(
            event,
            previous=packet_shape[0],
            index=packet_shape[1],
            leader_commit=packet_shape[2],
        )

    for number, (last_index, sent, matched) in EXPECTED_RESPONSES.items():
        event = by_number[number]
        packet = event.message.get("packet", {})
        require(
            event.message.get("from_node_id") == "1",
            f"event {number}: response source is not node 1",
        )
        require(
            packet
            == {
                "last_log_idx": last_index,
                "msg": "raft_append_entries_response",
                "success": "OK",
                "term": 2,
            },
            f"event {number}: unexpected response packet {packet!r}",
        )
        require(
            (event.message.get("sent_idx"), event.message.get("match_idx"))
            == (sent, matched),
            f"event {number}: unexpected response sent/match indices",
        )

    for number, index in ((22, 4), (29, 4), (32, 6), (35, 6), (48, 7), (51, 7)):
        require(
            by_number[number].message.get("args") == {"idx": index},
            f"event {number}: commit target is not {index}",
        )

    for number, sequence, committable in ((23, 5, False), (24, 6, True), (42, 7, True)):
        message = by_number[number].message
        require(
            (
                message.get("view"),
                message.get("seqno"),
                message.get("globally_committable"),
            )
            == (2, sequence, committable),
            f"event {number}: unexpected replicate fields",
        )
    require(
        by_number[23].row.get("cmd") == "replicate,2,helloworld",
        "event 23 is not the requested noncommittable replicate command",
    )
    require(
        by_number[42].row.get("cmd") == "assert_state_sync",
        "event 42 is not the assert_state_sync signature",
    )

    for number in (27, 28, 45):
        require(
            by_number[number].message.get("from_node_id") == "0",
            f"event {number}: execute record source is not node 0",
        )

    for number, last_index, commit in (
        (30, 6, 4),
        (36, 6, 6),
        (40, 6, 6),
        (46, 7, 6),
        (52, 7, 7),
    ):
        event = by_number[number]
        require(
            event.message.get("to_node_id") == "0",
            f"event {number}: response destination is not node 0",
        )
        packet = event.message.get("packet", {})
        require(
            packet
            == {
                "last_log_idx": last_index,
                "msg": "raft_append_entries_response",
                "success": "OK",
                "term": 2,
            },
            f"event {number}: unexpected sent response packet",
        )
        require(
            event.state["commit_idx"] == commit,
            f"event {number}: unexpected follower commit index",
        )
    return cut, reconfiguration


def unchanged_except(**effects: str) -> dict[str, str]:
    return dict(effects)


def semantic_actions() -> list[Action]:
    return [
        Action(
            "receive,1,0",
            (20,),
            "receive initial response index 3",
            unchanged_except(
                match01="(ite (> initial_response_0_index match01) "
                "initial_response_0_index match01)",
                response_queue="(- response_queue 1)",
            ),
        ),
        Action(
            "receive,1,0",
            (21,),
            "receive initial response index 4",
            unchanged_except(
                match01="(ite (> initial_response_1_index match01) "
                "initial_response_1_index match01)",
                response_queue="(- response_queue 1)",
            ),
        ),
        Action(
            "commit,0",
            (22,),
            "advance leader commit to 4",
            unchanged_except(n0_commit="4"),
        ),
        Action(
            "client,0,{tx_id}",
            (23,),
            "append fresh client transaction",
            unchanged_except(n0_last="(+ n0_last 1)"),
        ),
        Action(
            "sign,0",
            (24,),
            "append committable signature",
            unchanged_except(n0_last="(+ n0_last 1)"),
        ),
        Action(
            "append,0,1,5",
            (25,),
            "split two-entry C++ send at entry 5",
            unchanged_except(sent01="5", request_queue="(+ request_queue 1)"),
        ),
        Action(
            "append,0,1,6",
            (25,),
            "split two-entry C++ send at entry 6",
            unchanged_except(sent01="6", request_queue="(+ request_queue 1)"),
        ),
        Action(
            "receive,0,1",
            (26, 27),
            "split C++ follower receive at entry 5",
            unchanged_except(
                n1_last="(+ n1_last 1)",
                n1_commit="4",
                request_queue="(- request_queue 1)",
                response_queue="(+ response_queue 1)",
            ),
        ),
        Action(
            "receive,0,1",
            (26, 28, 29, 30),
            "split C++ follower receive at entry 6",
            unchanged_except(
                n1_last="(+ n1_last 1)",
                n1_commit="4",
                request_queue="(- request_queue 1)",
                response_queue="(+ response_queue 1)",
            ),
        ),
        Action(
            "receive,1,0",
            (31,),
            "receive split response index 5",
            unchanged_except(
                match01="(ite (> 5 match01) 5 match01)",
                response_queue="(- response_queue 1)",
            ),
        ),
        Action(
            "receive,1,0",
            (31,),
            "receive split response index 6",
            unchanged_except(
                match01="(ite (> 6 match01) 6 match01)",
                response_queue="(- response_queue 1)",
            ),
        ),
        Action(
            "commit,0",
            (32,),
            "advance leader commit to 6",
            unchanged_except(n0_commit="6"),
        ),
        Action(
            "append,0,1,6",
            (33,),
            "send heartbeat at index 6",
            unchanged_except(sent01="6", request_queue="(+ request_queue 1)"),
        ),
        Action(
            "receive,0,1",
            (34, 35, 36),
            "receive heartbeat and follower commit 6",
            unchanged_except(
                n1_commit="6",
                request_queue="(- request_queue 1)",
                response_queue="(+ response_queue 1)",
            ),
        ),
        Action(
            "receive,1,0",
            (37,),
            "receive heartbeat response index 6",
            unchanged_except(
                match01="(ite (> 6 match01) 6 match01)",
                response_queue="(- response_queue 1)",
            ),
        ),
        Action(
            "append,0,1,6",
            (38,),
            "send second heartbeat at index 6",
            unchanged_except(sent01="6", request_queue="(+ request_queue 1)"),
        ),
        Action(
            "receive,0,1",
            (39, 40),
            "receive second heartbeat at index 6",
            unchanged_except(
                request_queue="(- request_queue 1)",
                response_queue="(+ response_queue 1)",
            ),
        ),
        Action(
            "receive,1,0",
            (41,),
            "receive second heartbeat response index 6",
            unchanged_except(
                match01="(ite (> 6 match01) 6 match01)",
                response_queue="(- response_queue 1)",
            ),
        ),
        Action(
            "sign,0",
            (42,),
            "append assert_state_sync signature",
            unchanged_except(n0_last="(+ n0_last 1)"),
        ),
        Action(
            "append,0,1,7",
            (43,),
            "send signature entry 7",
            unchanged_except(sent01="7", request_queue="(+ request_queue 1)"),
        ),
        Action(
            "receive,0,1",
            (44, 45, 46),
            "receive signature entry 7",
            unchanged_except(
                n1_last="(+ n1_last 1)",
                request_queue="(- request_queue 1)",
                response_queue="(+ response_queue 1)",
            ),
        ),
        Action(
            "receive,1,0",
            (47,),
            "receive response index 7",
            unchanged_except(
                match01="(ite (> 7 match01) 7 match01)",
                response_queue="(- response_queue 1)",
            ),
        ),
        Action(
            "commit,0",
            (48,),
            "advance leader commit to 7",
            unchanged_except(n0_commit="7"),
        ),
        Action(
            "append,0,1,7",
            (49,),
            "send heartbeat carrying leader commit 7",
            unchanged_except(sent01="7", request_queue="(+ request_queue 1)"),
        ),
        Action(
            "receive,0,1",
            (50, 51, 52),
            "receive heartbeat and follower commit 7",
            unchanged_except(
                n1_commit="7",
                request_queue="(- request_queue 1)",
                response_queue="(+ response_queue 1)",
            ),
        ),
        Action(
            "receive,1,0",
            (53,),
            "receive final response index 7",
            unchanged_except(
                match01="(ite (> 7 match01) 7 match01)",
                response_queue="(- response_queue 1)",
            ),
        ),
    ]


def state_variable(field: str, step: int) -> str:
    return f"{field}_s{step:02d}"


def substitute_effect(expression: str, step: int) -> str:
    for field in sorted(FIELDS, key=len, reverse=True):
        expression = re.sub(
            rf"\b{re.escape(field)}\b",
            state_variable(field, step),
            expression,
        )
    return expression


def observation_assertion(
    event: Event, step: int, node: str, fields: tuple[str, ...]
) -> str:
    prefix = "n0" if node == "n0" else "n1"
    state = event.state
    values = {
        "term": state["current_view"],
        "last": state["last_idx"],
        "commit": state["commit_idx"],
        "sent": event.message.get("sent_idx"),
        "match": event.message.get("match_idx"),
    }
    equalities = []
    for field in fields:
        require(
            values[field] is not None,
            f"event {event.number}: observation field {field} is absent",
        )
        scalar = (
            f"{prefix}_{field}" if field in {"term", "last", "commit"} else f"{field}01"
        )
        equalities.append(f"(= {state_variable(scalar, step)} {values[field]})")
    return "(and " + " ".join(equalities) + ")"


def build_smt(events: list[Event], actions: list[Action]) -> tuple[str, dict[str, str]]:
    by_number = {event.number: event for event in events}
    labels: dict[str, str] = {}
    declarations: list[str] = []
    assertions: list[str] = []
    assumptions: list[str] = []

    def labelled(label: str, description: str, expression: str) -> None:
        require(label not in labels, f"duplicate SMT label {label}")
        labels[label] = description
        assumptions.append(label)
        declarations.append(f"(declare-const {label} Bool)")
        assertions.append(f"(assert (=> {label} {expression}))")

    for step in range(len(actions) + 1):
        for field in FIELDS:
            declarations.append(f"(declare-const {state_variable(field, step)} Int)")
        declarations.append(f"(declare-const tx_member_s{step:02d} Bool)")
    declarations.extend(
        [
            "(declare-const initial_response_0_term Int)",
            "(declare-const initial_response_0_success Bool)",
            "(declare-const initial_response_0_index Int)",
            "(declare-const initial_response_0_source Int)",
            "(declare-const initial_response_0_destination Int)",
            "(declare-const initial_response_1_term Int)",
            "(declare-const initial_response_1_success Bool)",
            "(declare-const initial_response_1_index Int)",
            "(declare-const initial_response_1_source Int)",
            "(declare-const initial_response_1_destination Int)",
            "(declare-const tx_id Int)",
        ]
    )

    bounds = []
    for step in range(len(actions) + 1):
        for field in FIELDS:
            bounds.append(f"(>= {state_variable(field, step)} 0)")
        bounds.extend(
            [
                f"(<= {state_variable('n0_commit', step)} "
                f"{state_variable('n0_last', step)})",
                f"(<= {state_variable('n1_commit', step)} "
                f"{state_variable('n1_last', step)})",
                f"(<= {state_variable('sent01', step)} "
                f"{state_variable('n0_last', step)})",
                f"(<= {state_variable('match01', step)} "
                f"{state_variable('n0_last', step)})",
            ]
        )
    labelled(
        "scalar_domain_bounds",
        "nonnegative scalar state and local index bounds at every reduction step",
        "(and " + " ".join(bounds) + ")",
    )
    labelled(
        "event23_fresh_transaction",
        "event 23 uses one transaction identifier in the bounded Fin 64 domain",
        "(and " "(>= tx_id 0) (< tx_id 64))",
    )

    for response, event_number in ((0, 20), (1, 21)):
        packet = by_number[event_number].message["packet"]
        labelled(
            f"event{event_number}_initial_response_payload",
            f"event {event_number} identifies pre-existing response {response}",
            "(and "
            f"(= initial_response_{response}_term {packet['term']}) "
            f"initial_response_{response}_success "
            f"(= initial_response_{response}_index {packet['last_log_idx']}) "
            f"(= initial_response_{response}_source 1) "
            f"(= initial_response_{response}_destination 0))",
        )

    for event_number, step, node, fields in OBSERVATIONS:
        labelled(
            f"event{event_number}_observed_{node}_state",
            f"event {event_number} observed pre-action {node} scalar state",
            observation_assertion(by_number[event_number], step, node, fields),
        )

    for step, action in enumerate(actions):
        equalities = []
        for field in FIELDS:
            expression = action.effect.get(field, field)
            equalities.append(
                f"(= {state_variable(field, step + 1)} "
                f"{substitute_effect(expression, step)})"
            )
        if action.events == (23,):
            equalities.extend(
                [
                    f"(not tx_member_s{step:02d})",
                    f"tx_member_s{step + 1:02d}",
                ]
            )
        else:
            equalities.append(f"(= tx_member_s{step + 1:02d} tx_member_s{step:02d})")
        event_code = "_".join(str(number) for number in action.events)
        label = f"reduce_event{event_code}_step{step + 1:02d}"
        labelled(
            label,
            f"events {event_code} reduce to {action.line}: {action.reduction}",
            "(and " + " ".join(equalities) + ")",
        )

    labelled(
        "segment_final_queues_drained",
        "the reduced segment drains the node 0 response and node 1 request queues",
        f"(and (= {state_variable('request_queue', len(actions))} 0) "
        f"(= {state_variable('response_queue', len(actions))} 0))",
    )

    contradiction = "contradictory_event54_final_node0_commit_8"
    labels[contradiction] = (
        "synthetic event 54 contradicts the event-53-derived final node 0 commit"
    )
    declarations.append(f"(declare-const {contradiction} Bool)")
    assertions.append(
        f"(assert (=> {contradiction} "
        f"(= {state_variable('n0_commit', len(actions))} 8)))"
    )

    values = (
        [state_variable(field, 0) for field in FIELDS]
        + [
            "initial_response_0_term",
            "initial_response_0_success",
            "initial_response_0_index",
            "initial_response_0_source",
            "initial_response_0_destination",
            "initial_response_1_term",
            "initial_response_1_success",
            "initial_response_1_index",
            "initial_response_1_source",
            "initial_response_1_destination",
            "tx_id",
            "tx_member_s00",
            f"tx_member_s{len(actions):02d}",
        ]
        + [state_variable(field, len(actions)) for field in FIELDS]
    )

    smt = "\n".join(
        [
            "; Copyright (c) Microsoft Corporation. All rights reserved.",
            "; Licensed under the Apache 2.0 License.",
            ";",
            "; Generated from the real tests/raft_scenarios/replicate trace.",
            "; This is a scalar alignment abstraction, not a full CCFRaft SMT encoding.",
            "; The four-entry retained log prefix is supplied to Lean, not discovered here.",
            "",
            "(set-logic QF_LIA)",
            "(set-option :incremental true)",
            "(set-option :produce-models true)",
            "(set-option :produce-unsat-assumptions true)",
            "",
            *declarations,
            "",
            *assertions,
            "",
            "(check-sat-assuming",
            "  (" + "\n   ".join(assumptions) + "))",
            "(get-value",
            "  (" + "\n   ".join(values) + "))",
            "",
            f"(check-sat-assuming\n  ({' '.join(assumptions)} {contradiction}))",
            "(get-unsat-assumptions)",
            "",
        ]
    )
    return smt, labels


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def generate(raw_path: Path, output_dir: Path) -> None:
    events = read_events(raw_path)
    cut, reconfiguration = validate_real_trace(events)
    actions = semantic_actions()
    require(len(actions) == 26, "internal semantic action count changed")
    require(len(events) - cut + 1 == 34, "internal suffix event count changed")

    output_dir.mkdir(parents=True, exist_ok=True)
    raw_text = "\n".join(event.raw for event in events) + "\n"
    suffix_text = "\n".join(event.raw for event in events[cut - 1 :]) + "\n"
    (output_dir / "raw.ndjson").write_text(raw_text, encoding="utf-8")
    (output_dir / "suffix.ndjson").write_text(suffix_text, encoding="utf-8")
    observation_lines = []
    by_number = {event.number: event for event in events}
    for event_number, step, node_name, fields in OBSERVATIONS:
        event = by_number[event_number]
        node = int(event.state["node_id"])
        values = {
            "term": event.state["current_view"],
            "last": event.state["last_idx"],
            "commit": event.state["commit_idx"],
            "sent": event.message.get("sent_idx"),
            "match": event.message.get("match_idx"),
        }
        columns = [
            str(event_number),
            str(step),
            str(node),
            event.state["leadership_state"],
        ]
        for field in ("term", "last", "commit", "sent", "match"):
            columns.append(str(values[field]) if field in fields else "-")
        observation_lines.append(",".join(columns))
    (output_dir / "observations.csv").write_text(
        "\n".join(observation_lines) + "\n", encoding="utf-8"
    )

    smt, labels = build_smt(events, actions)
    (output_dir / "probe.smt2").write_text(smt, encoding="utf-8")
    metadata = {
        "scenario": "tests/raft_scenarios/replicate",
        "real_event_count": len(events),
        "cut_event": cut,
        "last_reconfiguration_event": reconfiguration,
        "suffix_event_count": len(events) - cut + 1,
        "semantic_action_count": len(actions),
        "actions": [
            {
                "template": action.line,
                "events": list(action.events),
                "reduction": action.reduction,
            }
            for action in actions
        ],
        "labels": labels,
    }
    write_json(output_dir / "metadata.json", metadata)
    print(
        f"generated events={len(events)} suffix={len(events) - cut + 1} "
        f"actions={len(actions)} cut={cut}"
    )


def tokenize_sexpressions(text: str) -> list[str]:
    return re.findall(r"\(|\)|[^()\s]+", text)


def parse_sexpressions(text: str) -> list[Any]:
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
    raise ProbeError(f"unsupported solver value {value!r}")


def parse_solver_output(path: Path) -> tuple[dict[str, int | bool], list[str]]:
    expressions = parse_sexpressions(path.read_text(encoding="utf-8"))
    require(
        len(expressions) == 4, f"solver returned {len(expressions)} forms, expected 4"
    )
    require(expressions[0] == "sat", "first SMT query is not SAT")
    require(expressions[2] == "unsat", "contradictory SMT query is not UNSAT")
    raw_values = expressions[1]
    require(isinstance(raw_values, list), "get-value result is not a list")
    values: dict[str, int | bool] = {}
    for pair in raw_values:
        require(
            isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], str),
            f"malformed get-value pair {pair!r}",
        )
        values[pair[0]] = atom_value(pair[1])
    raw_core = expressions[3]
    require(
        isinstance(raw_core, list)
        and all(isinstance(label, str) for label in raw_core),
        "get-unsat-assumptions result is malformed",
    )
    return values, raw_core


def expected_model_values() -> dict[str, int | bool]:
    expected = {
        "n0_term_s00": 2,
        "n0_last_s00": 4,
        "n0_commit_s00": 2,
        "n1_term_s00": 2,
        "n1_last_s00": 4,
        "n1_commit_s00": 2,
        "sent01_s00": 4,
        "match01_s00": 0,
        "request_queue_s00": 0,
        "response_queue_s00": 2,
        "initial_response_0_term": 2,
        "initial_response_0_success": True,
        "initial_response_0_index": 3,
        "initial_response_0_source": 1,
        "initial_response_0_destination": 0,
        "initial_response_1_term": 2,
        "initial_response_1_success": True,
        "initial_response_1_index": 4,
        "initial_response_1_source": 1,
        "initial_response_1_destination": 0,
        "tx_member_s00": False,
        "tx_member_s26": True,
        "n0_term_s26": 2,
        "n0_last_s26": 7,
        "n0_commit_s26": 7,
        "n1_term_s26": 2,
        "n1_last_s26": 7,
        "n1_commit_s26": 7,
        "sent01_s26": 7,
        "match01_s26": 7,
        "request_queue_s26": 0,
        "response_queue_s26": 0,
    }
    return expected


def validate_solver(output_dir: Path) -> None:
    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    values, core = parse_solver_output(output_dir / "solver.out")
    for key, expected in expected_model_values().items():
        require(key in values, f"solver model omitted {key}")
        require(
            values[key] == expected,
            f"solver model has {key}={values[key]!r}, expected {expected!r}",
        )
    tx_id = values.get("tx_id")
    require(isinstance(tx_id, int), "solver model omitted integer tx_id")
    require(0 <= tx_id < 64, f"solver chose out-of-range tx_id {tx_id}")

    contradiction = "contradictory_event54_final_node0_commit_8"
    require(
        contradiction in core, "UNSAT assumptions omit the contradictory final event"
    )
    require(
        any(re.fullmatch(r"event[0-9]+_observed_.*", label) for label in core),
        "UNSAT assumptions contain no real event observation label",
    )
    require(
        any(re.fullmatch(r"reduce_event[0-9_]+_step[0-9]+", label) for label in core),
        "UNSAT assumptions contain no semantic reduction label",
    )
    known_labels = metadata["labels"]
    require(
        all(label in known_labels for label in core),
        "UNSAT assumptions contain a label absent from metadata",
    )

    actions = semantic_actions()
    trace_lines = [action.line.format(tx_id=tx_id) for action in actions]
    (output_dir / "semantic.trace").write_text(
        "\n".join(trace_lines) + "\n", encoding="utf-8"
    )

    result = {
        "status": "sat",
        "values": values,
        "unsat_status": "unsat",
        "unsat_assumptions": core,
        "unsat_assumption_descriptions": {label: known_labels[label] for label in core},
    }
    write_json(output_dir / "solver-result.json", result)
    model_lines = [
        f"{key}={str(value).lower() if isinstance(value, bool) else value}"
        for key, value in sorted(values.items())
    ]
    (output_dir / "model.values").write_text(
        "\n".join(model_lines) + "\n", encoding="utf-8"
    )
    print(f"solver sat tx_id={tx_id} unsat_labels={len(core)}")


def parse_summary(summary: str) -> dict[str, str]:
    result = {}
    for token in summary.strip().split():
        if "=" in token:
            key, value = token.split("=", 1)
            result[key] = value
    return result


def write_report(
    output_dir: Path,
    scenario_ms: int,
    solver_ms: int,
    lean_ms: int,
    lean_summary: str,
) -> None:
    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    solver = json.loads((output_dir / "solver-result.json").read_text(encoding="utf-8"))
    summary = parse_summary(lean_summary)
    require(
        summary.get("canonical_replay") == "passed",
        "Lean replay did not report success",
    )
    require(
        int(summary.get("actions", "-1")) == metadata["semantic_action_count"],
        "Lean replay action count differs from generated trace",
    )
    values = solver["values"]
    report = {
        "result": "passed",
        "scenario": metadata["scenario"],
        "real_event_count": metadata["real_event_count"],
        "cut": {
            "event": metadata["cut_event"],
            "last_reconfiguration_event": metadata["last_reconfiguration_event"],
            "method": (
                "first consecutive leader recv_append_entries_response pair for "
                "indices 3 and 4 after reconfiguration index 3 to nodes {0,1}"
            ),
        },
        "prefix_validation": {
            "bootstrap_entries": [
                "index 1 reconfiguration {0}",
                "index 2 signature",
            ],
            "observed_reconfiguration": "index 3 reconfiguration {0,1}",
            "observed_signature": "index 4 signature",
            "pending_response_producers": [16, 19],
            "pending_response_consumers": [20, 21],
        },
        "suffix_event_count": metadata["suffix_event_count"],
        "semantic_action_count": metadata["semantic_action_count"],
        "smt": {
            "scope": (
                "scalar abstraction of node 0 and node 1 terms, last and commit "
                "indices, sent01, match01, request and response queue counts, "
                "initial response payloads, and the fresh transaction ID"
            ),
            "sat_values": values,
            "synthetic_unsat_negative_control": solver["unsat_assumptions"],
            "synthetic_unsat_descriptions": solver["unsat_assumption_descriptions"],
            "direct_solver_ms": solver_ms,
        },
        "lean": {
            "canonical_apply_action": True,
            "state_checks": int(summary["state_checks"]),
            "edge_checks": int(summary["edge_checks"]),
            "observation_checks": int(summary["observation_checks"]),
            "final": {
                "node0_last": int(summary["node0_last"]),
                "node0_commit": int(summary["node0_commit"]),
                "node1_last": int(summary["node1_last"]),
                "node1_commit": int(summary["node1_commit"]),
                "request_queue": int(summary["request_queue"]),
                "response_queue": int(summary["response_queue"]),
            },
        },
        "timings_ms": {
            "real_scenario_and_preprocessing": scenario_ms,
            "direct_solver": solver_ms,
            "lean_compile_and_replay": lean_ms,
        },
        "retained_prefix": {
            "source": "manually supplied, not discovered by SMT",
            "entries": [
                "term 2 reconfiguration {0}",
                "term 2 signature",
                "term 2 reconfiguration {0,1}",
                "term 2 signature",
            ],
        },
        "limitations": [
            "The SMT model is a scalar trace-alignment abstraction, not a full CCFRaft encoding.",
            "The four-entry retained log prefix is supplied manually from the earlier real events.",
            (
                "The checkpoint is a manual completion: unobserved model fields and "
                "nodes inherit values from Lean initialState."
            ),
            (
                "Python owns the fixture-specific event grouping and action expansion; "
                "Lean independently rechecks the selected scalar observations and "
                "canonical witness, but does not parse the raw NDJSON grammar."
            ),
            "The C++ two-entry batch is reduced to two canonical one-entry Lean sends and receives.",
            (
                "C++ defers the batched follower commit until both entries execute; "
                "the first split Lean receive advances commit 4 earlier."
            ),
            (
                "Splitting the C++ batch synthesizes a response for index 5 and a "
                "leader match-index transition through 5 that C++ does not emit."
            ),
            "This segment checkpoint is checked directly; no reachability claim from Lean initialState is made.",
        ],
    }
    write_json(output_dir / "report.json", report)

    tx_id = values["tx_id"]
    core_lines = "\n".join(
        f"- `{label}`: {solver['unsat_assumption_descriptions'][label]}"
        for label in solver["unsat_assumptions"]
    )
    markdown = f"""# Long real-trace SMT probe

Result: `passed`

- Real trace: {metadata['real_event_count']} events.
- Structural cut: original event {metadata['cut_event']}, after reconfiguration event {metadata['last_reconfiguration_event']}.
- Retained suffix: {metadata['suffix_event_count']} events.
- Canonical semantic trace: {metadata['semantic_action_count']} actions.
- SMT result: `sat`; transaction representative `{tx_id}`; direct solver time {solver_ms} ms.
- Canonical Lean witness replay: `passed`; both nodes end at last index 7 and commit index 7; both relevant queues are empty.

## SAT checkpoint values

Node 0 starts at term 2, last index 4, and commit index 2. Its sent01 index is 4 and its match01 index is 0.
Node 1 starts at term 2, last index 4, and commit index 2.
The initial request queue is empty. The response queue contains ordered indices 3 and 4.
The solver chose transaction representative `{tx_id}` in `[0,64)`. The mapped
client transition constrains that representative to be absent before the action
and present afterward. Any fresh identifier is symmetric in this probe.

## Synthetic UNSAT negative control

{core_lines}

## Scope

The SMT file is a scalar trace-alignment abstraction, not a full CCFRaft SMT encoding.
The retained four-entry prefix is manually supplied: term 2 reconfiguration `{{0}}`,
term 2 signature, term 2 reconfiguration `{{0,1}}`, term 2 signature.
The real prefix is checked for those four entries and for response producers 16
and 19, which become the two pending messages consumed at events 20 and 21.
Other unobserved model fields use a manual completion inherited from Lean
`initialState`.
For the two-entry batch, C++ defers follower commit 4 until both entries execute;
the first split Lean receive advances it after entry 5.
The split also synthesizes an index-5 response and leader match transition that
C++ does not emit. Python owns this fixture-specific reduction. Lean rechecks
the selected scalar observations and replays the witness with canonical
`system.applyAction`, `stateChecks`, and `edgeChecks`; it does not parse the raw
event grammar or claim that the checkpoint is reachable from Lean `initialState`.
"""
    (output_dir / "report.md").write_text(markdown, encoding="utf-8")
    print(
        f"report events={metadata['real_event_count']} "
        f"actions={metadata['semantic_action_count']} result=passed"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate")
    generate_parser.add_argument("--raw", type=Path, required=True)
    generate_parser.add_argument("--output-dir", type=Path, required=True)

    validate_parser = subparsers.add_parser("validate-solver")
    validate_parser.add_argument("--output-dir", type=Path, required=True)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--output-dir", type=Path, required=True)
    report_parser.add_argument("--scenario-ms", type=int, required=True)
    report_parser.add_argument("--solver-ms", type=int, required=True)
    report_parser.add_argument("--lean-ms", type=int, required=True)
    report_parser.add_argument("--lean-summary", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        if args.command == "generate":
            generate(args.raw, args.output_dir)
        elif args.command == "validate-solver":
            validate_solver(args.output_dir)
        elif args.command == "report":
            write_report(
                args.output_dir,
                args.scenario_ms,
                args.solver_ms,
                args.lean_ms,
                args.lean_summary,
            )
        else:
            raise ProbeError(f"unknown command {args.command}")
        return 0
    except (ProbeError, KeyError, TypeError, ValueError) as error:
        print(f"long-trace-smt-probe: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
