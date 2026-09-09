# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Replication uses evaluated packet equality, including transaction aliases."""

from __future__ import annotations

import copy
import json
import unittest

from tests.test_client_request_encoding import (
    ROOT,
    SOLVER_TESTS,
    ClientRequestSliceTestCase,
    _observation,
    _request,
    _submitted,
)
from tests.test_leader_writes import action, trace
from tests.test_template_client_requests import entry_state, local_state


def send(node: int = 0, destination: int = 1, batch_end: int = 1) -> dict[str, object]:
    return action(
        "appendEntries", node=node, destination=destination, batchEnd=batch_end
    )


def queued_entry() -> dict[str, object]:
    entry = entry_state()
    peer = local_state()
    peer.update(role="follower", log=[])
    entry["nodes"][0] = peer
    entry["hasJoined"] = [0, 1]
    payload = copy.deepcopy(entry["nodes"][1]["log"])
    payload[0]["content"]["transaction"] = {"unknown": "queued"}
    entry["network"][0] = [
        {
            "kind": "appendEntriesRequest",
            "term": 7,
            "source": 1,
            "destination": 0,
            "prevLogIndex": 0,
            "prevLogTerm": 0,
            "entries": payload,
            "leaderCommit": 0,
        }
    ]
    return entry


class ReplicationFixtureTests(unittest.TestCase):
    def test_persistent_example_matches_builder(self) -> None:
        example = json.loads(
            (ROOT / "Traces/Replication/send.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            example,
            trace(
                [
                    _request({"unknown": "tx"}),
                    send(),
                    _observation("queueLength", 1, node=1),
                ],
                unknowns=["tx"],
                transaction_count=1,
                term_count=2,
                index_count=2,
                log_capacity=1,
                queue_capacity=1,
            ),
        )


@SOLVER_TESTS
class ReplicationEncodingTests(ClientRequestSliceTestCase):
    def test_client_request_can_be_sent(self) -> None:
        status, output = self.run_runner(
            trace(
                [_request(0), send(), _observation("queueLength", 1, node=1)],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "sat")
        self.assertIn(
            "appendEntries", self.result(output)["assurance"]["supported_actions"]
        )

    def test_queue_observation_retains_the_send_action(self) -> None:
        status, output = self.run_runner(
            trace(
                [_request(0), send(), _observation("queueLength", 0, node=1)],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertEqual(
            self._core_names(output / "unsat-core.txt"), {"group_2", "group_3"}
        )

    def test_queue_capacity_retains_the_send_action(self) -> None:
        status, output = self.run_runner(trace([_request(0), send()], queue_capacity=0))
        self.assertEqual(status, "unsat")
        self.assertEqual(
            self._core_names(output / "unsat-core.txt"), {"group_2", "group_3"}
        )

    def test_send_can_be_inspected_at_clause_granularity(self) -> None:
        status, output = self.run_runner(
            trace([_request(0), send()], queue_capacity=0), inspect_group=2
        )
        self.assertEqual(status, "unsat")
        core = self._core_names(output / "unsat-core.txt")
        self.assertIn("group_3", core)
        self.assertTrue(any(name.startswith("group_2_clause_") for name in core))
        diagnosis = json.loads((output / "diagnosis.json").read_text(encoding="utf-8"))
        self.assertTrue(
            any("queue" in item.get("label", "") for item in diagnosis["items"])
        )

    def test_wrong_batch_end_is_disabled(self) -> None:
        status, _ = self.run_runner(
            trace([_request(0), send(batch_end=0)], queue_capacity=1)
        )
        self.assertEqual(status, "unsat")

    def test_follower_cannot_send(self) -> None:
        status, _ = self.run_runner(
            trace([send(node=1, destination=0, batch_end=0)], queue_capacity=1)
        )
        self.assertEqual(status, "unsat")

    def test_repeated_heartbeat_is_not_enqueued_twice(self) -> None:
        status, _ = self.run_runner(
            trace(
                [
                    _request(0),
                    send(),
                    send(),
                    send(),
                    _observation("queueLength", 2, node=1),
                ],
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "sat")

    def test_different_unknowns_can_name_the_same_queued_transaction(self) -> None:
        status, _ = self.run_runner(
            trace(
                [send(node=1, destination=0), _observation("queueLength", 1, node=0)],
                entry=queued_entry(),
                unknowns=["old", "queued"],
                transaction_count=1,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "sat")

    def test_a_distinct_transaction_produces_a_second_packet(self) -> None:
        status, _ = self.run_runner(
            trace(
                [
                    _submitted({"unknown": "queued"}, False),
                    send(node=1, destination=0),
                    _observation("queueLength", 2, node=0),
                ],
                entry=queued_entry(),
                unknowns=["old", "queued"],
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "sat")

    def test_distinct_packet_cannot_fit_a_full_queue(self) -> None:
        status, _ = self.run_runner(
            trace(
                [_submitted({"unknown": "queued"}, False), send(node=1, destination=0)],
                entry=queued_entry(),
                unknowns=["old", "queued"],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")

    def test_later_writes_keep_branch_bindings_separate(self) -> None:
        status, _ = self.run_runner(
            trace(
                [
                    send(node=1, destination=0),
                    _request({"unknown": "new"}, node=1),
                    send(node=1, destination=0, batch_end=2),
                    action("signCommittableMessages", node=1),
                    action("changeConfiguration", node=1, configuration=[0, 1, 7]),
                    _observation("logLength", 4, node=1),
                    _observation("allocated", True, node=7),
                ],
                entry=queued_entry(),
                unknowns=["old", "queued", "new"],
                transaction_count=3,
                index_count=6,
                queue_capacity=4,
            )
        )
        self.assertEqual(status, "sat")


if __name__ == "__main__":
    unittest.main()
