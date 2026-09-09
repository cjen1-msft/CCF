# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Arbitrary-entry client requests, with concrete structure and symbolic IDs."""

from __future__ import annotations

import json
import unittest

from tests.test_client_request_encoding import (
    ROOT,
    SOLVER_TESTS,
    CertificateRejected,
    ClientRequestSliceTestCase,
    _observation,
    _request,
    _submitted,
)

NODE_COUNT = 15


def local_state() -> dict[str, object]:
    return {
        "role": "leader",
        "currentTerm": 7,
        "log": [
            {
                "term": 6,
                "content": {"kind": "transaction", "transaction": {"unknown": "old"}},
            }
        ],
        "commitIndex": 0,
        "sentIndex": [0] * NODE_COUNT,
        "matchIndex": [0] * NODE_COUNT,
        "isNewFollower": False,
        "votedFor": 1,
        "votesGranted": [1],
        "preVotesGranted": [],
        "membershipState": "active",
        "retirementIndex": None,
        "retirementCommittableIndex": None,
        "retiredCommittedIndex": None,
    }


def entry_state(local: dict[str, object] | None = None) -> dict[str, object]:
    nodes: list[dict[str, object] | None] = [None] * NODE_COUNT
    nodes[1] = local_state() if local is None else local
    return {
        "nodes": nodes,
        "network": [[] for _ in range(NODE_COUNT)],
        "submittedTxIds": [{"unknown": "old"}],
        "hasJoined": [1],
        "preVoteStatus": ["capable"] * NODE_COUNT,
        "retirementCompleted": [[] for _ in range(NODE_COUNT)],
    }


def certificate(
    steps: list[dict[str, object]],
    *,
    entry: dict[str, object] | None = None,
    transaction_count: int = 2,
    log_capacity: int = 2,
    index_count: int = 3,
) -> dict[str, object]:
    return {
        "schema_version": "ccfraft-client-request/v2",
        "entry": entry_state() if entry is None else entry,
        "bounds": {
            "transaction_count": transaction_count,
            "term_count": 8,
            "index_count": index_count,
            "log_capacity": log_capacity,
            "queue_capacity": 1,
        },
        "unknowns": ["old", "new"],
        "steps": steps,
    }


class TemplateFixtureTests(unittest.TestCase):
    def test_persistent_example_matches_the_test_template(self) -> None:
        example = json.loads(
            (ROOT / "Traces/ClientRequests/template.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            example,
            certificate(
                [
                    _request({"unknown": "new"}, node=1),
                    _observation("logLength", 2, node=1),
                ]
            ),
        )


@SOLVER_TESTS
class TemplateClientRequestTests(ClientRequestSliceTestCase):
    def test_a_nonbootstrap_leader_accepts_a_fresh_symbolic_transaction(self) -> None:
        status, output = self.run_runner(
            certificate(
                [
                    _observation("allocated", False, node=0),
                    _observation("currentTerm", 7, node=1),
                    _request({"unknown": "new"}, node=1),
                    _observation("logLength", 2, node=1),
                    _submitted({"unknown": "old"}, True),
                    _submitted({"unknown": "new"}, True),
                ]
            )
        )
        self.assertEqual(status, "sat")
        self.assertEqual(self.result(output)["assurance"]["entry"], "template")

    def test_distinct_names_do_not_imply_distinct_transaction_values(self) -> None:
        status, _ = self.run_runner(
            certificate(
                [_request({"unknown": "new"}, node=1)],
                transaction_count=1,
            )
        )
        self.assertEqual(status, "unsat")

    def test_existing_symbolic_identifiers_may_alias(self) -> None:
        entry = entry_state()
        entry["submittedTxIds"] = [{"unknown": "old"}, {"unknown": "new"}]
        status, _ = self.run_runner(
            certificate([_submitted(0, True)], entry=entry, transaction_count=1)
        )
        self.assertEqual(status, "sat")

    def test_transaction_bounds_include_queued_payloads(self) -> None:
        entry = entry_state()
        network = [[] for _ in range(NODE_COUNT)]
        network[1] = [
            {
                "kind": "appendEntriesRequest",
                "term": 7,
                "source": 2,
                "destination": 1,
                "prevLogIndex": 0,
                "prevLogTerm": 0,
                "leaderCommit": 0,
                "entries": [
                    {
                        "term": 7,
                        "content": {"kind": "transaction", "transaction": 2},
                    }
                ],
            }
        ]
        entry["network"] = network
        status, _ = self.run_runner(certificate([], entry=entry))
        self.assertEqual(status, "unsat")

    def test_log_capacity_core_keeps_the_causal_action(self) -> None:
        status, output = self.run_runner(
            certificate([_request({"unknown": "new"}, node=1)], log_capacity=1)
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))
        self.assertIn("group_2", self._core_names(output / "unsat-core.txt"))

    def test_retirement_refresh_bound_keeps_the_causal_action(self) -> None:
        local = local_state()
        local["log"] = [
            {"term": 6, "content": {"kind": "reconfiguration", "nodes": [0]}}
        ]
        entry = entry_state(local)
        status, output = self.run_runner(
            certificate(
                [_request({"unknown": "new"}, node=1)],
                entry=entry,
                index_count=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))
        self.assertIn("group_2", self._core_names(output / "unsat-core.txt"))

    def test_absent_nodes_do_not_consume_scalar_domains(self) -> None:
        empty = entry_state()
        empty["nodes"] = [None] * NODE_COUNT
        empty["submittedTxIds"] = []
        empty["hasJoined"] = []
        trace = certificate([], entry=empty)
        trace["unknowns"] = []
        trace["bounds"] = {
            "transaction_count": 0,
            "term_count": 0,
            "index_count": 0,
            "log_capacity": 0,
            "queue_capacity": 0,
        }
        status, _ = self.run_runner(trace)
        self.assertEqual(status, "sat")

    def test_unreachable_structural_snapshots_are_not_silently_restricted(self) -> None:
        local = local_state()
        local["commitIndex"] = 2
        status, _ = self.run_runner(
            certificate(
                [_observation("commitIndex", 2, node=1)],
                entry=entry_state(local),
            )
        )
        self.assertEqual(status, "sat")

    def test_unknown_control_fields_are_rejected_not_defaulted(self) -> None:
        local = local_state()
        local["currentTerm"] = {"unknown": "new"}
        with self.assertRaises(CertificateRejected):
            self.run_runner(certificate([], entry=entry_state(local)))


if __name__ == "__main__":
    unittest.main()
