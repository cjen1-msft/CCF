# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

from raw_normalization import normalize
from reduction import SCHEMA_VERSION, ReductionError, build_certificate
from Shared.trace_io import read_ndjson

ROOT = Path(__file__).resolve().parents[1]


def certificate(*steps: dict) -> dict:
    return {"schema_version": SCHEMA_VERSION, "steps": list(steps)}


def action(name: str, node: str, **parameters: object) -> dict:
    return {
        "kind": "action",
        "action": name,
        "node": node,
        "provenance": [{"line": 3}],
        "rule": "test",
        **parameters,
    }


class RawNormalizationTests(unittest.TestCase):
    def test_all_saved_reductions_preserve_order_and_provenance(self) -> None:
        paths = sorted((ROOT / "Traces/Captured").glob("*.ndjson"))
        paths += sorted((ROOT / "Traces/Mutated").glob("*.ndjson"))
        self.assertEqual(len(paths), 6)
        for path in paths:
            with self.subTest(trace=path.name):
                source = build_certificate(read_ndjson(path))
                before = deepcopy(source)
                trace = normalize(source)
                self.assertEqual(source, before)
                self.assertEqual(len(source["steps"]), len(trace.steps))
                for index, (original, actual) in enumerate(
                    zip(source["steps"], trace.steps, strict=True), 1
                ):
                    self.assertEqual(original["kind"], actual["kind"])
                    self.assertEqual(original["provenance"], actual["provenance"])
                    self.assertEqual(original["rule"], actual["rule"])
                    if "evidence" in original:
                        self.assertEqual(trace.evidence[index], original["evidence"])
                    if original["kind"] == "observation":
                        self.assertEqual(original["variable"], actual["variable"])
                        if original["variable"] != "firstMessageFrom":
                            self.assertEqual(original["value"], actual["value"])
                        elif original["value"]["messageType"] == "raft_append_entries":
                            self.assertEqual(
                                actual["value"]["entriesLength"],
                                original["value"]["batchEnd"]
                                - original["value"]["previousIndex"],
                            )

    def test_receive_and_update_term_use_source_then_destination(self) -> None:
        trace = normalize(
            certificate(
                action("receive", "9", source="2"),
                action("updateTerm", "9", source="2"),
                action("requestVote", "2", destination="9"),
            )
        )
        for step in trace.steps:
            self.assertEqual(trace.node_names[step["node"]], "2")
            self.assertEqual(trace.node_names[step["destination"]], "9")
            self.assertNotIn("source", step)

    def test_transaction_names_remain_shared_unknowns_not_distinct_literals(
        self,
    ) -> None:
        trace = normalize(
            certificate(
                action("clientRequest", "0", transaction="a"),
                action("clientRequest", "0", transaction="b"),
                action("clientRequest", "0", transaction="a"),
            )
        )
        self.assertEqual(trace.unknowns, ("a", "b"))
        self.assertEqual(
            [step["transaction"] for step in trace.steps],
            [{"unknown": "a"}, {"unknown": "b"}, {"unknown": "a"}],
        )

    def test_partial_messages_do_not_acquire_unobserved_fields(self) -> None:
        trace = normalize(
            certificate(
                {
                    "kind": "observation",
                    "variable": "firstMessageFrom",
                    "node": "1",
                    "rule": "test",
                    "provenance": [{"line": 8}],
                    "value": {
                        "messageType": "raft_append_entries",
                        "source": "0",
                        "term": 2,
                        "previousIndex": 0,
                        "batchEnd": 1,
                        "leaderCommitIndex": 0,
                        "batchCount": 1,
                        "batchPosition": 1,
                    },
                }
            )
        )
        pattern = trace.steps[0]["value"]
        self.assertEqual(
            pattern,
            {
                "kind": "appendEntriesRequest",
                "source": 0,
                "destination": 1,
                "term": 2,
                "prevLogIndex": 0,
                "entriesLength": 1,
                "leaderCommit": 0,
            },
        )
        self.assertNotIn("prevLogTerm", pattern)
        self.assertNotIn("entries", pattern)

        for previous, end, length in ((2, 2, 0), (4, 5, 1), (2, 5, 3)):
            with self.subTest(previous=previous, end=end):
                source = build_certificate(
                    read_ndjson(ROOT / "Traces/Captured/bad_network.ndjson")
                )
                observation = next(
                    step
                    for step in source["steps"]
                    if step.get("variable") == "firstMessageFrom"
                    and step["value"]["messageType"] == "raft_append_entries"
                )
                observation["value"]["previousIndex"] = previous
                observation["value"]["batchEnd"] = end
                normalized = normalize(certificate(observation))
                self.assertEqual(normalized.steps[0]["value"]["entriesLength"], length)

    def test_sparse_node_ids_keep_their_bootstrap_meaning(self) -> None:
        first = normalize(
            certificate(*(action("timeout", name) for name in ("4", "9", "1", "2")))
        )
        second = normalize(
            certificate(*(action("timeout", name) for name in ("2", "1", "9", "4")))
        )
        self.assertEqual(first.node_names, {1: "1", 2: "2", 4: "4", 9: "9"})
        self.assertEqual(first.node_names, second.node_names)
        self.assertEqual([step["node"] for step in first.steps], [4, 9, 1, 2])

    def test_ambiguous_or_unmapped_node_names_are_rejected(self) -> None:
        for name in ("01", "peer", "", "-1", "15"):
            with self.subTest(name=name), self.assertRaisesRegex(
                ReductionError, "canonical ID"
            ):
                normalize(certificate(action("timeout", name)))

    def test_remaining_packet_families_preserve_all_observed_fields(self) -> None:
        cases = [
            (
                "raft_append_entries_response",
                "appendEntriesResponse",
                {"success": "FAIL", "lastLogIndex": 4},
                {"success": False, "lastLogIndex": 4},
            ),
            (
                "raft_append_entries_response",
                "appendEntriesResponse",
                {"success": "OK", "lastLogIndex": 5},
                {"success": True, "lastLogIndex": 5},
            ),
            (
                "raft_request_vote",
                "requestVoteRequest",
                {"lastCommittableIndex": 3, "lastCommittableTerm": 1},
                {"lastCommittableIndex": 3, "lastCommittableTerm": 1},
            ),
            (
                "raft_request_pre_vote",
                "requestPreVote",
                {"lastCommittableIndex": 3, "lastCommittableTerm": 1},
                {"lastCommittableIndex": 3, "lastCommittableTerm": 1},
            ),
            (
                "raft_request_vote_response",
                "requestVoteResponse",
                {"voteGranted": True},
                {"voteGranted": True},
            ),
            (
                "raft_request_pre_vote_response",
                "requestPreVoteResponse",
                {"voteGranted": False},
                {"voteGranted": False},
            ),
            ("raft_propose_request_vote", "proposeVoteRequest", {}, {}),
        ]
        for family, kind, raw, expected in cases:
            with self.subTest(family=family, raw=raw):
                trace = normalize(
                    certificate(
                        {
                            "kind": "observation",
                            "variable": "firstMessageFrom",
                            "node": "1",
                            "rule": "test",
                            "provenance": [{"line": 8}],
                            "value": {
                                "messageType": family,
                                "source": "0",
                                "term": 2,
                                "batchCount": 1,
                                "batchPosition": 1,
                                **raw,
                            },
                        }
                    )
                )
                self.assertEqual(
                    trace.steps[0]["value"],
                    {
                        "kind": kind,
                        "source": 0,
                        "destination": 1,
                        "term": 2,
                        **expected,
                    },
                )

    def test_nodes_referenced_only_by_configuration_are_included(self) -> None:
        trace = normalize(
            certificate(action("changeConfiguration", "0", configuration=["0", "9"]))
        )
        self.assertEqual(trace.node_names, {0: "0", 9: "9"})
        self.assertEqual(trace.steps[0]["configuration"], [0, 9])

    def test_more_than_fifteen_nodes_is_explicitly_rejected(self) -> None:
        with self.assertRaisesRegex(ReductionError, "model has 15 slots"):
            normalize(
                certificate(*(action("timeout", str(node)) for node in range(16)))
            )

    def test_unknown_actions_observations_and_extra_parameters_are_rejected(
        self,
    ) -> None:
        for step in (
            action("futureAction", "0"),
            action("timeout", "0", futureParameter=1),
            {
                "kind": "observation",
                "variable": "futureField",
                "node": "0",
                "value": 1,
                "provenance": [],
                "rule": "test",
            },
        ):
            with self.subTest(step=step), self.assertRaises(ReductionError):
                normalize(certificate(step))

    def test_normalized_provenance_does_not_alias_source(self) -> None:
        step = action("timeout", "0")
        step["evidence"] = {
            "batchCorrelation": {"matchingReceiveProvenance": [{"line": 2}]}
        }
        source = certificate(step)
        trace = normalize(source)
        trace.steps[0]["provenance"][0]["line"] = 100
        trace.evidence[1]["batchCorrelation"]["matchingReceiveProvenance"][0][
            "line"
        ] = 99
        self.assertEqual(source["steps"][0]["provenance"][0]["line"], 3)
        self.assertEqual(
            source["steps"][0]["evidence"]["batchCorrelation"][
                "matchingReceiveProvenance"
            ],
            [{"line": 2}],
        )

    def test_invalid_packet_index_ranges_are_rejected(self) -> None:
        source = build_certificate(
            read_ndjson(ROOT / "Traces/Captured/bad_network.ndjson")
        )
        observation = next(
            step
            for step in source["steps"]
            if step.get("variable") == "firstMessageFrom"
            and step["value"]["messageType"] == "raft_append_entries"
        )
        for previous, end in ((3, 2), (-1, 2), (0, True), ("0", 2)):
            with self.subTest(previous=previous, end=end):
                observation["value"]["previousIndex"] = previous
                observation["value"]["batchEnd"] = end
                with self.assertRaisesRegex(ReductionError, "invalid index range"):
                    normalize(certificate(observation))


if __name__ == "__main__":
    unittest.main()
