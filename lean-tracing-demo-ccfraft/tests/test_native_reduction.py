# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from copy import deepcopy
from pathlib import Path
import unittest

from native_reduction import native_document, RECEIVE_KINDS
from raw_normalization import normalize
from reduction import SCHEMA_VERSION, ReductionError, build_certificate
from Shared.trace_io import read_ndjson

ROOT = Path(__file__).resolve().parents[1]


def action(name, node, **parameters):
    return {
        "kind": "action",
        "action": name,
        "node": node,
        "provenance": [{"line": 3}],
        "rule": "test",
        **parameters,
    }


def observation(variable, node, value):
    return {
        "kind": "observation",
        "variable": variable,
        "node": node,
        "value": value,
        "provenance": [{"line": 2}],
        "rule": "test",
    }


def normalized(*steps):
    return normalize(
        {"schema_version": SCHEMA_VERSION, "steps": list(steps)}, native_ids=True
    )


def received(family):
    payloads = {
        "raft_request_vote": {"lastCommittableTerm": 0, "lastCommittableIndex": 0},
        "raft_request_vote_response": {"voteGranted": True},
        "raft_request_pre_vote_response": {"voteGranted": False},
        "raft_append_entries": {
            "previousIndex": 0,
            "batchEnd": 2,
            "leaderCommitIndex": 0,
        },
        "raft_append_entries_response": {"lastLogIndex": 2, "success": "FAIL"},
    }
    return normalized(
        observation(
            "firstMessageFrom",
            "destination",
            {
                "messageType": family,
                "source": "source",
                "term": 7,
                "batchCount": 1,
                "batchPosition": 1,
                **payloads[family],
            },
        ),
        action(
            "receive", "destination", source="source", evidence={"messageType": family}
        ),
    )


class NativeReductionTests(unittest.TestCase):
    def test_typed_receives_match_the_selected_incoming_queue(self):
        for family, kind in RECEIVE_KINDS.items():
            with self.subTest(family=family):
                trace = received(family)
                before = deepcopy(trace)
                document = native_document(trace, ["source"])
                self.assertEqual(trace, before)
                packet, receive = document["instructions"]
                self.assertEqual(packet["kind"], "queuePattern")
                self.assertEqual(packet["index"], 0)
                self.assertEqual(packet["source"], "source")
                self.assertEqual(packet["destination"], "destination")
                self.assertEqual(
                    receive,
                    {
                        "kind": kind,
                        "source": "source",
                        "destination": "destination",
                    },
                )
                if family == "raft_append_entries":
                    self.assertEqual(packet["value"]["entriesLength"], 2)
                    self.assertNotIn("entries", packet["value"])
                    self.assertNotIn("prevLogTerm", packet["value"])

    def test_receive_evidence_is_required_and_checked(self):
        for mutation in ("missing", "family", "source", "observation"):
            with self.subTest(mutation=mutation), self.assertRaises(ReductionError):
                trace = received("raft_request_vote")
                if mutation == "missing":
                    trace.evidence.clear()
                elif mutation == "family":
                    trace.evidence[2]["messageType"] = "raft_append_entries"
                elif mutation == "source":
                    trace.steps[0]["value"]["source"] = trace.steps[0]["node"]
                else:
                    trace.steps[0]["variable"] = "role"
                    trace.steps[0]["value"] = "leader"
                native_document(trace, ["source"])

    def test_names_aliases_optional_values_and_order_survive_projection(self):
        trace = normalized(
            observation("joined", "105", False),
            observation("retirementIndex", "105", None),
            observation("retirementCommittableIndex", "105", 0),
            action("clientRequest", "105", transaction="shared"),
            action("clientRequest", "105", transaction="shared"),
            action("changeConfiguration", "105", configuration=["105", "other"]),
        )
        document = native_document(trace, ["105"])
        self.assertEqual(document["unknowns"], ["shared"])
        instructions = document["instructions"]
        self.assertEqual(
            instructions[0], {"kind": "joined", "node": "105", "value": False}
        )
        self.assertIsNone(instructions[1]["value"])
        self.assertEqual(instructions[2]["value"], 0)
        self.assertEqual(
            [item["transaction"] for item in instructions[3:5]],
            [{"unknown": "shared"}, {"unknown": "shared"}],
        )
        self.assertEqual(
            instructions[5],
            {
                "kind": "changeConfiguration",
                "source": "105",
                "configuration": ["105", "other"],
            },
        )
        instructions[3]["transaction"]["unknown"] = "changed"
        self.assertEqual(trace.steps[3]["transaction"], {"unknown": "shared"})

    def test_projection_rejects_unsupported_actions_and_invalid_bootstrap(self):
        for name, parameters in (
            ("becomeCandidate", {}),
            ("appendRetiredCommitted", {}),
            ("proposeVote", {"destination": "b"}),
        ):
            with self.subTest(action=name), self.assertRaises(ReductionError):
                native_document(normalized(action(name, "a", **parameters)), ["a"])
        trace = normalized(action("timeout", "a"))
        for bootstrap in ([], ["missing"], "a", None, 1, [True]):
            with self.subTest(bootstrap=bootstrap), self.assertRaises(ReductionError):
                native_document(trace, bootstrap)
        legacy = normalize(
            {
                "schema_version": SCHEMA_VERSION,
                "steps": [action("timeout", "0")],
            }
        )
        with self.assertRaisesRegex(ReductionError, "native identifier"):
            native_document(legacy, ["0"])

    def test_saved_captures_preserve_each_reduced_step(self):
        paths = sorted((ROOT / "Traces/Captured").glob("*.ndjson"))
        paths += sorted((ROOT / "Traces/Mutated").glob("*.ndjson"))
        self.assertEqual(len(paths), 6)
        for path in paths:
            with self.subTest(capture=path.name):
                certificate = build_certificate(read_ndjson(path))
                before = deepcopy(certificate)
                trace = normalize(certificate, native_ids=True)
                document = native_document(trace, [certificate["steps"][0]["node"]])
                self.assertEqual(certificate, before)
                self.assertEqual(
                    len(document["instructions"]), len(certificate["steps"])
                )
                self.assertEqual(document["unknowns"], list(trace.unknowns))
                self.assertEqual(
                    set(document), {"nodes", "bootstrap", "unknowns", "instructions"}
                )
                for source, instruction in zip(
                    trace.steps, document["instructions"], strict=True
                ):
                    if (
                        source["kind"] == "observation"
                        and source["variable"] != "firstMessageFrom"
                    ):
                        self.assertEqual(source["value"], instruction["value"])
                    elif source.get("action") == "updateTerm":
                        self.assertEqual(
                            instruction["source"], trace.node_names[source["node"]]
                        )
                        self.assertEqual(
                            instruction["destination"],
                            trace.node_names[source["destination"]],
                        )
