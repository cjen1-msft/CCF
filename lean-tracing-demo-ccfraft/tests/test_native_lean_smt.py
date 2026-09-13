# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Compare Lean-emitted SMT with kernel-proved fixture verdicts."""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from copy import deepcopy
from pathlib import Path

from explorer_api import ExplorerApi
from native_run import NativeRun
from native_solver import find_z3, run_z3

ROOT = Path(__file__).resolve().parents[1]
RETIREMENT_FIELDS = (
    "retirementIndex",
    "retirementCommittableIndex",
    "retiredCommittedIndex",
)
VOTE_SET_FIELDS = ("votesGranted", "preVotesGranted")
PEER_INDEX_FIELDS = ("sentIndex", "matchIndex")
MEMBERSHIP_STATES = (
    "active",
    "retirementOrdered",
    "retirementSigned",
    "retirementCompleted",
    "retiredCommitted",
)


def packet_samples(source, destination):
    header = {"term": 7, "source": source, "destination": destination}
    payloads = [
        (
            "appendEntriesRequest",
            {
                "prevLogIndex": 0,
                "prevLogTerm": 3,
                "leaderCommit": 7,
                "entries": [
                    {"term": 4, "content": "signature"},
                    {"term": 5, "content": {"transaction": 10**30}},
                    {"term": 6, "content": {"reconfiguration": [source, destination]}},
                    {"term": 7, "content": {"retiredCommitted": [destination]}},
                ],
            },
        ),
        ("appendEntriesResponse", {"success": False, "lastLogIndex": 9}),
        ("requestVoteRequest", {"lastCommittableTerm": 3, "lastCommittableIndex": 9}),
        ("requestVoteResponse", {"voteGranted": True}),
        ("requestPreVote", {"lastCommittableTerm": 3, "lastCommittableIndex": 9}),
        ("requestPreVoteResponse", {"voteGranted": False}),
        ("proposeVoteRequest", {}),
    ]
    return [dict(header, kind=kind, **payload) for kind, payload in payloads]


def packet_observation(packet, *, source=None, destination=None, index=0):
    return {
        "kind": "queuePoint",
        "source": packet["source"] if source is None else source,
        "destination": packet["destination"] if destination is None else destination,
        "index": index,
        "value": packet,
    }


class NativeImportBoundaryTests(unittest.TestCase):
    def test_core_proofs_do_not_import_public_trace_compiler(self):
        seen = set()

        def visit(module):
            if module in seen:
                return
            seen.add(module)
            path = ROOT.joinpath(*module.split(".")).with_suffix(".lean")
            if not path.exists():
                self.assertFalse(
                    module.startswith(("Sparse.", "MachineGenerated.")),
                    f"Missing project module {module}",
                )
                return
            for line in path.read_text().splitlines():
                if line.startswith("import "):
                    for dependency in line.partition("--")[0].split()[1:]:
                        visit(dependency)

        for module in (
            "Sparse.NativeClientRequestComplete",
            "Sparse.NativeClientRequestAssignment",
            "Sparse.NativeClientRequestSound",
            "Sparse.NativeClientRequestStructure",
            "Sparse.NativeNatParametersEncoding",
            "Sparse.NativeLeaderLogPrefix",
            "Sparse.NativeClientRequestExecution",
            "Sparse.NativeSubmittedWriteEncoding",
            "Sparse.NativeArrayClientRequestModel",
            "Sparse.NativeClientRequestTermsEncoding",
            "Sparse.NativeFrameColumns",
            "Sparse.NativeCampaignWrites",
            "Sparse.NativeVoteReceiveWritesEncoding",
            "Sparse.NativeVoteReceiveEncoding",
            "Sparse.NativeAppendGuardEncoding",
            "Sparse.NativeAppendSendEncoding",
            "Sparse.NativeFirstMatchEncoding",
            "Sparse.NativeRetirementEncoding",
            "Sparse.NativeArrayRetirementIndex",
            "Sparse.NativeArrayAppendNetwork",
            "Sparse.NativeArrayChangeConfiguration",
            "Sparse.NativeLogSpliceEncoding",
            "Sparse.NativeRetirementIndexEncoding",
            "Sparse.NativeArrayAppendReceiveGuard",
            "Sparse.NativeFirstMatchWitness",
            "Sparse.NativeRetirementIndexSound",
            "Sparse.NativeLogRangeEncoding",
            "Sparse.NativeRetirementRefreshTerms",
            "Sparse.NativeAppendResponseTerm",
            "Sparse.NativeRetirementCompletedTerm",
            "Sparse.NativeMaxMatchEncoding",
            "Sparse.NativeArrayLogSummaries",
            "Sparse.NativeNodeRowWritesEncoding",
            "Sparse.NativeLogSummaryEncoding",
            "Sparse.NativeAppendReceiveTermsEncoding",
            "Sparse.NativeRetirementRefreshEncoding",
            "Sparse.NativeAppendReceiveWritesEncoding",
            "Sparse.NativeAppendReceiveResponseEncoding",
            "Sparse.NativeRetirementCompletedEncoding",
            "Sparse.NativeArrayAppendCandidate",
            "Sparse.NativeMembershipTermsEncoding",
            "Sparse.NativeAppendReceiveCandidateEncoding",
            "Sparse.NativeAppendReceiveFinalRowEncoding",
            "Sparse.NativeAppendReceiveFrameEncoding",
            "Sparse.NativeAppendReceiveHandlerEncoding",
            "Sparse.NativeRetirementCompletedConstraintsEncoding",
            "Sparse.NativeAppendReceiveLocalEncoding",
            "Sparse.NativeMembershipRowEncoding",
            "Sparse.NativeAllocationEncoding",
            "Sparse.NativeNodeRowModelEncoding",
            "Sparse.NativeMembershipWritesEncoding",
            "Sparse.NativeMembershipFrameEncoding",
            "Sparse.NativeRetirementRefreshAssignment",
            "Sparse.NativeLogSummaryAssignment",
            "Sparse.NativeLogSpliceAssignment",
            "Sparse.NativeAppendReceiveExecution",
            "Sparse.NativeAppendReceiveSound",
            "Sparse.NativeAppendReceiveExecutionConstraints",
            "Sparse.NativeAppendReceiveCommitAssignment",
            "Sparse.NativeAppendReceiveComplete",
            "Sparse.NativeAppendReceiveRetirementAssignment",
            "Sparse.NativeAppendReceiveLogAssignment",
            "Sparse.NativeMembershipExecution",
            "Sparse.NativeAppendReceiveTailAssignment",
            "Sparse.NativeMembershipExecutionConstraints",
            "Sparse.NativeMembershipSound",
            "Sparse.NativeMembershipComplete",
            "Sparse.NativeMembershipChangeEncoding",
            "Sparse.NativeMembershipRetirementAssignment",
            "Sparse.NativeMembershipTailAssignment",
            "Sparse.NativeMembershipLogAssignment",
            "Sparse.NativeAppendReceiveEncoding",
            "Sparse.NativeArrayAdvanceCommit",
            "Sparse.NativeMajorityTerms",
            "Sparse.NativeArrayVotingMajority",
            "Sparse.NativeVotingMajority",
            "Sparse.NativeVotingMajorityEncoding",
            "Sparse.NativeArrayBecomeLeader",
            "Sparse.NativeBecomeLeader",
            "Sparse.NativeBecomeLeaderGuardsEncoding",
            "Sparse.NativeBecomeLeaderExecution",
            "Sparse.NativeArrayBecomeLeaderTransition",
            "Sparse.NativeBecomeLeaderRowEncoding",
            "Sparse.NativeBecomeLeaderPrefixAssignment",
            "Sparse.NativeBecomeLeaderSound",
            "Sparse.NativeBecomeLeaderComplete",
            "Sparse.NativeNatSetInsert",
            "Sparse.NativeNatSetInsertEncoding",
            "Sparse.NativeActiveConfigurationEncoding",
            "Sparse.NativeReplicationMajority",
            "Sparse.NativeArrayCommitTransition",
            "Sparse.NativeCommitIndexEncoding",
            "Sparse.NativeRetirementWritesEncoding",
            "Sparse.NativeCommitTermsEncoding",
            "Sparse.NativeCommitIndexAssignment",
            "Sparse.NativeAdvanceCommit",
            "Sparse.NativeCommitExecution",
            "Sparse.NativeCommitSound",
            "Sparse.NativeCommitPrefixAssignment",
            "Sparse.NativeCommitSuffixAssignment",
            "Sparse.NativeCommitComplete",
            "Sparse.NativeAdvanceCommitEncoding",
            "Sparse.NativeArrayLeaderLogWrite",
            "Sparse.NativeArraySignature",
            "Sparse.NativeArraySignatureTransition",
            "Sparse.NativeSignatureTermsEncoding",
            "Sparse.NativeSignaturePrefix",
            "Sparse.NativeSignature",
            "Sparse.NativeRetirementTail",
            "Sparse.NativeRetirementTailExecution",
            "Sparse.NativeRetirementTailSound",
            "Sparse.NativeRetirementTailPrefixAssignment",
            "Sparse.NativeRetirementTailSuffixAssignment",
            "Sparse.NativeRetirementTailComplete",
            "Sparse.NativeSignatureSound",
            "Sparse.NativeSignatureComplete",
            "Sparse.NativeSignCommittableEncoding",
            "Sparse.NativeQueuePattern",
            "Sparse.NativePacketArrayHint",
            "Sparse.NativePacketArrayHintEncoding",
            "Sparse.NativePacketPatternEncoding",
            "Sparse.NativeQueuePatternEncoding",
            "Sparse.NativeVoteResponse",
            "Sparse.NativeArrayVoteResponse",
            "Sparse.NativeVoteResponseExecution",
            "Sparse.NativeVoteResponseTermsEncoding",
            "Sparse.NativeVoteResponseSound",
            "Sparse.NativeVoteResponseComplete",
            "Sparse.NativeArrayAppendResponse",
            "Sparse.NativeAppendResponse",
            "Sparse.NativeAppendResponseExecution",
            "Sparse.NativeAppendResponseTermsEncoding",
            "Sparse.NativeAppendResponseSound",
            "Sparse.NativeAppendResponseComplete",
        ):
            visit(module)
        forbidden = {
            "Sparse.NativeArrayVote",
            "Sparse.NativeFrameEncode",
            "Sparse.NativeFrameStep",
            "Sparse.NativeFrameTrace",
            "Sparse.NativeFrameDecoded",
            "Sparse.NativeNodeSets",
            "Sparse.NativeNodeOperations",
        }
        self.assertFalse(seen & forbidden, sorted(seen & forbidden))


@unittest.skipUnless(
    os.environ.get("CCF_NATIVE_ARRAY_TESTS") == "1",
    "set CCF_NATIVE_ARRAY_TESTS=1 to run Lean/Z3 fixtures",
)
class NativeLeanSmtTests(unittest.TestCase):
    def test_proved_fixtures(self):
        result = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeSmtFixtureMain.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertGreaterEqual(len(fixtures), 156)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.solve(fixtures)

    def test_model_signature_indices(self):
        self.assert_script_fixtures("NativeSignatureFixtureMain", 483, 85)

    def test_configuration_majority_terms(self):
        self.assert_script_fixtures("NativeMajorityFixtureMain", 200, 100)

    def test_voting_majority_terms(self):
        fixtures = self.assert_script_fixtures("NativeVotingMajorityFixtureMain", 318, 159)
        named = {fixture["name"]: fixture for fixture in fixtures}
        for name, expected in (
            ("future-configuration-commit-0-support-3-true", False),
            ("future-configuration-commit-0-support-7-true", True),
            ("obsolete-configuration-commit-1000000000000000000000000000000-support-3-true", True),
            ("empty-configuration-commit-0-support-7-true", False),
            ("wide-singleton-65-commit-1-support-18446744073709551616-true", True),
        ):
            self.assertEqual(named[name]["majority"], expected, name)

    def test_nat_set_insert_terms(self):
        fixtures = self.assert_script_fixtures("NativeNatSetInsertFixtureMain", 122, 61)
        named = {fixture["name"]: fixture for fixture in fixtures}
        self.assertEqual(named["naive-store-resurrects-gap-false"]["expected"], "unsat")
        self.assertEqual(named["naive-store-resurrects-gap-true"]["expected"], "sat")

    def test_submitted_set_writes(self):
        self.assert_script_fixtures("NativeSubmittedWriteFixtureMain", 60, 30)

    def test_natural_parameters(self):
        self.assert_script_fixtures("NativeNatParametersFixtureMain", 29, 16)

    def test_highest_commit_index(self):
        fixtures = self.assert_script_fixtures("NativeCommitIndexFixtureMain", 127, 32)
        by_name = {fixture["name"]: fixture for fixture in fixtures}
        for name, best, last_signature, majorities in [
            ("pending-joint-rejects", 0, 2, [(0, False), (1, True)]),
            ("future-configuration-ignored", 1, 1, [(0, True), (2, False)]),
            ("joint-falls-back", 2, 4, [(1, False), (3, True)]),
        ]:
            with self.subTest(name=name):
                fixture = by_name[f"commit-index-{name}-exact"]
                self.assertEqual(fixture["best"], best)
                self.assertEqual(fixture["lastSignature"], last_signature)
                self.assertEqual(
                    [
                        (configuration["index"], configuration["majority"])
                        for configuration in fixture["configurationMajorities"]
                    ],
                    majorities,
                )
        for name, best in [
            ("non-current-unsorted-terms", 1),
            ("no-current-term-signature", 0),
            ("nonzero-source-with-remote", 1),
        ]:
            with self.subTest(name=name):
                self.assertEqual(by_name[f"commit-index-{name}-exact"]["best"], best)

    def test_first_match_encoding(self):
        self.assert_script_fixtures("NativeFirstMatchFixtureMain", 530, 66)

    def test_normalized_entry_observations(self):
        self.assert_script_fixtures("NativeObservationNormalizeFixtureMain", 576, 24)

    def test_retirement_scan_encoding(self):
        self.assert_script_fixtures("NativeRetirementFixtureMain", 1410, 210)

    def test_log_splice_encoding(self):
        self.assert_script_fixtures("NativeLogSpliceFixtureMain", 1280, 796)

    def test_log_range_encoding(self):
        self.assert_script_fixtures("NativeLogRangeFixtureMain", 4800, 2400)

    def test_append_response_encoding(self):
        self.assert_script_fixtures("NativeAppendResponseFixtureMain", 756, 108)

    def test_retirement_index_encoding(self):
        self.assert_script_fixtures("NativeRetirementIndexFixtureMain", 1788, 72)

    def test_retirement_refresh_encoding(self):
        fixtures = self.assert_script_fixtures(
            "NativeRetirementRefreshFixtureMain", 1440, 288
        )
        self.assertEqual(
            {
                fixture["membership"]
                for fixture in fixtures
                if fixture["expected"] == "sat"
            },
            set(range(5)),
        )
        self.assertTrue(
            any(
                fixture["activeWithCommittedRetired"] and fixture["expected"] == "sat"
                for fixture in fixtures
            )
        )

    def test_retirement_completed_prefix_encoding(self):
        fixtures = self.assert_script_fixtures(
            "NativeRetirementCompletedFixtureMain", 720, 360
        )
        self.assertEqual(
            {
                fixture["modelCompleted"]
                for fixture in fixtures
                if fixture["expected"] == "sat"
            },
            {False, True},
        )

    def test_retirement_completed_constraints(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeRetirementCompletedConstraintsFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        output = json.loads(result.stdout)
        fixtures = output["fixtures"]
        self.assertEqual(len(fixtures), 240)
        self.assertEqual(len({item["name"] for item in fixtures}), len(fixtures))
        successful = [item for item in fixtures if item["expected"] == "sat"]
        self.assertEqual(len(successful), 160)
        self.assertEqual(
            {item["modelBits"] for item in successful if item["enabled"]},
            {0, 1, 2, 3, 4, 6},
        )
        self.assertTrue(
            all(item["expected"] == "sat" for item in fixtures if not item["enabled"])
        )
        self.assertEqual(len(output["rejected"]), 20)
        self.assertEqual(
            {(item["kind"], item["symbol"]) for item in output["rejected"]},
            {
                (kind, symbol)
                for kind in ("enabled", "length", "entries", "commit", "current")
                for symbol in (24, 25, 33, 1024)
            },
        )
        for item in output["rejected"]:
            self.assertEqual(
                item["error"],
                "internal encoder error: retirement completed constraints reference an unallocated SMT symbol",
            )
        self.solve(fixtures)

    def test_retirement_refresh_constraints(self):
        fixtures = self.assert_script_fixtures(
            "NativeRetirementRefreshConstraintsFixtureMain", 2592, 288
        )
        successful = [item for item in fixtures if item["expected"] == "sat"]
        self.assertEqual({item["membership"] for item in successful}, set(range(5)))
        self.assertTrue(any(item["activeWithCommittedRetired"] for item in successful))

    def test_node_row_writes(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeNodeRowWritesFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        output = json.loads(result.stdout)
        fixtures = output["fixtures"]
        self.assertEqual(len(fixtures), 1584)
        self.assertEqual(len({item["name"] for item in fixtures}), len(fixtures))
        successful = [item for item in fixtures if item["expected"] == "sat"]
        self.assertEqual(len(successful), 72)
        self.assertEqual({item["mode"] for item in successful}, {0, 1, 2})
        for field in ("sourcePresent", "destinationPresent", "self"):
            self.assertEqual({item[field] for item in successful}, {False, True})
        self.assertEqual(len(output["rejected"]), 60)
        self.assertEqual(
            {(item["column"], item["symbol"]) for item in output["rejected"]},
            {
                (column, symbol)
                for column in range(1, 16)
                for symbol in (24, 25, 39, 1024)
            },
        )
        self.assertEqual(
            {item["error"] for item in output["rejected"]},
            {"internal encoder error: row write references an unallocated SMT symbol"},
        )
        self.solve(fixtures)

    def test_native_allocation(self):
        result = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeAllocationFixtureMain.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        output = json.loads(result.stdout)
        fixtures = output["fixtures"]
        self.assertEqual(len(fixtures), 4416)
        self.assertEqual(len({item["name"] for item in fixtures}), len(fixtures))
        successful = [item for item in fixtures if item["expected"] == "sat"]
        self.assertEqual(len(successful), 192)
        self.assertEqual(
            {(item["present"], item["added"], item["mode"]) for item in successful},
            {
                (present, added, mode)
                for present in range(8)
                for added in range(8)
                for mode in range(3)
            },
        )
        self.assertEqual(
            {(item["targetPresent"], item["targetAdded"]) for item in successful},
            {(False, False), (False, True), (True, False), (True, True)},
        )
        self.assertEqual({item["mutation"] for item in fixtures}, set(range(23)))
        self.assertEqual(len(output["rejected"]), 10)
        self.assertEqual(
            {(item["kind"], item["symbol"]) for item in output["rejected"]},
            {
                (kind, symbol)
                for kind in ("node", "set")
                for symbol in (24, 25, 40, 74, 1024)
            },
        )
        for item in output["rejected"]:
            subject = "condition" if item["kind"] == "node" else "set"
            self.assertEqual(
                item["error"],
                f"internal encoder error: allocation {subject} references an unallocated SMT symbol",
            )
        self.solve(fixtures)

    def test_explicit_log_summaries(self):
        fixtures = self.assert_script_fixtures("NativeLogSummaryFixtureMain", 4160, 800)
        successful = [item for item in fixtures if item["expected"] == "sat"]
        self.assertEqual({item["kind"] for item in successful}, set(range(5)))
        self.assertEqual({item["modelIndex"] for item in successful}, set(range(6)))
        for field in ("noncanonical", "nested"):
            self.assertEqual({item[field] for item in successful}, {False, True})

    def test_model_append_receive_guards(self):
        models = self.model_traces("NativeArrayAppendReceiveFixtureMain", 1344)
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeAppendReceiveGuardFixtureMain.lean",
            ],
            cwd=ROOT,
            input=json.dumps(models),
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 1416)
        self.assertEqual(len({item["name"] for item in fixtures}), len(fixtures))
        self.assertEqual(sum(item["expected"] == "sat" for item in fixtures), 680)
        for model, fixture in zip(models, fixtures):
            self.assertEqual(
                fixture["expected"] == "sat",
                model["modelEnabled"] and model["selectedAppendRequest"],
            )
        self.solve(fixtures)

    def test_model_append_receive_responses(self):
        fixtures = self.assert_script_fixtures(
            "NativeAppendReceiveResponseFixtureMain", 396, 69
        )
        successful = [item for item in fixtures if item["expected"] == "sat"]
        self.assertEqual(len({item["scenario"] for item in successful}), 11)
        for field in ("hinted", "ack", "self"):
            self.assertEqual({item[field] for item in successful}, {False, True})
        self.assertEqual(
            {item["selected"] for item in successful if not item["hinted"]},
            {-11, 0, 10**30},
        )
        self.assertEqual(
            {item["selected"] for item in successful if item["hinted"]}, {0, 1, 2}
        )
        by_scenario = {item["scenario"]: item for item in successful}
        for scenario, expected in {
            "zero-last-term": (5, 2),
            "zero-previous-term": (0, 1),
            "no-match": (1, 0),
            "positive-match": (5, 1),
            "unordered": (1, 2),
            "match-beyond-cap": (1, 0),
        }.items():
            item = by_scenario[scenario]
            self.assertEqual((item["responseTerm"], item["responseIndex"]), expected)

    def test_model_membership_guards(self):
        models = self.model_traces("NativeArrayMembershipFixtureMain", 1572)
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeMembershipGuardFixtureMain.lean",
            ],
            cwd=ROOT,
            input=json.dumps(models),
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), len(models))
        self.assertEqual(len({item["name"] for item in fixtures}), len(fixtures))
        self.assertEqual(sum(item["expected"] == "sat" for item in fixtures), 314)
        self.assertEqual(
            [item["expected"] == "sat" for item in fixtures],
            [item["modelEnabled"] for item in models],
        )
        self.solve(fixtures)

    def test_internal_membership_change(self):
        models = self.model_traces("NativeArrayMembershipFixtureMain", 1572)
        self.assert_internal_model_traces(
            "NativeMembershipChangeFixtureMain", models, 147, "membership"
        )

    def test_internal_advance_commit(self):
        models = self.model_traces("NativeArrayAdvanceCommitFixtureMain", 43)
        originals = {
            item["scenario"]: item
            for item in models
            if item["mutation"].endswith(".unchanged")
        }
        self.assertEqual(
            {name for name, item in originals.items() if item["modelEnabled"]},
            {
                "bootstrap-success",
                "stale-retired-metadata-success",
                "retirement-refresh-success",
                "configuration-commit-success",
                "transaction-zero-success",
                "nonzero-source-success",
                "source-outside-bootstrap-success",
            },
        )
        for item in models:
            if not item["modelEnabled"]:
                self.assertEqual(
                    item["trace"]["instructions"][-1]["kind"], "advanceCommitIndex"
                )
        self.assertFalse(originals["majority-rejection"]["advances"])
        self.assertFalse(originals["wrong-role"]["leader"])
        self.assertFalse(originals["unallocated-source"]["allocated"])
        self.assertFalse(originals["no-new-current-term-signature"]["advances"])
        terminal = originals["terminal-retirement-rejection"]
        self.assertTrue(terminal["advances"])
        self.assertTrue(terminal["terminalRetirement"])
        refreshed = originals["retirement-refresh-success"]
        self.assertEqual(refreshed["afterMembership"], "retirementCompleted")
        self.assertEqual(refreshed["completedBefore"], ["c"])
        self.assertEqual(refreshed["completedAfter"], ["a"])
        stale = originals["stale-retired-metadata-success"]
        self.assertEqual(stale["beforeMembership"], "retiredCommitted")
        self.assertEqual(stale["afterMembership"], "active")
        self.assert_internal_model_traces(
            "NativeAdvanceCommitFixtureMain", models, 7, "advance-commit"
        )

        extras = [f"spare-{index}" for index in range(3, 17)]
        absent = [
            {"kind": "allocated", "node": node, "value": False} for node in extras
        ]
        wide = []
        for item in models:
            if item["scenario"] == "bootstrap-success" and (
                item["mutation"].endswith(".unchanged")
                or item["mutation"].endswith(".sourceCommit")
            ):
                extended = deepcopy(item)
                extended["trace"]["nodes"].extend(extras)
                extended["trace"]["instructions"] = (
                    absent + extended["trace"]["instructions"] + absent
                )
                wide.append(extended)
        self.assertEqual(len(wide), 2)
        self.assert_internal_model_traces(
            "NativeAdvanceCommitFixtureMain", wide, 1, "advance-commit-wide"
        )

    def test_membership_write_reference_checks(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeMembershipWritesFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        rejected = json.loads(result.stdout)
        self.assertEqual(len(rejected), 15)
        self.assertEqual(
            {(item["kind"], item["symbol"]) for item in rejected},
            {
                (kind, symbol)
                for kind in ("added", "completed", "row")
                for symbol in (24, 25, 74, 92, 1024)
            },
        )
        self.assertEqual(
            {item["error"] for item in rejected},
            {
                "internal encoder error: membership writes reference an unallocated SMT symbol"
            },
        )

    def test_internal_signature(self):
        models = self.model_traces("NativeArraySignatureFixtureMain", 50)
        originals = {
            item["scenario"]: item
            for item in models
            if item["mutation"].endswith(".unchanged")
        }
        disabled = {
            name for name, item in originals.items() if not item["modelEnabled"]
        }
        self.assertEqual(
            disabled,
            {
                "unallocated-source",
                "nonleader",
                "empty-log",
                "old-retired-committed",
                "newly-refreshed-retired-committed",
            },
        )
        for name in disabled:
            self.assertEqual(
                originals[name]["trace"]["instructions"][-1]["kind"],
                "signCommittableMessages",
            )
        for name, item in originals.items():
            self.assertEqual(item["outputLength"], item["oldLength"] + 1, name)
            self.assertEqual(item["oldVotedFor"], item["outputVotedFor"], name)
        old_terminal = originals["old-retired-committed"]
        self.assertTrue(old_terminal["oldTerminal"])
        self.assertFalse(old_terminal["refreshedTerminal"])
        refreshed_terminal = originals["newly-refreshed-retired-committed"]
        self.assertFalse(refreshed_terminal["oldTerminal"])
        self.assertTrue(refreshed_terminal["refreshedTerminal"])
        for name, membership in [
            ("refresh-retirement-signed", "retirementSigned"),
            ("refresh-retirement-completed", "retirementCompleted"),
            ("stale-retirement-metadata-refreshes-active", "active"),
        ]:
            self.assertEqual(originals[name]["outputMembership"], membership)
        self.assertEqual(
            originals["refresh-retirement-signed"]["refreshedRetirementCommittableIndex"],
            2,
        )
        stale = originals["stale-retirement-metadata-refreshes-active"]
        self.assertGreater(stale["oldCommit"], stale["oldLength"])
        self.assertEqual(stale["oldRetiredCommittedIndex"], 0)
        self.assertIsNone(stale["refreshedRetiredCommittedIndex"])
        zero = originals["transaction-zero-unsorted-current-zero"]
        self.assertEqual(zero["currentTerm"], 0)
        self.assertEqual(originals["signature-nonempty"]["oldVotedFor"], "a")
        self.assertIsNone(originals["nonzero-source"]["oldVotedFor"])
        self.assertFalse(originals["source-outside-bootstrap"]["sourceInBootstrap"])
        self.assert_internal_model_traces(
            "NativeSignCommittableFixtureMain", models, 8, "signature"
        )

    def signature_commit_traces(self):
        models = self.model_traces("NativeArraySignatureFixtureMain", 50)
        base = next(
            item
            for item in models
            if item["scenario"] == "signature-nonempty"
            and item["mutation"].endswith(".unchanged")
        )
        document = deepcopy(base["trace"])
        document["instructions"].extend(
            [
                {"kind": "advanceCommitIndex", "node": "a"},
                {"kind": "commit", "node": "a", "value": 2},
            ]
        )
        variants = [{"trace": document, "expected": "sat"}]
        stale = deepcopy(document)
        stale["instructions"][-1]["value"] = 0
        variants.append({"trace": stale, "expected": "unsat"})
        early = deepcopy(document)
        signature_index = next(
            index
            for index, instruction in enumerate(early["instructions"])
            if instruction["kind"] == "signCommittableMessages"
        )
        early["instructions"].insert(
            signature_index, {"kind": "advanceCommitIndex", "node": "a"}
        )
        variants.append({"trace": early, "expected": "unsat"})
        wide = deepcopy(document)
        extras = [f"spare-{index}" for index in range(3, 17)]
        wide["nodes"].extend(extras)
        absent = [
            {"kind": "allocated", "node": node, "value": False} for node in extras
        ]
        wide["instructions"] = absent + wide["instructions"] + absent
        variants.append({"trace": wide, "expected": "sat"})
        return variants

    def test_signature_commit_sequence(self):
        self.assert_internal_model_traces(
            "NativeSignCommittableFixtureMain",
            self.signature_commit_traces(),
            2,
            "signature-commit",
        )

    def test_public_signature_commit_sequence(self):
        models = self.signature_commit_traces()
        scripts = self.encode([model["trace"] for model in models])
        self.solve(
            [
                {
                    "name": f"public-signature-commit-{index}",
                    "script": script,
                    "expected": model["expected"],
                }
                for index, (model, script) in enumerate(zip(models, scripts))
            ]
        )

    def test_internal_core_action_sequences(self):
        models = self.model_traces("NativeArrayCoreActionsFixtureMain", 184)
        baseline = [item for item in models if item["mutation"] == 0]
        successful = [item for item in baseline if item["modelEnabled"]]
        self.assertEqual(
            {(item["present"], item["mode"]) for item in successful},
            {(False, 0), (True, 0), (False, 3), (True, 3)},
            {
                (item["present"], item["mode"]): item["disabledSteps"]
                for item in baseline
            },
        )
        for item in baseline:
            self.assertEqual(
                item["disabledSteps"],
                [] if item["mode"] in (0, 3) else [1 if item["mode"] == 1 else 7],
            )
        self.assert_internal_model_traces(
            "NativeCoreActionsFixtureMain", models, 4, "core"
        )

    def test_public_core_action_sequences(self):
        fixtures = self.assert_model_traces(
            "NativeArrayCoreActionsFixtureMain", 184, "public-core"
        )
        successful = [item for item in fixtures if item["expected"] == "sat"]
        self.assertEqual(len(successful), 4)
        required = {
            "requestVote",
            "receiveRequestVote",
            "appendEntries",
            "receiveAppendEntries",
            "changeConfiguration",
        }
        for item in successful:
            kinds = {entry["kind"] for entry in item["trace"]["instructions"]}
            self.assertTrue(required.issubset(kinds))
        larger = deepcopy(successful[0]["trace"])
        inactive = [
            f"node-{index}" for index in range(len(larger["nodes"]), 21)
        ]
        larger["nodes"] += inactive
        larger["instructions"] = [
            {"kind": "allocated", "node": node, "value": False}
            for node in inactive
        ] + larger["instructions"]
        self.assertEqual(len(larger["nodes"]), 21)
        scripts = self.encode([larger])
        self.solve(
            [
                {
                    "name": "twenty-one-node-core-sequence",
                    "script": scripts[0],
                    "expected": "sat",
                }
            ]
        )

    def test_model_append_receive_writes(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeAppendReceiveWritesFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        output = json.loads(result.stdout)
        fixtures = output["fixtures"]
        self.assertEqual(len(fixtures), 2436)
        self.assertEqual(len({item["name"] for item in fixtures}), len(fixtures))
        successful = [item for item in fixtures if item["expected"] == "sat"]
        self.assertEqual(len(successful), 348)
        self.assertEqual(
            {item["branch"] for item in successful},
            {"stepdown", "reject", "alreadyDone", "extension", "conflict"},
        )
        for field in ("sourcePresent", "self"):
            self.assertEqual({item[field] for item in successful}, {False, True})
        self.assertEqual(len(output["rejected"]), 16)
        self.assertEqual(
            {(item["kind"], item["symbol"]) for item in output["rejected"]},
            {
                (kind, symbol)
                for kind in ("stepDown", "response", "completed", "row")
                for symbol in (24, 39, 47, 1024)
            },
        )
        for item in output["rejected"]:
            self.assertEqual(
                item["error"],
                (
                    "internal encoder error: row write references an unallocated SMT symbol"
                    if item["kind"] == "row"
                    else "internal encoder error: append receive inputs reference an unallocated SMT symbol"
                ),
            )
        self.solve(fixtures)

    def test_internal_append_receive(self):
        models = self.model_traces("NativeArrayAppendReceiveFixtureMain", 1344)
        self.assert_internal_append_receive(models, 334, "base")

    def test_internal_append_receive_hints(self):
        models = self.model_traces("NativeArrayAppendReceiveHintFixtureMain", 110)
        self.assertEqual(len({item["scenario"] for item in models}), 11)
        self.assertEqual(
            {item["branch"] for item in models}, {"reject", "alreadyDone", "extension"}
        )
        self.assertTrue(all(item["modelEnabled"] for item in models))
        self.assert_internal_append_receive(models, 55, "hint")

    def assert_internal_append_receive(self, models, satisfiable, prefix):
        self.assert_internal_model_traces(
            "NativeAppendReceiveFixtureMain", models, satisfiable, prefix
        )

    def assert_internal_model_traces(self, module, models, satisfiable, prefix):
        result = subprocess.run(
            ["lake", "env", "lean", "--run", f"Sparse/{module}.lean"],
            cwd=ROOT,
            input=json.dumps(models),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), len(models))
        self.assertEqual(len({item["name"] for item in fixtures}), len(fixtures))
        self.assertEqual(
            sum(item["expected"] == "sat" for item in fixtures), satisfiable
        )
        self.assertEqual(
            [item["expected"] for item in fixtures],
            [item["expected"] for item in models],
        )
        self.solve([{**item, "name": f"{prefix}-{item['name']}"} for item in fixtures])

    def assert_script_fixtures(self, module, count, satisfiable):
        result = subprocess.run(
            ["lake", "env", "lean", "--run", f"Sparse/{module}.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), count)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.assertEqual(
            sum(item["expected"] == "sat" for item in fixtures), satisfiable
        )
        self.solve(fixtures)
        return fixtures

    def test_queue_store_execution(self):
        pairs = [("a", "b"), ("b", "a"), ("a", "a"), ("c", "b"), ("a", "c"), ("a", "b")]
        packets = [
            [packet_samples(source, destination)[kind] for source, destination in pairs]
            for kind in range(7)
        ]
        result = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeQueueStoreFixtureMain.lean"],
            cwd=ROOT,
            input=json.dumps(packets),
            capture_output=True,
            text=True,
            check=True,
        )
        output = json.loads(result.stdout)
        fixtures = output["fixtures"]
        self.assertEqual(len(fixtures), 56)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.assertEqual(sum(item["expected"] == "sat" for item in fixtures), 28)
        pop_fixtures = output["popFixtures"]
        self.assertEqual(len(pop_fixtures), 56)
        self.assertEqual(
            len(pop_fixtures), len({item["name"] for item in pop_fixtures})
        )
        self.assertEqual(sum(item["expected"] == "sat" for item in pop_fixtures), 28)
        self.assertEqual(
            [(item["next"], item["id"]) for item in output["rejected"]],
            [(24, 24), (24, 25), (24, 1024), (26, 26), (26, 27)],
        )
        for item in output["rejected"]:
            self.assertEqual(
                item["error"],
                "internal encoder error: packet references an unallocated SMT symbol",
            )
        self.solve(fixtures + pop_fixtures)

    def test_model_vote_packets(self):
        result = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeVotePacketFixtureMain.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 5080)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.assertEqual(sum(item["expected"] == "sat" for item in fixtures), 2540)
        self.solve(fixtures)

    def test_model_append_packets(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeAppendPacketFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 2538)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.assertEqual({item["expected"] for item in fixtures}, {"sat", "unsat"})
        self.solve(fixtures)

    def test_model_append_guards(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeAppendGuardFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 1216)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.assertEqual({item["expected"] for item in fixtures}, {"sat", "unsat"})
        self.solve(fixtures)

    def test_model_vote_receive_writes(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeVoteReceiveWritesFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        output = json.loads(result.stdout)
        fixtures = output["fixtures"]
        self.assertEqual(len(fixtures), 192)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.assertEqual(sum(item["expected"] == "sat" for item in fixtures), 96)
        self.assertEqual(
            [(item["packet"], item["signature"]) for item in output["rejected"]],
            [(24, 23), (23, 24), (24, 24), (1024, 23)],
        )
        for item in output["rejected"]:
            self.assertEqual(
                item["error"],
                "internal encoder error: vote receive inputs reference an unallocated SMT symbol",
            )
        self.solve(fixtures)

    def test_model_vote_receive_responses(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeVoteReceiveFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 1728)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.assertEqual({item["expected"] for item in fixtures}, {"sat", "unsat"})
        self.solve(fixtures)

    def test_model_term_guards(self):
        models = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeArrayTermFixtureMain.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(len(json.loads(models.stdout)), 168)
        encoded = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeTermGuardFixtureMain.lean"],
            cwd=ROOT,
            input=models.stdout,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(encoded.stdout)
        self.assertEqual(len(fixtures), 216)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.solve(fixtures)

    def test_model_campaign_guards(self):
        models = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeArrayVoteFixtureMain.lean",
                "campaign",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(len(json.loads(models.stdout)), 400)
        encoded = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeCampaignGuardFixtureMain.lean",
            ],
            cwd=ROOT,
            input=models.stdout,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(encoded.stdout)
        self.assertEqual(len(fixtures), 1200)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.assertEqual({item["expected"] for item in fixtures}, {"sat", "unsat"})
        self.solve(fixtures)

    def test_model_active_membership(self):
        result = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeMembershipFixtureMain.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 1140)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.assertEqual({item["expected"] for item in fixtures}, {"sat", "unsat"})
        self.solve(fixtures)

    def solve(self, fixtures):
        requested = os.environ.get("Z3")
        solver = find_z3(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="native-lean-smt-") as temporary:
            artifacts = Path(os.environ.get("CCF_NATIVE_ARRAY_ARTIFACTS", temporary))
            artifacts.mkdir(parents=True, exist_ok=True)
            for fixture in fixtures:
                with self.subTest(name=fixture["name"]):
                    name = f"lean-smt-{fixture['name']}"
                    path = artifacts / f"{name}.smt2"
                    path.write_text(fixture["script"], encoding="ascii")
                    result = run_z3(solver, fixture["script"], "", artifacts, name)
                    (artifacts / f"{name}.metrics.json").write_text(
                        json.dumps(
                            {
                                "status": result.status,
                                "wall_time_ms": result.wall_time_ms,
                                "script_bytes": path.stat().st_size,
                            },
                            indent=2,
                        )
                        + "\n",
                        encoding="ascii",
                    )
                    self.assertEqual(result.status, fixture["expected"])

    def encode(self, documents):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeEncodeMain.lean",
                "--batch",
            ],
            cwd=ROOT,
            input=json.dumps(
                documents, separators=(",", ":"), sort_keys=True, ensure_ascii=False
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        scripts = json.loads(result.stdout)
        self.assertEqual(len(scripts), len(documents))
        return scripts

    def test_actual_model_check_quorum(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeArrayCheckQuorumFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 150)
        scripts = self.encode([fixture["trace"] for fixture in fixtures])
        self.solve(
            [
                {
                    "name": f"model-quorum-{index}",
                    "script": script,
                    "expected": fixture["expected"],
                }
                for index, (fixture, script) in enumerate(zip(fixtures, scripts))
            ]
        )

    def test_actual_model_vote_sends(self):
        result = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeArrayVoteFixtureMain.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 400)
        self.assertEqual({item["expected"] for item in fixtures}, {"sat", "unsat"})
        scripts = self.encode([fixture["trace"] for fixture in fixtures])
        self.solve(
            [
                {
                    "name": f"model-vote-send-{index}",
                    "script": script,
                    "expected": fixture["expected"],
                }
                for index, (fixture, script) in enumerate(zip(fixtures, scripts))
            ]
        )

    def test_actual_model_term_updates(self):
        result = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeArrayTermFixtureMain.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 168)
        self.assertEqual({item["expected"] for item in fixtures}, {"sat", "unsat"})
        scripts = self.encode([fixture["trace"] for fixture in fixtures])
        self.solve(
            [
                {
                    "name": f"model-term-update-{index}",
                    "script": script,
                    "expected": fixture["expected"],
                }
                for index, (fixture, script) in enumerate(zip(fixtures, scripts))
            ]
        )

    def test_actual_model_campaigns(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeArrayVoteFixtureMain.lean",
                "campaign",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 400)
        scripts = self.encode([fixture["trace"] for fixture in fixtures])
        self.solve(
            [
                {
                    "name": f"model-campaign-{index}",
                    "script": script,
                    "expected": fixture["expected"],
                }
                for index, (fixture, script) in enumerate(zip(fixtures, scripts))
            ]
        )

    def test_campaign_state_and_vote_sequence(self):
        def local(kind, value, node="a"):
            return {"kind": kind, "node": node, "value": value}

        cases = []
        for pre_vote in (False, True):
            kind = "becomePreVoteCandidate" if pre_vote else "timeout"
            term = 10**30 if pre_vote else 10**30 + 1
            start = [
                local("allocated", True),
                local("allocated", True, "b"),
                local("role", "follower"),
                local("currentTerm", 10**30),
                local("newFollower", False),
                local("votedFor", "b"),
                local("votesGranted", ["b"]),
                local("preVotesGranted", ["b"]),
                local("logLength", 0),
                local("commit", 0),
                local("membershipState", "active"),
                local("preVoteStatus", "enabled" if pre_vote else "capable"),
                local("retirementCompleted", []),
                local("currentTerm", 0, "b"),
                {
                    "kind": "queueLength",
                    "source": "a",
                    "destination": "b",
                    "value": 0,
                },
            ]
            action = {"kind": kind, "node": "a"}
            post = [
                local("role", "preVoteCandidate" if pre_vote else "candidate"),
                local("currentTerm", term),
                local("newFollower", False),
                local("votedFor", "b" if pre_vote else "a"),
                local("votesGranted", ["b"] if pre_vote else ["a"]),
                local("preVotesGranted", ["a"] if pre_vote else []),
            ]
            cases.append((f"{kind}-state", start + [action] + post, "sat"))
            wrong_values = ["leader", term + 1, True, None, [], ["b"]]
            for index, wrong in enumerate(wrong_values):
                mutated = [dict(item) for item in post]
                mutated[index]["value"] = wrong
                cases.append(
                    (f"{kind}-mutated-{index}", start + [action] + mutated, "unsat")
                )
            send = {
                "kind": "requestPreVote" if pre_vote else "requestVote",
                "source": "a",
                "destination": "b",
            }
            packet = {
                "kind": "requestPreVote" if pre_vote else "requestVoteRequest",
                "source": "a",
                "destination": "b",
                "term": term,
                "lastCommittableTerm": 0,
                "lastCommittableIndex": 0,
            }
            point = {
                "kind": "queuePoint",
                "source": "a",
                "destination": "b",
                "index": 0,
                "value": packet,
            }
            update = {"kind": "updateTerm", "source": "a", "destination": "b"}
            sequence = (
                start
                + [action]
                + post
                + [
                    send,
                    point,
                    update,
                    local("currentTerm", term, "b"),
                    local("role", "follower", "b"),
                    local("newFollower", True, "b"),
                    action,
                    local("currentTerm", term if pre_vote else term + 1),
                    send,
                    {
                        "kind": "queueLength",
                        "source": "a",
                        "destination": "b",
                        "value": 2,
                    },
                    point,
                    dict(
                        point,
                        index=1,
                        value=dict(packet, term=term if pre_vote else term + 1),
                    ),
                ]
            )
            cases.append((f"{kind}-vote-sequence", sequence, "sat"))
            # updateTerm does not consume the old head, even after a newer send.
            cases.append((f"{kind}-head-not-consumed", sequence + [update], "unsat"))
        scripts = self.encode(
            [
                {"nodes": ["a", "b"], "bootstrap": ["a", "b"], "instructions": items}
                for _, items, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_campaign_input_errors(self):
        invalid = []
        for kind in ("timeout", "becomePreVoteCandidate"):
            invalid.extend(
                [
                    {"kind": kind},
                    {"kind": kind, "node": "missing"},
                    {"kind": kind, "node": 0},
                    {"kind": kind, "node": "a", "term": 7},
                ]
            )
        self.assert_invalid_instructions(invalid)

    def test_term_update_frame_and_sequence(self):
        def local(kind, value, **extra):
            return {"kind": kind, "node": "b", "value": value, **extra}

        def point(source, term):
            return {
                "kind": "queuePoint",
                "source": source,
                "destination": "b",
                "index": 0,
                "value": {
                    "kind": "proposeVoteRequest",
                    "source": source,
                    "destination": "a",
                    "term": term,
                },
            }

        preserved = [
            local("allocated", True),
            local("commit", 10**30),
            local("logLength", 1),
            local("entry", {"term": 7, "content": "signature"}, index=0),
            local("votesGranted", ["a", "c"]),
            local("membershipState", "retirementSigned"),
            local("retirementIndex", 10**30),
            local("retirementCommittableIndex", None),
            local("retiredCommittedIndex", 9),
            local("sentIndex", 10**30, peer="a"),
            local("matchIndex", 5, peer="c"),
            {"kind": "currentTerm", "node": "a", "value": 17},
            {"kind": "role", "node": "a", "value": "candidate"},
            {"kind": "hasJoined", "value": ["b"]},
            {"kind": "preVoteStatus", "node": "b", "value": "enabled"},
            {"kind": "retirementCompleted", "node": "b", "value": ["c"]},
            {"kind": "submittedTxId", "txId": 10**30, "value": True},
            {"kind": "queueLength", "source": "a", "destination": "b", "value": 1},
            {"kind": "queueLength", "source": "c", "destination": "b", "value": 1},
            point("a", 3),
            point("c", 10**30),
        ]
        start = preserved + [
            local("currentTerm", 2),
            local("role", "leader"),
            local("newFollower", False),
            local("votedFor", "c"),
            local("preVotesGranted", ["a", "c"]),
        ]
        action = {"kind": "updateTerm", "source": "a", "destination": "b"}
        changed = [
            local("currentTerm", 3),
            local("role", "follower"),
            local("newFollower", True),
            local("votedFor", None),
            local("preVotesGranted", []),
        ]
        after = start + [action] + preserved + changed
        cases = [("frame", after, "sat")]
        for index, observation in enumerate(preserved + changed):
            value = observation["value"]
            if isinstance(value, dict):
                wrong = dict(value, term=value["term"] + 1)
            elif isinstance(value, bool):
                wrong = not value
            elif isinstance(value, int):
                wrong = value + 1
            elif isinstance(value, list):
                wrong = [] if value else ["a"]
            elif value is None:
                wrong = "a" if observation["kind"] == "votedFor" else 0
            else:
                wrong = {
                    "role": "none",
                    "membershipState": "active",
                    "preVoteStatus": "capable",
                }[observation["kind"]]
            # Replace the matching post-state fact, rather than contradicting it directly.
            post = [dict(item) for item in preserved + changed]
            post[index]["value"] = wrong
            cases.append((f"mutated-{index}", start + [action] + post, "unsat"))
        cases.extend(
            [
                ("equal-repeat", after + [action], "unsat"),
                (
                    "higher-next",
                    after
                    + [
                        dict(action, source="c"),
                        local("currentTerm", 10**30),
                        *preserved,
                        *changed[1:],
                    ],
                    "sat",
                ),
                (
                    "older-after-higher",
                    after + [dict(action, source="c"), action],
                    "unsat",
                ),
            ]
        )
        scripts = self.encode(
            [
                {
                    "nodes": ["a", "b", "c"],
                    "bootstrap": ["a", "b"],
                    "instructions": items,
                }
                for _, items, _ in cases
            ]
        )
        self.solve(
            [
                {"name": f"term-update-{name}", "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_vote_send_guards(self):
        cases = []
        for kind, required_role in (
            ("requestVote", "candidate"),
            ("requestPreVote", "preVoteCandidate"),
        ):
            for role in ("none", "follower", "preVoteCandidate", "candidate", "leader"):
                for source_present in (False, True):
                    for destination_present in (False, True):
                        for destination in ("a", "b"):
                            for bootstrap in (["a"], ["a", "b"]):
                                allowed = (
                                    source_present
                                    and destination_present
                                    and role == required_role
                                    and destination != "a"
                                    and destination in bootstrap
                                )
                                cases.append(
                                    (
                                        {
                                            "nodes": ["a", "b"],
                                            "bootstrap": bootstrap,
                                            "instructions": [
                                                {
                                                    "kind": "allocated",
                                                    "node": "a",
                                                    "value": source_present,
                                                },
                                                {
                                                    "kind": "allocated",
                                                    "node": destination,
                                                    "value": destination_present,
                                                },
                                                {
                                                    "kind": "role",
                                                    "node": "a",
                                                    "value": role,
                                                },
                                                {
                                                    "kind": "logLength",
                                                    "node": "a",
                                                    "value": 0,
                                                },
                                                {
                                                    "kind": kind,
                                                    "source": "a",
                                                    "destination": destination,
                                                },
                                            ],
                                        },
                                        "sat" if allowed else "unsat",
                                    )
                                )
        self.assertEqual(len(cases), 160)
        scripts = self.encode([document for document, _ in cases])
        self.solve(
            [
                {"name": f"vote-guards-{index}", "script": script, "expected": expected}
                for index, ((_, expected), script) in enumerate(zip(cases, scripts))
            ]
        )

    def test_vote_send_fifo_and_frame(self):
        cases = []
        vote = {
            "kind": "requestVoteRequest",
            "source": "a",
            "destination": "b",
            "term": 3,
            "lastCommittableIndex": 10**30,
            "lastCommittableTerm": 0,
        }
        pre_vote = {
            "kind": "requestPreVote",
            "source": "b",
            "destination": "a",
            "term": 7,
            "lastCommittableIndex": 0,
            "lastCommittableTerm": 0,
        }
        other = {
            "kind": "proposeVoteRequest",
            "source": "b",
            "destination": "b",
            "term": 99,
        }
        for size in (2, 21):
            names = ["a", "b"] + [f"node-{index}" for index in range(2, size)]
            observed = [
                {"kind": "allocated", "node": "a", "value": True},
                {"kind": "allocated", "node": "b", "value": True},
                {"kind": "role", "node": "a", "value": "candidate"},
                {"kind": "role", "node": "b", "value": "preVoteCandidate"},
                {"kind": "logLength", "node": "a", "value": 0},
                {"kind": "logLength", "node": "b", "value": 0},
                {"kind": "commit", "node": "a", "value": 10**30},
                {"kind": "commit", "node": "b", "value": 0},
                {"kind": "currentTerm", "node": "a", "value": 3},
                {"kind": "currentTerm", "node": "b", "value": 7},
                {"kind": "votedFor", "node": "a", "value": "b"},
                {"kind": "newFollower", "node": "a", "value": False},
                {"kind": "membershipState", "node": "a", "value": "retirementSigned"},
                {"kind": "sentIndex", "node": "a", "peer": "b", "value": 10**30},
                {"kind": "hasJoined", "value": ["a"]},
                {"kind": "preVoteStatus", "node": "b", "value": "capable"},
                {"kind": "retirementCompleted", "node": "a", "value": ["b"]},
                {"kind": "submittedTxId", "txId": 10**30, "value": True},
                {"kind": "submittedTxId", "txId": 10**30 + 1, "value": False},
            ]
            initial_queues = [
                {"kind": "queueLength", "source": "a", "destination": "b", "value": 1},
                {"kind": "queueLength", "source": "b", "destination": "a", "value": 0},
                {"kind": "queueLength", "source": "b", "destination": "b", "value": 1},
                packet_observation(vote),
                packet_observation(other),
            ]
            action = {"kind": "requestVote", "source": "a", "destination": "b"}
            actions = [
                action,
                {"kind": "requestPreVote", "source": "b", "destination": "a"},
            ]
            if size > 2:
                actions += [
                    {"kind": "role", "node": names[-1], "value": "leader"},
                    {"kind": "logLength", "node": names[-1], "value": 0},
                    {"kind": "checkQuorum", "node": names[-1]},
                    {"kind": "role", "node": names[-1], "value": "follower"},
                ]
            for count in (2, 3):
                final_queues = [
                    {
                        "kind": "queueLength",
                        "source": "a",
                        "destination": "b",
                        "value": count,
                    },
                    {
                        "kind": "queueLength",
                        "source": "b",
                        "destination": "a",
                        "value": 1,
                    },
                    {
                        "kind": "queueLength",
                        "source": "b",
                        "destination": "b",
                        "value": 1,
                    },
                    *[packet_observation(vote, index=index) for index in range(3)],
                    packet_observation(pre_vote),
                    packet_observation(other),
                ]
                cases.append(
                    (
                        f"vote-fifo-{size}-{count}",
                        {
                            "nodes": names,
                            "bootstrap": names,
                            "instructions": observed
                            + initial_queues
                            + actions
                            + [action]
                            + observed
                            + final_queues,
                        },
                        "sat" if count == 3 else "unsat",
                    )
                )
        scripts = self.encode([document for _, document, _ in cases])
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_public_model_append_sends(self):
        self.assert_model_traces(
            "NativeArrayAppendFixtureMain", 1200, "public-model-append"
        )

    def test_public_model_vote_receives(self):
        fixtures = self.assert_model_traces(
            "NativeArrayVoteReceiveFixtureMain", 480, "public-model-vote-receive"
        )
        self.assertTrue(
            any(
                fixture["modelEnabled"] and not fixture["selectedVoteRequest"]
                for fixture in fixtures
            )
        )

    def test_public_model_append_receives(self):
        self.assert_model_traces(
            "NativeArrayAppendReceiveFixtureMain", 1344, "public-model-append-receive"
        )

    def test_public_model_append_receive_hints(self):
        self.assert_model_traces(
            "NativeArrayAppendReceiveHintFixtureMain", 110, "public-model-append-hint"
        )

    def test_public_model_membership_changes(self):
        self.assert_model_traces(
            "NativeArrayMembershipFixtureMain", 1572, "public-model-membership"
        )

    def test_public_model_advance_commit(self):
        fixtures = self.assert_model_traces(
            "NativeArrayAdvanceCommitFixtureMain", 43, "public-model-advance-commit"
        )
        self.assertEqual(sum(item["expected"] == "sat" for item in fixtures), 7)

    def test_public_model_signatures(self):
        fixtures = self.assert_model_traces(
            "NativeArraySignatureFixtureMain", 50, "public-model-signature"
        )
        self.assertEqual(sum(item["expected"] == "sat" for item in fixtures), 8)

    def mutate_frame_observation(self, observed, names):
        kind, value = observed["kind"], observed["value"]
        if isinstance(value, bool):
            replacement = not value
        elif isinstance(value, int):
            replacement = value + 1
        elif value is None:
            replacement = names[0] if kind == "votedFor" else 0
        elif isinstance(value, list):
            replacement = [] if value else [names[0]]
        elif isinstance(value, dict) and "term" in value:
            replacement = dict(value, term=value["term"] + 1)
        elif kind == "votedFor":
            replacement = None
        elif kind == "role":
            replacement = "leader" if value != "leader" else "follower"
        elif kind == "membershipState":
            replacement = "active" if value != "active" else "retiredCommitted"
        elif kind == "preVoteStatus":
            replacement = "enabled" if value == "capable" else "capable"
        else:
            self.fail(f"Unhandled frame observation: {observed}")
        return dict(observed, value=replacement)

    def response_guard_traces(self, baseline, expected_kind):
        action = baseline["trace"]["instructions"][baseline["stepIndex"]]
        source, destination = action["source"], action["destination"]
        cases = []
        for packet in packet_samples(source, destination):
            if packet["kind"] == expected_kind:
                continue
            changed = deepcopy(baseline)
            prefix = changed["trace"]["instructions"][: baseline["stepIndex"] + 1]
            selected = next(
                item
                for item in prefix
                if item["kind"] == "queuePoint"
                and item["source"] == source
                and item["destination"] == destination
                and item["index"] == 0
            )
            selected["value"] = dict(packet, term=selected["value"]["term"])
            changed["trace"]["instructions"] = prefix
            changed["expected"] = "unsat"
            changed["name"] = f"{baseline['name']}-wrong-{packet['kind']}"
            cases.append(changed)
        empty = deepcopy(baseline)
        empty["trace"]["instructions"] = [
            item
            for item in empty["trace"]["instructions"][: baseline["stepIndex"] + 1]
            if not (
                item["kind"] == "queuePoint"
                and item["source"] == source
                and item["destination"] == destination
            )
        ]
        selected_length = next(
            item
            for item in empty["trace"]["instructions"]
            if item["kind"] == "queueLength"
            and item["source"] == source
            and item["destination"] == destination
        )
        selected_length["value"] = 0
        empty["expected"] = "unsat"
        empty["name"] = f"{baseline['name']}-empty"
        return cases + [empty]

    def vote_response_traces(self):
        models = self.model_traces("NativeArrayVoteResponseFixtureMain", 120)
        guard_cases = []
        self.assertEqual(sum(item["expected"] == "sat" for item in models), 76)
        for model in models:
            if not model["destinationAllocated"] or not model["recipientMatches"]:
                self.assertEqual(model["expected"], "unsat", model["name"])
            elif not model["sourceAllocated"]:
                self.assertEqual(model["expected"], "sat", model["name"])
            elif model["term"] == 2:
                candidate = "preVoteCandidate" if model["preVote"] else "candidate"
                self.assertEqual(
                    model["expected"],
                    "unsat" if model["role"] == candidate else "sat",
                    model["name"],
                )

        for pre_vote in (False, True):
            candidate = "preVoteCandidate" if pre_vote else "candidate"
            baseline = next(
                model
                for model in models
                if model["preVote"] == pre_vote
                and model["role"] == candidate
                and model["term"] == 1
                and model["granted"]
                and model["sourceAllocated"]
                and model["destinationAllocated"]
                and model["recipientMatches"]
                and model["source"] == "a"
            )
            instructions = baseline["trace"]["instructions"]
            expected_kind = (
                "requestPreVoteResponse" if pre_vote else "requestVoteResponse"
            )
            guard_cases.extend(self.response_guard_traces(baseline, expected_kind))

            for index in range(baseline["stepIndex"] + 1, len(instructions)):
                changed = deepcopy(baseline)
                observed = changed["trace"]["instructions"][index]
                changed["trace"]["instructions"][index] = self.mutate_frame_observation(
                    observed, changed["trace"]["nodes"]
                )
                changed["expected"] = "unsat"
                changed["name"] = f"vote-response-{pre_vote}-changed-{index}-{observed['kind']}"
                models.append(changed)
        self.assertEqual(len(models), 288)
        models.extend(guard_cases)
        names = [f"peer-{index}" for index in range(17)]
        source, destination = names[-1], names[1]
        for pre_vote in (False, True):
            vote_field = "preVotesGranted" if pre_vote else "votesGranted"
            packet = {
                "kind": "requestPreVoteResponse" if pre_vote else "requestVoteResponse",
                "term": 1,
                "source": source,
                "destination": destination,
                "voteGranted": True,
            }
            queue_length = {
                "kind": "queueLength",
                "source": source,
                "destination": destination,
                "value": 1,
            }
            models.append(
                {
                    "expected": "sat",
                    "trace": {
                        "nodes": names,
                        "bootstrap": [names[0]],
                        "instructions": [
                            {
                                "kind": "allocated",
                                "node": node,
                                "value": node in (source, destination),
                            }
                            for node in names
                        ]
                        + [
                            {
                                "kind": "role",
                                "node": destination,
                                "value": "preVoteCandidate" if pre_vote else "candidate",
                            },
                            {"kind": "currentTerm", "node": destination, "value": 1},
                            {"kind": vote_field, "node": destination, "value": []},
                            queue_length,
                            packet_observation(packet),
                            {
                                "kind": (
                                    "receiveRequestPreVoteResponse"
                                    if pre_vote
                                    else "receiveRequestVoteResponse"
                                ),
                                "source": source,
                                "destination": destination,
                            },
                            {
                                "kind": vote_field,
                                "node": destination,
                                "value": [source],
                            },
                            dict(queue_length, value=0),
                        ],
                    },
                }
            )
        self.assertEqual(len(models), 304)
        return models

    def test_internal_vote_responses(self):
        self.assert_internal_model_traces(
            "NativeReceiveVoteResponseFixtureMain",
            self.vote_response_traces(),
            78,
            "vote-responses",
        )

    def append_response_traces(self):
        models = self.model_traces("NativeArrayAppendResponseFixtureMain", 226)
        for model in models:
            allowed = (
                model["destinationAllocated"]
                and model["recipientMatches"]
                and (
                    not model["sourceAllocated"]
                    or not model["success"]
                    or model["term"] <= 1
                    or model["role"] != "leader"
                )
            )
            self.assertEqual(model["expected"], "sat" if allowed else "unsat", model["name"])
            if not allowed:
                continue
            sent, matched = model["sentBefore"], model["matchBefore"]
            if model["sourceAllocated"] and not model["success"]:
                possible = max(
                    (
                        index
                        for index, term in enumerate(model["logTerms"], 1)
                        if index <= model["lastLogIndex"] and term <= model["term"]
                    ),
                    default=0,
                )
                sent = max(min(possible, sent), matched)
            elif (
                model["sourceAllocated"]
                and model["term"] == 1
                and model["role"] == "leader"
            ):
                matched = max(matched, model["lastLogIndex"])
            self.assertEqual(model["sentAfter"], sent, model["name"])
            self.assertEqual(model["matchAfter"], matched, model["name"])
        for success, last_index, terms in (
            (True, 21, [9, 0]),
            (False, 3, [4, 0, 2]),
        ):
            baseline = next(
                model
                for model in models
                if model["expected"] == "sat"
                and model["success"] == success
                and model["term"] == 1
                and model["lastLogIndex"] == last_index
                and model["logTerms"] == terms
                and model["role"] == "leader"
                and model["source"] == "a"
                and model["sourceAllocated"]
            )
            if not success:
                models.extend(self.response_guard_traces(baseline, "appendEntriesResponse"))
            for index in range(
                baseline["stepIndex"] + 1, len(baseline["trace"]["instructions"])
            ):
                changed = deepcopy(baseline)
                changed["trace"]["instructions"][index] = self.mutate_frame_observation(
                    changed["trace"]["instructions"][index], changed["trace"]["nodes"]
                )
                changed["expected"] = "unsat"
                changed["name"] = f"append-response-{success}-changed-{index}"
                models.append(changed)
        names = [f"peer-{index}" for index in range(17)]
        source, destination = names[-1], names[1]
        for success in (False, True):
            packet = {
                "kind": "appendEntriesResponse",
                "source": source,
                "destination": destination,
                "term": 1 if success else 0,
                "success": success,
                "lastLogIndex": 10**30 if success else 2,
            }
            cursor = "matchIndex" if success else "sentIndex"
            expected_cursor = 10**30 if success else 2
            instructions = [
                {"kind": "allocated", "node": node, "value": node in (source, destination)}
                for node in names
            ] + [
                {"kind": "role", "node": destination, "value": "leader"},
                {"kind": "currentTerm", "node": destination, "value": 1},
                {"kind": "logLength", "node": destination, "value": 2},
            ]
            instructions.extend(
                {
                    "kind": "entry",
                    "node": destination,
                    "index": index,
                    "value": {"term": term, "content": "signature"},
                }
                for index, term in enumerate((4, 0))
            )
            instructions.extend(
                [
                    {"kind": "sentIndex", "node": destination, "peer": source, "value": 5},
                    {"kind": "matchIndex", "node": destination, "peer": source, "value": 0},
                    {"kind": "queueLength", "source": source, "destination": destination, "value": 1},
                    packet_observation(packet),
                    {"kind": "receiveAppendEntriesResponse", "source": source, "destination": destination},
                    {"kind": cursor, "node": destination, "peer": source, "value": expected_cursor},
                    {"kind": "queueLength", "source": source, "destination": destination, "value": 0},
                ]
            )
            model = {
                "name": f"append-response-wide-{success}",
                "expected": "sat",
                "trace": {"nodes": names, "bootstrap": [names[0]], "instructions": instructions},
            }
            wrong = deepcopy(model)
            wrong["name"] += "-wrong-cursor"
            wrong["expected"] = "unsat"
            wrong["trace"]["instructions"][-2]["value"] += 1
            models.extend([model, wrong])
        return models

    def test_internal_append_responses(self):
        self.assert_internal_model_traces(
            "NativeReceiveAppendResponseFixtureMain",
            self.append_response_traces(),
            196,
            "append-responses",
        )

    def client_request_traces(self):
        models = self.model_traces("NativeArrayClientRequestFixtureMain", 36)
        named = {model["name"]: model for model in models}
        for name in (
            "empty-log",
            "present-in-log-not-submitted",
            "retirement-ordered",
            "retirement-signed",
            "retirement-completed",
            "stale-metadata",
            "zero-transaction",
            "large-naturals",
        ):
            self.assertEqual(named[name]["expected"], "sat", name)
        for name in (
            "submitted-but-not-in-log",
            "refreshed-terminal",
            "unallocated-source",
            "membership-retiredCommitted",
        ):
            self.assertEqual(named[name]["expected"], "unsat", name)
        for name in ("empty-log", "retirement-completed"):
            baseline = named[name]
            for index in range(
                baseline["stepIndex"] + 1, len(baseline["trace"]["instructions"])
            ):
                changed = deepcopy(baseline)
                changed["trace"]["instructions"][index] = self.mutate_frame_observation(
                    changed["trace"]["instructions"][index], changed["trace"]["nodes"]
                )
                changed["expected"] = "unsat"
                changed["name"] = f"{name}-changed-{index}"
                models.append(changed)
        duplicate = deepcopy(named["empty-log"])
        duplicate["name"] += "-duplicate"
        duplicate["expected"] = "unsat"
        duplicate["trace"]["instructions"].append(
            {"kind": "clientRequest", "node": "a", "transaction": 5}
        )
        models.append(duplicate)
        names = [f"peer-{index}" for index in range(17)]
        source = names[-1]
        instructions = [
            {"kind": "allocated", "node": node, "value": node == source}
            for node in names
        ] + [
            {"kind": "role", "node": source, "value": "leader"},
            {"kind": "membershipState", "node": source, "value": "active"},
            {"kind": "currentTerm", "node": source, "value": 10**30},
            {"kind": "commit", "node": source, "value": 10**30},
            {"kind": "logLength", "node": source, "value": 0},
            {"kind": "newFollower", "node": source, "value": True},
            {"kind": "submittedTxId", "txId": 10**30, "value": False},
            {"kind": "submittedTxId", "txId": 0, "value": True},
        ]
        cursors = [
            {"kind": kind, "node": source, "peer": peer, "value": value}
            for peer in names
            for kind, value in (("sentIndex", 5), ("matchIndex", 12))
        ]
        instructions.extend(deepcopy(cursors))
        instructions.extend(
            [
                {"kind": "clientRequest", "node": source, "transaction": 10**30},
                {"kind": "logLength", "node": source, "value": 1},
                {"kind": "commit", "node": source, "value": 10**30},
                {"kind": "newFollower", "node": source, "value": True},
                {"kind": "entry", "node": source, "index": 0,
                 "value": {"term": 10**30, "content": {"transaction": 10**30}}},
                {"kind": "submittedTxId", "txId": 10**30, "value": True},
                {"kind": "submittedTxId", "txId": 0, "value": True},
            ]
        )
        instructions.extend(cursors)
        wide = {
            "name": "client-request-wide",
            "expected": "sat",
            "trace": {"nodes": names, "bootstrap": [source], "instructions": instructions},
        }
        wrong = deepcopy(wide)
        wrong["name"] += "-wrong-cursor"
        wrong["expected"] = "unsat"
        wrong["trace"]["instructions"][-1]["value"] += 1
        models.extend([wide, wrong])
        return models

    def test_internal_client_request(self):
        self.assert_internal_model_traces(
            "NativeClientRequestFixtureMain",
            self.client_request_traces(),
            26,
            "client-request",
        )

    def client_request_duplicate_traces(self):
        document = json.loads(
            (ROOT / "Traces/native_client_request_duplicate_conflict.json").read_text()
        )
        corrected = deepcopy(document)
        corrected["instructions"][-1]["transaction"] = 6
        return [
            {"name": "duplicate-client-request", "trace": document, "expected": "unsat"},
            {"name": "different-client-request", "trace": corrected, "expected": "sat"},
        ]

    def test_internal_client_request_duplicate(self):
        self.assert_internal_model_traces(
            "NativeClientRequestFixtureMain",
            self.client_request_duplicate_traces(),
            1,
            "client-request-duplicate",
        )

    def test_parameterized_client_requests(self):
        models = [
            deepcopy(model)
            for model in self.client_request_traces()
            if model["expected"] == "sat"
        ]
        for model in models:
            names = {}
            for item in model["trace"]["instructions"]:
                if item["kind"] == "clientRequest":
                    name = f"tx-{item['transaction']}"
                    names[name] = None
                    item["transaction"] = {"unknown": name}
            model["trace"]["unknowns"] = list(names)
        initial = [
            {"kind": "allocated", "node": "a", "value": True},
            {"kind": "role", "node": "a", "value": "leader"},
            {"kind": "membershipState", "node": "a", "value": "active"},
            {"kind": "currentTerm", "node": "a", "value": 3},
            {"kind": "commit", "node": "a", "value": 0},
            {"kind": "logLength", "node": "a", "value": 0},
            {"kind": "submittedTxId", "txId": 5, "value": False},
            {"kind": "submittedTxId", "txId": 99, "value": False},
        ]
        sequence = {
            "nodes": ["a"],
            "bootstrap": ["a"],
            "unknowns": ["x", "y"],
            "instructions": initial + [
                {"kind": "clientRequest", "node": "a", "transaction": {"unknown": "x"}},
                {"kind": "entry", "node": "a", "index": 0,
                 "value": {"term": 3, "content": {"transaction": 5}}},
                {"kind": "signCommittableMessages", "node": "a"},
                {"kind": "advanceCommitIndex", "node": "a"},
                {"kind": "commit", "node": "a", "value": 2},
                {"kind": "clientRequest", "node": "a", "transaction": {"unknown": "y"}},
                {"kind": "entry", "node": "a", "index": 2,
                 "value": {"term": 3, "content": {"transaction": 99}}},
                {"kind": "submittedTxId", "txId": 5, "value": True},
                {"kind": "submittedTxId", "txId": 99, "value": True},
            ],
        }
        duplicate = deepcopy(sequence)
        duplicate["instructions"][-4]["transaction"] = {"unknown": "x"}
        opaque = {
            "nodes": ["a"],
            "bootstrap": ["a"],
            "unknowns": ["5"],
            "instructions": deepcopy(initial) + [
                {"kind": "clientRequest", "node": "a", "transaction": {"unknown": "5"}},
                {"kind": "entry", "node": "a", "index": 0,
                 "value": {"term": 3, "content": {"transaction": 99}}},
            ],
        }
        opaque["instructions"][-4]["value"] = True
        literal = deepcopy(opaque)
        literal["instructions"][-2]["transaction"] = 5
        models.extend(
            [
                {"name": "parameters-across-core", "trace": sequence, "expected": "sat"},
                {"name": "shared-parameter-repeated", "trace": duplicate, "expected": "unsat"},
                {"name": "opaque-name-not-value", "trace": opaque, "expected": "sat"},
                {"name": "literal-already-submitted", "trace": literal, "expected": "unsat"},
            ]
        )
        self.assert_internal_model_traces(
            "NativeParameterizedFrameFixtureMain", models, 28, "parameterized-client"
        )

    def test_transaction_parameter_input_errors(self):
        valid = {
            "nodes": ["a"],
            "bootstrap": ["a"],
            "unknowns": ["x"],
            "instructions": [
                {"kind": "clientRequest", "node": "a", "transaction": {"unknown": "x"}}
            ],
        }
        documents = [valid]
        expected = [None]
        for value, message in (
            (-1, "negative"),
            (1.5, "decimal"),
            (True, "natural transaction"),
            ("x", "natural transaction"),
            (None, "natural transaction"),
            ({"unknown": "missing"}, "undeclared transaction"),
            ({"unknown": "x", "other": 0}, "expected fields"),
            ({"unknown": 1}, "String"),
        ):
            document = deepcopy(valid)
            document["instructions"][0]["transaction"] = value
            documents.append(document)
            expected.append(message)
        for unknowns, message in (
            (["x", "x"], "distinct"),
            ([""], "nonempty"),
            ([1], "String"),
            ("x", "array"),
            ([], "undeclared transaction"),
        ):
            document = deepcopy(valid)
            document["unknowns"] = unknowns
            documents.append(document)
            expected.append(message)
        missing = deepcopy(valid)
        del missing["unknowns"]
        documents.append(missing)
        expected.append("undeclared transaction")
        extra = deepcopy(valid)
        extra["extra"] = True
        documents.append(extra)
        expected.append("expected fields")
        result = subprocess.run(
            ["lake", "env", "lean", "--run",
             "Sparse/NativeParameterizedFrameFixtureMain.lean", "--decode"],
            cwd=ROOT, input=json.dumps(documents), capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        errors = json.loads(result.stdout)
        self.assertEqual(len(errors), len(expected))
        for index, (error, message) in enumerate(zip(errors, expected, strict=True)):
            with self.subTest(index=index):
                if message is None:
                    self.assertIsNone(error)
                else:
                    self.assertIsInstance(error, str)
                    self.assertIn(message.lower(), error.lower())

    def test_parameterized_core_encoding_unchanged(self):
        documents = [
            json.loads((ROOT / "Traces" / name).read_text(encoding="utf-8"))
            for name in (
                "native_vote_fifo_conflict.json",
                "native_commit_advancement_conflict.json",
                "native_become_leader_follower_conflict.json",
            )
        ]
        scripts = self.encode(documents)
        models = [
            {"trace": document, "expected": "unsat"}
            for document in documents
        ]
        models.extend(
            {"trace": {**document, "unknowns": []}, "expected": "unsat"}
            for document in documents
        )
        result = subprocess.run(
            ["lake", "env", "lean", "--run",
             "Sparse/NativeParameterizedFrameFixtureMain.lean"],
            cwd=ROOT, input=json.dumps(models), capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        fixtures = json.loads(result.stdout)
        self.assertEqual([item["script"] for item in fixtures], scripts + scripts)
        for fixture, model in zip(fixtures, models, strict=True):
            groups = fixture["groups"]
            self.assertEqual(
                [group["instruction"] for group in groups],
                [None, *range(len(model["trace"]["instructions"]))],
            )
            self.assertEqual(groups[0]["start"], 0)
            self.assertEqual(
                [group["stop"] for group in groups[:-1]],
                [group["start"] for group in groups[1:]],
            )

    def test_native_reduction_decodes_saved_captures(self):
        from native_reduction import native_document
        from raw_normalization import normalize
        from reduction import build_certificate
        from Shared.trace_io import read_ndjson

        paths = sorted((ROOT / "Traces/Captured").glob("*.ndjson"))
        paths += sorted((ROOT / "Traces/Mutated").glob("*.ndjson"))
        self.assertEqual(len(paths), 6)
        documents = []
        for path in paths:
            certificate = build_certificate(read_ndjson(path))
            documents.append(native_document(
                normalize(certificate, native_ids=True), [certificate["steps"][0]["node"]]
            ))
        result = subprocess.run(
            ["lake", "env", "lean", "--run",
             "Sparse/NativeParameterizedFrameFixtureMain.lean", "--decode"],
            cwd=ROOT, input=json.dumps(documents), capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        errors = json.loads(result.stdout)
        self.assertEqual(len(errors), len(paths))
        for path, error in zip(paths, errors, strict=True):
            self.assertIsNone(error, f"{path.name}: {error}")

    def test_configuration_callback_heartbeat_conflict(self):
        document = json.loads(
            (ROOT / "Traces/native_configuration_callback_heartbeat_conflict.json").read_text()
        )
        model_send = deepcopy(document)
        model_send["instructions"][-1]["batchEnd"] = 5
        scripts = self.encode([document, model_send])
        self.solve(
            [
                {"name": "configuration-callback-heartbeat", "script": scripts[0],
                 "expected": "unsat"},
                {"name": "configuration-model-send", "script": scripts[1],
                 "expected": "sat"},
            ]
        )

    def become_leader_traces(self):
        models = self.model_traces("NativeArrayBecomeLeaderFixtureMain", 202)
        named = {model["name"]: model for model in models}
        for name in (
            "empty-commit-7-votes-3",
            "allocation-0",
            "discard-configuration-commit-0-votes-5",
            "discard-terminal-commit-7-votes-3",
            "large-naturals",
        ):
            self.assertEqual(named[name]["expected"], "sat", name)
        for name in (
            "discard-configuration-commit-0-votes-3",
            "terminal-commit-7-votes-5",
            "membership-4",
        ):
            self.assertEqual(named[name]["expected"], "unsat", name)
        for model in models:
            if model["expected"] != "sat":
                continue
            before = model["trace"]["instructions"][: model["stepIndex"]]
            self.assertEqual(model["logLengthAfter"], model["latestSignature"])
            for kind, observed in (
                ("commit", "commitAfter"),
                ("newFollower", "newFollowerAfter"),
            ):
                expected = next(
                    item["value"]
                    for item in before
                    if item["kind"] == kind and item.get("node") == "a"
                )
                self.assertEqual(model[observed], expected, model["name"])
        for name in (
            "truncate-commit-7-votes-3",
            "retirement-completed-commit-7-votes-5",
        ):
            baseline = named[name]
            self.assertEqual(baseline["expected"], "sat", name)
            for index in range(
                baseline["stepIndex"] + 1, len(baseline["trace"]["instructions"])
            ):
                changed = deepcopy(baseline)
                changed["trace"]["instructions"][index] = self.mutate_frame_observation(
                    changed["trace"]["instructions"][index], changed["trace"]["nodes"]
                )
                changed["expected"] = "unsat"
                changed["name"] = f"{name}-changed-{index}"
                models.append(changed)
        names = [f"peer-{index}" for index in range(17)]
        source = names[-1]
        instructions = [
            {"kind": "allocated", "node": node, "value": node == source}
            for node in names
        ] + [
            {"kind": "role", "node": source, "value": "candidate"},
            {"kind": "membershipState", "node": source, "value": "active"},
            {"kind": "votesGranted", "node": source, "value": [names[0]]},
            {"kind": "commit", "node": source, "value": 10**30},
            {"kind": "newFollower", "node": source, "value": True},
            {"kind": "logLength", "node": source, "value": 3},
        ]
        instructions.extend(
            {
                "kind": "entry",
                "node": source,
                "index": index,
                "value": {"term": term, "content": content},
            }
            for index, (term, content) in enumerate(
                ((9, {"transaction": 99}), (0, "signature"), (10, {"transaction": 99}))
            )
        )
        instructions.extend(
            [
                {"kind": "becomeLeader", "node": source},
                {"kind": "role", "node": source, "value": "leader"},
                {"kind": "commit", "node": source, "value": 10**30},
                {"kind": "newFollower", "node": source, "value": True},
                {"kind": "logLength", "node": source, "value": 2},
            ]
        )
        instructions.extend(
            {"kind": kind, "node": source, "peer": peer, "value": value}
            for peer in names
            for kind, value in (("sentIndex", 2), ("matchIndex", 0))
        )
        wide = {
            "name": "become-leader-wide",
            "expected": "sat",
            "trace": {"nodes": names, "bootstrap": [names[0]], "instructions": instructions},
        }
        wrong = deepcopy(wide)
        wrong["expected"] = "unsat"
        wrong["name"] += "-wrong-cursor"
        wrong["trace"]["instructions"][-2]["value"] += 1
        tail = deepcopy(wide)
        tail["expected"] = "unsat"
        tail["name"] += "-truncated-entry"
        tail["trace"]["instructions"].append(
            {"kind": "entry", "node": source, "index": 2,
             "value": {"term": 10, "content": {"transaction": 99}}}
        )
        models.extend([wide, wrong, tail])
        return models

    def test_internal_become_leader(self):
        self.assert_internal_model_traces(
            "NativeBecomeLeaderFixtureMain",
            self.become_leader_traces(),
            58,
            "become-leader",
        )

    def become_leader_append_traces(self):
        baseline = next(
            model
            for model in self.model_traces("NativeArrayBecomeLeaderFixtureMain", 202)
            if model["name"] == "truncate-commit-7-votes-3"
        )
        document = deepcopy(baseline["trace"])
        document["instructions"].extend(
            [
                {"kind": "appendEntries", "source": "a", "destination": "b", "batchEnd": 2},
                {"kind": "queuePattern", "source": "a", "destination": "b", "index": 0,
                 "value": {"kind": "appendEntriesRequest", "term": 0,
                           "prevLogIndex": 2, "entriesLength": 0}},
                {"kind": "receiveAppendEntries", "source": "a", "destination": "b"},
                {"kind": "queuePattern", "source": "b", "destination": "a", "index": 0,
                 "value": {"kind": "appendEntriesResponse", "term": 31,
                           "success": False, "lastLogIndex": 3}},
                {"kind": "receiveAppendEntriesResponse", "source": "b", "destination": "a"},
                {"kind": "currentTerm", "node": "a", "value": 0},
                {"kind": "newFollower", "node": "a", "value": True},
                {"kind": "queueLength", "source": "c", "destination": "b", "value": 2},
                {"kind": "queueLength", "source": "b", "destination": "a", "value": 0},
                {"kind": "sentIndex", "node": "a", "peer": "b", "value": 2},
            ]
        )
        wrong = deepcopy(document)
        wrong["instructions"][-1]["value"] = 3
        return [
            {"name": "leader-append-nack", "trace": document, "expected": "sat"},
            {"name": "leader-append-nack-wrong-cursor", "trace": wrong, "expected": "unsat"},
        ]

    def test_internal_become_leader_append_sequence(self):
        self.assert_internal_model_traces(
            "NativeBecomeLeaderFixtureMain",
            self.become_leader_append_traces(),
            1,
            "become-leader-append",
        )

    def test_public_become_leader(self):
        models = self.become_leader_traces() + self.become_leader_append_traces()
        scripts = self.encode([model["trace"] for model in models])
        self.solve(
            [
                {"name": f"public-leader-{index}", "script": script,
                 "expected": model["expected"]}
                for index, (model, script) in enumerate(zip(models, scripts))
            ]
        )

    def test_become_leader_input_errors(self):
        self.assert_unary_action_input_errors("becomeLeader")

    def test_become_leader_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_become_leader_follower_conflict.json", {1, 2, 3}
        )

    def test_public_vote_responses(self):
        models = self.vote_response_traces()
        scripts = self.encode([model["trace"] for model in models])
        self.solve(
            [
                {
                    "name": f"public-vote-response-{index}",
                    "script": script,
                    "expected": model["expected"],
                }
                for index, (model, script) in enumerate(zip(models, scripts))
            ]
        )

    def test_public_append_responses(self):
        models = self.append_response_traces()
        scripts = self.encode([model["trace"] for model in models])
        self.solve(
            [
                {
                    "name": f"public-append-response-{index}",
                    "script": script,
                    "expected": model["expected"],
                }
                for index, (model, script) in enumerate(zip(models, scripts))
            ]
        )

    def test_response_receive_input_errors(self):
        invalid = []
        for kind in (
            "receiveRequestVoteResponse",
            "receiveRequestPreVoteResponse",
            "receiveAppendEntriesResponse",
        ):
            valid = {"kind": kind, "source": "a", "destination": "b"}
            invalid.extend(
                {key: value for key, value in valid.items() if key != missing}
                for missing in valid
            )
            invalid.extend(
                dict(valid, **{field: value})
                for field in ("source", "destination")
                for value in ("missing", None, False, 0, 1.5, [], {})
            )
            invalid.extend(
                dict(valid, **{field: value})
                for field, value in (("node", "a"), ("value", True), ("preVote", True))
            )
        self.assert_invalid_instructions(invalid)

    def test_vote_response_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_vote_response_tally_conflict.json", set(range(6))
        )

    def test_append_response_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_append_response_match_conflict.json", set(range(6))
        )

    def vote_request_response_traces(self):
        document = json.loads(
            (ROOT / "Traces/native_vote_receive_fifo_conflict.json").read_text()
        )
        document["instructions"][-1]["value"] = 2
        document["instructions"].insert(
            0, {"kind": "votesGranted", "node": "a", "value": []}
        )
        for remaining in (1, 0):
            document["instructions"].extend(
                [
                    {
                        "kind": "receiveRequestVoteResponse",
                        "source": "b",
                        "destination": "a",
                    },
                    {"kind": "votesGranted", "node": "a", "value": ["b"]},
                    {
                        "kind": "queueLength",
                        "source": "b",
                        "destination": "a",
                        "value": remaining,
                    },
                ]
            )
        wrong_tally = deepcopy(document)
        wrong_tally["instructions"][-2]["value"] = []
        empty = deepcopy(document)
        empty["instructions"].append(
            {"kind": "receiveRequestVoteResponse", "source": "b", "destination": "a"}
        )
        variants = [
            ("vote-round-trip-duplicates", document, "sat"),
            ("vote-round-trip-missing-vote", wrong_tally, "unsat"),
            ("vote-round-trip-empty", empty, "unsat"),
        ]
        return [
            {"name": name, "trace": trace, "expected": expected}
            for name, trace, expected in variants
        ]

    def test_internal_vote_request_response_sequence(self):
        self.assert_internal_model_traces(
            "NativeReceiveVoteResponseFixtureMain",
            self.vote_request_response_traces(),
            1,
            "vote-round-trip",
        )

    def test_vote_request_response_sequence(self):
        models = self.vote_request_response_traces()
        scripts = self.encode([model["trace"] for model in models])
        self.solve(
            [
                {
                    "name": model["name"],
                    "script": script,
                    "expected": model["expected"],
                }
                for model, script in zip(models, scripts)
            ]
        )

    def test_append_receive_model_fixture_coverage(self):
        fixtures = self.model_traces("NativeArrayAppendReceiveFixtureMain", 1344)
        self.assertEqual(
            Counter(fixture["branch"] for fixture in fixtures),
            {
                "alreadyDone": 48,
                "blocked": 514,
                "conflict": 8,
                "empty": 30,
                "extension": 8,
                "reject": 402,
                "stepdown": 202,
                "unallocated": 72,
                "wrongDestination": 30,
                "wrongKind": 30,
            },
        )
        self.assertEqual(
            Counter(
                fixture["branch"]
                for fixture in fixtures
                if fixture["expected"] == "sat"
            ),
            {
                "alreadyDone": 24,
                "conflict": 4,
                "extension": 4,
                "reject": 201,
                "stepdown": 101,
            },
        )
        self.assertTrue(
            any(
                fixture["modelEnabled"] and not fixture["selectedAppendRequest"]
                for fixture in fixtures
            )
        )

    def model_traces(self, module, count, *arguments):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                f"Sparse/{module}.lean",
                *arguments,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), count)
        self.assertEqual(
            {fixture["expected"] for fixture in fixtures}, {"sat", "unsat"}
        )
        return fixtures

    def test_relocated_columns(self):
        wanted = {
            "checkQuorum",
            "requestVote",
            "requestPreVote",
            "updateTerm",
            "timeout",
            "becomePreVoteCandidate",
            "appendEntries",
            "receiveRequestVote",
        }
        selected = {}
        entry_trace = None
        for module, count, arguments in (
            ("NativeArrayCheckQuorumFixtureMain", 150, []),
            ("NativeArrayVoteFixtureMain", 400, []),
            ("NativeArrayVoteFixtureMain", 400, ["campaign"]),
            ("NativeArrayTermFixtureMain", 168, []),
            ("NativeArrayAppendFixtureMain", 1200, []),
            ("NativeArrayVoteReceiveFixtureMain", 480, []),
        ):
            for fixture in self.model_traces(module, count, *arguments):
                if fixture["expected"] != "sat":
                    continue
                trace = fixture["trace"]
                for instruction in trace["instructions"]:
                    if instruction["kind"] in wanted:
                        selected.setdefault(instruction["kind"], trace)
                    if instruction["kind"] == "entry" and entry_trace is None:
                        entry_trace = trace
        self.assertEqual(set(selected), wanted)
        documents = list(selected.values())
        self.assertIsNotNone(entry_trace)
        if entry_trace not in documents:
            documents.append(entry_trace)
        combined = deepcopy(selected["appendEntries"])
        combined["instructions"] = []
        for document in documents:
            self.assertEqual(document["nodes"], combined["nodes"])
            combined["instructions"].extend(document["instructions"])
        documents.append(combined)
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeRelocatedColumnsFixtureMain.lean",
            ],
            cwd=ROOT,
            input=json.dumps(documents),
            capture_output=True,
            text=True,
            check=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(
            {item["field"] for item in report["rejectedReferences"]},
            {"allocated", "logLength", "commit", "logEntries"},
        )
        self.assertEqual(len(report["rejectedReferences"]), 4)
        for item in report["rejectedReferences"]:
            self.assertEqual(
                item["error"],
                "internal encoder error: assertion references an unallocated SMT symbol",
            )
        results = report["fixtures"]
        self.assertEqual(len(results), len(documents))
        for index, fixture in enumerate(results):
            self.assertEqual(
                [item["offset"] for item in fixture["relocated"]], [24, 1000]
            )
            for relocated in fixture["relocated"]:
                with self.subTest(trace=index, offset=relocated["offset"]):
                    renames = dict(relocated["renames"])
                    expected = [
                        re.sub(
                            r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                            lambda match, names=renames: names.get(match[0], match[0]),
                            clause,
                        )
                        for clause in fixture["clauses"]
                    ]
                    self.assertEqual(relocated["clauses"], expected)
                    self.assertEqual(
                        relocated["next"], fixture["next"] + relocated["offset"]
                    )

    def test_membership_model_fixture_coverage(self):
        fixtures = self.model_traces("NativeArrayMembershipFixtureMain", 1572)
        self.assertEqual(sum(fixture["expected"] == "sat" for fixture in fixtures), 147)
        for mutation in (
            "peerTerm",
            "peerRole",
            "peerLog",
            "peerCommit",
            "peerVote",
            "peerCursor",
            "peerRetirement",
            "hasJoined",
            "completed",
            "queue",
        ):
            with self.subTest(mutation=mutation):
                cases = [
                    fixture
                    for fixture in fixtures
                    if fixture["mutation"].endswith(f".{mutation}")
                ]
                self.assertEqual(len(cases), 2)
                self.assertEqual(
                    {fixture["peerInitiallyAllocated"] for fixture in cases},
                    {False, True},
                )
                self.assertTrue(all(fixture["modelEnabled"] for fixture in cases))
                self.assertTrue(
                    all(fixture["expected"] == "unsat" for fixture in cases)
                )

    def assert_model_traces(self, module, count, prefix):
        fixtures = self.model_traces(module, count)
        scripts = self.encode([fixture["trace"] for fixture in fixtures])
        self.solve(
            [
                {
                    "name": f"{prefix}-{index}",
                    "script": script,
                    "expected": fixture["expected"],
                }
                for index, (fixture, script) in enumerate(zip(fixtures, scripts))
            ]
        )
        return fixtures

    def test_append_send_input_errors(self):
        valid = {
            "kind": "appendEntries",
            "source": "a",
            "destination": "b",
            "batchEnd": 1,
        }
        invalid = [
            {key: value for key, value in valid.items() if key != missing}
            for missing in ("source", "destination", "batchEnd")
        ]
        invalid.extend(
            dict(valid, batchEnd=value) for value in (-1, True, 1.5, "1", None, [])
        )
        invalid.extend(
            [
                dict(valid, source="missing"),
                dict(valid, destination="missing"),
                dict(valid, source=0),
                dict(valid, destination=False),
                dict(valid, value=True),
                {"kind": "receive", "source": "a", "destination": "b"},
            ]
        )
        self.assert_invalid_instructions(invalid)

    def test_append_receive_input_errors(self):
        valid = {
            "kind": "receiveAppendEntries",
            "source": "a",
            "destination": "a",
        }
        invalid = [
            {key: value for key, value in valid.items() if key != missing}
            for missing in ("source", "destination")
        ]
        invalid.extend(
            [
                dict(valid, source="missing"),
                dict(valid, destination="missing"),
                dict(valid, source=0),
                dict(valid, destination=False),
                dict(valid, value=True),
                {"kind": "receive", "source": "a", "destination": "a"},
            ]
        )
        self.assert_invalid_instructions(invalid)

    def test_membership_change_input_errors(self):
        valid = {
            "kind": "changeConfiguration",
            "source": "a",
            "configuration": ["a"],
        }
        invalid = [
            {key: value for key, value in valid.items() if key != missing}
            for missing in ("source", "configuration")
        ]
        invalid.extend(
            dict(valid, configuration=value)
            for value in (
                None, False, 0, 1.5, "a", {"a": True}, ["missing"], [0], [True]
            )
        )
        invalid.extend(
            [
                dict(valid, source="missing"),
                dict(valid, source=0),
                dict(valid, source=False),
                dict(valid, node="a"),
                dict(valid, value=True),
            ]
        )
        self.assert_invalid_instructions(invalid)

    def test_membership_change_configuration_sets(self):
        scripts = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a"],
                    "instructions": [
                        {
                            "kind": "changeConfiguration",
                            "source": "a",
                            "configuration": configuration,
                        }
                    ],
                }
                for configuration in (["a", "b"], ["b", "a"], ["b", "a", "a"], [])
            ]
        )
        self.assertEqual(scripts[1:3], [scripts[0], scripts[0]])
        self.solve(
            [{"name": "empty-membership-change", "script": scripts[3], "expected": "unsat"}]
        )

    def test_advance_commit_input_errors(self):
        self.assert_unary_action_input_errors("advanceCommitIndex")

    def test_signature_input_errors(self):
        self.assert_unary_action_input_errors("signCommittableMessages")

    def assert_unary_action_input_errors(self, kind):
        valid = {"kind": kind, "node": "a"}
        invalid = [
            {"kind": kind},
            {"kind": kind, "source": "a"},
            dict(valid, source="a"),
            dict(valid, value=1),
        ]
        invalid.extend(
            dict(valid, node=value)
            for value in ("missing", None, False, 0, 1.5, [], {})
        )
        self.assert_invalid_instructions(invalid)

    def test_advance_commit_send_sequence(self):
        document = json.loads(
            (ROOT / "Traces/native_commit_advancement_conflict.json").read_text()
        )
        document["instructions"][-1]["value"] = 1
        document["instructions"][:0] = [
            {"kind": "allocated", "node": "b", "value": True},
            {"kind": "sentIndex", "node": "a", "peer": "b", "value": 0},
            {
                "kind": "queueLength",
                "source": "a",
                "destination": "b",
                "value": 0,
            },
        ]
        packet = {
            "kind": "appendEntriesRequest",
            "source": "a",
            "destination": "b",
            "term": 1,
            "prevLogIndex": 0,
            "prevLogTerm": 0,
            "leaderCommit": 1,
            "entries": [{"term": 1, "content": "signature"}],
        }
        for index in range(3):
            document["instructions"].append(
                {
                    "kind": "appendEntries",
                    "source": "a",
                    "destination": "b",
                    "batchEnd": 1,
                }
            )
            expected = (
                packet
                if index == 0
                else dict(packet, prevLogIndex=1, prevLogTerm=1, entries=[])
            )
            document["instructions"].append(
                packet_observation(expected, index=index)
            )
        document["instructions"].append(
            {
                "kind": "queueLength",
                "source": "a",
                "destination": "b",
                "value": 3,
            }
        )
        variants = [("commit-then-append-and-heartbeats", document, "sat")]
        wrong = deepcopy(document)
        wrong["instructions"][-2]["value"]["leaderCommit"] = 0
        variants.append(("heartbeat-uses-stale-commit", wrong, "unsat"))
        repeated = deepcopy(document)
        repeated["instructions"].append(
            {"kind": "advanceCommitIndex", "node": "a"}
        )
        variants.append(("commit-without-new-signature", repeated, "unsat"))
        wide = deepcopy(document)
        extras = [f"spare-{index}" for index in range(2, 17)]
        wide["nodes"].extend(extras)
        absent = [
            {"kind": "allocated", "node": node, "value": False} for node in extras
        ]
        wide["instructions"] = absent + wide["instructions"] + absent
        variants.append(("seventeen-node-commit-and-send", wide, "sat"))
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(
                    variants, self.encode([trace for _, trace, _ in variants])
                )
            ]
        )

    def test_append_cursor_and_duplicate_heartbeats(self):
        document = json.loads(
            (ROOT / "Traces/native_append_fifo_conflict.json").read_text()
        )
        document["instructions"][-1]["value"] = 4
        packet = {
            "kind": "appendEntriesRequest",
            "source": "a",
            "destination": "b",
            "term": 4,
            "leaderCommit": 0,
        }
        packets = [
            dict(
                packet,
                prevLogIndex=0,
                prevLogTerm=0,
                entries=[{"term": 8, "content": "signature"}],
            ),
            dict(
                packet,
                prevLogIndex=1,
                prevLogTerm=8,
                entries=[{"term": 2, "content": {"transaction": 99}}],
            ),
            dict(packet, prevLogIndex=2, prevLogTerm=2, entries=[]),
            dict(packet, prevLogIndex=2, prevLogTerm=2, entries=[]),
        ]
        document["instructions"].extend(
            {
                "kind": "queuePoint",
                "source": "a",
                "destination": "b",
                "index": index,
                "value": value,
            }
            for index, value in enumerate(packets)
        )
        variants = [("append-cursor-and-heartbeats", document, "sat")]
        larger = deepcopy(document)
        larger["nodes"] += [f"node-{index}" for index in range(2, 21)]
        variants.append(("twenty-one-node-append", larger, "sat"))
        mixed = deepcopy(document)
        mixed["instructions"].extend(
            [
                {"kind": "role", "node": "b", "value": "candidate"},
                {"kind": "logLength", "node": "b", "value": 0},
                {"kind": "commit", "node": "b", "value": 0},
                {"kind": "currentTerm", "node": "b", "value": 9},
                {
                    "kind": "queueLength",
                    "source": "b",
                    "destination": "a",
                    "value": 0,
                },
                {"kind": "requestVote", "source": "b", "destination": "a"},
                {"kind": "updateTerm", "source": "b", "destination": "a"},
                {"kind": "role", "node": "a", "value": "follower"},
                {"kind": "currentTerm", "node": "a", "value": 9},
                {"kind": "sentIndex", "node": "a", "peer": "b", "value": 2},
            ]
        )
        mixed["instructions"].extend(
            deepcopy(instruction)
            for instruction in document["instructions"]
            if instruction["kind"] == "queuePoint"
        )
        variants.append(("append-vote-and-term-update", mixed, "sat"))
        disabled = deepcopy(mixed)
        disabled["instructions"].append(
            {
                "kind": "appendEntries",
                "source": "a",
                "destination": "b",
                "batchEnd": 2,
            }
        )
        variants.append(("append-disabled-after-term-update", disabled, "unsat"))
        for index, instruction in enumerate(document["instructions"]):
            if instruction["kind"] == "appendEntries":
                bad = deepcopy(document)
                bad["instructions"][index]["batchEnd"] += 1
                variants.append((f"append-bad-frontier-{index}", bad, "unsat"))
            elif instruction["kind"] == "queuePoint":
                bad = deepcopy(document)
                bad["instructions"][index]["value"]["prevLogIndex"] += 1
                variants.append((f"append-bad-packet-{index}", bad, "unsat"))
        scripts = self.encode([trace for _, trace, _ in variants])
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(variants, scripts)
            ]
        )

    def test_peer_action_input_errors(self):
        invalid = []
        for kind in (
            "requestVote",
            "requestPreVote",
            "updateTerm",
            "receiveRequestVote",
        ):
            valid = {"kind": kind, "source": "a", "destination": "b"}
            invalid.extend(
                [
                    {key: value for key, value in valid.items() if key != "source"},
                    {
                        key: value
                        for key, value in valid.items()
                        if key != "destination"
                    },
                    dict(valid, source="missing"),
                    dict(valid, destination="missing"),
                    dict(valid, source=0),
                    dict(valid, destination=False),
                    dict(valid, value=True),
                ]
            )
        self.assert_invalid_instructions(invalid)

    def test_vote_send_explorer_core(self):
        self.assert_explorer_core("Traces/native_vote_fifo_conflict.json", {7, 8, 9})

    def test_append_send_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_append_fifo_conflict.json", {11, 12, 13, 14, 16}
        )

    def test_vote_receive_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_vote_receive_fifo_conflict.json", {14, 15, 18}
        )

    def test_append_receive_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_append_receive_fifo_conflict.json", {8, 9}
        )

    def test_membership_change_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_membership_allocation_conflict.json", {8, 9}
        )

    def test_advance_commit_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_commit_advancement_conflict.json", {7, 8}
        )

    def test_signature_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_signature_append_conflict.json", {7, 8}
        )

    def test_core_explorer_fixture_transitions(self):
        for trace, module, corrected in (
            (
                "native_append_receive_fifo_conflict",
                "NativeAppendReceiveFixtureMain",
                1,
            ),
            (
                "native_membership_allocation_conflict",
                "NativeMembershipChangeFixtureMain",
                True,
            ),
            (
                "native_commit_advancement_conflict",
                "NativeAdvanceCommitFixtureMain",
                1,
            ),
            (
                "native_signature_append_conflict",
                "NativeSignCommittableFixtureMain",
                2,
            ),
            (
                "native_vote_response_tally_conflict",
                "NativeReceiveVoteResponseFixtureMain",
                ["a"],
            ),
            (
                "native_append_response_match_conflict",
                "NativeReceiveAppendResponseFixtureMain",
                7,
            ),
            (
                "native_become_leader_follower_conflict",
                "NativeBecomeLeaderFixtureMain",
                True,
            ),
        ):
            with self.subTest(trace=trace):
                conflict = json.loads(
                    (ROOT / "Traces" / f"{trace}.json").read_text()
                )
                fixed = deepcopy(conflict)
                fixed["instructions"][-1]["value"] = corrected
                self.assert_internal_model_traces(
                    module,
                    [
                        {"trace": conflict, "expected": "unsat"},
                        {"trace": fixed, "expected": "sat"},
                    ],
                    1,
                    trace,
                )

    def test_vote_receive_send_sequence(self):
        document = json.loads(
            (ROOT / "Traces/native_vote_receive_fifo_conflict.json").read_text()
        )
        document["instructions"][-1]["value"] = 2
        document["instructions"].extend(
            {
                "kind": "queuePoint",
                "source": "b",
                "destination": "a",
                "index": index,
                "value": {
                    "kind": "requestVoteResponse",
                    "source": "b",
                    "destination": "a",
                    "term": 4,
                    "voteGranted": True,
                },
            }
            for index in range(2)
        )
        variants = [("vote-send-receive-duplicates", document, "sat")]
        larger = deepcopy(document)
        larger["nodes"] += [f"node-{index}" for index in range(2, 21)]
        variants.append(("twenty-one-node-vote-receive", larger, "sat"))
        for index in range(2):
            wrong = deepcopy(document)
            wrong["instructions"][-2 + index]["value"]["voteGranted"] = False
            variants.append((f"vote-receive-wrong-grant-{index}", wrong, "unsat"))
        remaining = deepcopy(document)
        remaining["instructions"][16]["value"] = 1
        variants.append(("vote-receive-wrong-remaining", remaining, "unsat"))
        empty = deepcopy(document)
        empty["instructions"].append(
            {"kind": "receiveRequestVote", "source": "a", "destination": "b"}
        )
        variants.append(("vote-receive-empty-after-consumption", empty, "unsat"))
        stale = deepcopy(document)
        stale["nodes"].append("c")
        stale["instructions"][14:14] = [
            {"kind": "queueLength", "source": "c", "destination": "b", "value": 1},
            {
                "kind": "queuePoint",
                "source": "c",
                "destination": "b",
                "index": 0,
                "value": {
                    "kind": "proposeVoteRequest",
                    "source": "c",
                    "destination": "b",
                    "term": 9,
                },
            },
            {"kind": "updateTerm", "source": "c", "destination": "b"},
        ]
        stale["instructions"][20]["value"] = None
        for instruction in stale["instructions"][-2:]:
            instruction["value"].update(term=9, voteGranted=False)
        variants.append(("vote-receive-stale-after-update", stale, "sat"))
        scripts = self.encode([trace for _, trace, _ in variants])
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(variants, scripts)
            ]
        )

    def assert_explorer_core(self, trace, required):
        requested = os.environ.get("Z3")
        solver = find_z3(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="native-vote-core-") as temporary:
            output = Path(temporary)
            result = subprocess.run(
                [
                    sys.executable,
                    "native_lean.py",
                    trace,
                    "--output-dir",
                    str(output),
                    "--z3",
                    str(solver),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(json.loads(result.stdout)["status"], "unsat")
            api = ExplorerApi(NativeRun.load(output))
            run = api.get("/api/run")
            self.assertEqual(
                run["instruction_count"],
                len(json.loads((ROOT / trace).read_text())["instructions"]),
            )
            self.assertEqual(
                run["result"]["assurance"],
                {"full_model_to_script_proved": False, "raw_reducer_integrated": False},
            )
            core = api.get("/api/core")
            self.assertTrue(required.issubset(core["instructions"]))
            self.assertFalse(core["minimal"])

    def test_history_and_arbitrary_size(self):
        names = [f"node-{index}" for index in range(21)]
        initial = [
            {"kind": "role", "node": names[0], "value": "leader"},
            {"kind": "logLength", "node": names[0], "value": 0},
            {"kind": "checkQuorum", "node": names[0]},
            {"kind": "role", "node": names[0], "value": "follower"},
            {"kind": "newFollower", "node": names[0], "value": True},
        ]
        cases = [
            ("twenty-one-node-quorum", initial, "sat"),
            (
                "quorum-preserves-history",
                initial + [{"kind": "checkQuorum", "node": names[0]}],
                "unsat",
            ),
            (
                "trillion-entry-log",
                [{"kind": "logLength", "node": names[0], "value": 10**12}],
                "sat",
            ),
        ]
        documents = [
            {
                "nodes": names,
                "bootstrap": [names[0], names[-1]],
                "instructions": instructions,
            }
            for _, instructions, _ in cases
        ]
        scripts = self.encode(documents)
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )
        self.assertLess(len(scripts[-1]), 100_000)

    def test_typed_observation_values(self):
        cases = []
        roles = ["none", "follower", "preVoteCandidate", "candidate", "leader"]
        for index, role in enumerate(roles):
            observed = {"kind": "role", "node": "a", "value": role}
            cases.append((f"role-{role}", [observed], "sat"))
            cases.append(
                (
                    f"role-{role}-conflict",
                    [
                        observed,
                        {
                            "kind": "role",
                            "node": "a",
                            "value": roles[(index + 1) % len(roles)],
                        },
                    ],
                    "unsat",
                )
            )
        contents = [
            "signature",
            {"transaction": 10**30},
            {"reconfiguration": ["a", "b"]},
            {"retiredCommitted": ["b"]},
        ]
        for index, content in enumerate(contents):
            observed = {
                "kind": "entry",
                "node": "a",
                "index": 0,
                "value": {"term": 10**30, "content": content},
            }
            cases.append((f"entry-variant-{index}", [observed], "sat"))
            other = dict(
                observed,
                value={
                    "term": 10**30,
                    "content": contents[(index + 1) % len(contents)],
                },
            )
            cases.append(
                (f"entry-variant-{index}-conflict", [observed, other], "unsat")
            )
        cases.append(
            (
                "configuration-members-ignore-order-and-duplicates",
                [
                    {
                        "kind": "entry",
                        "node": "a",
                        "index": 0,
                        "value": {"term": 0, "content": {"reconfiguration": members}},
                    }
                    for members in (["a", "b"], ["b", "a", "b"])
                ],
                "sat",
            )
        )
        scripts = self.encode(
            [
                {"nodes": ["a", "b"], "bootstrap": ["a"], "instructions": instructions}
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def framed_observation_cases(
        self, kind, default, value, other, *, allocation_guarded=True
    ):
        """Cases for quorum framing and allocation-dependent or global fields."""

        def observed(value):
            return {"kind": kind, "node": "a", "value": value}

        quorum = {"kind": "checkQuorum", "node": "a"}
        absent = {"kind": "allocated", "node": "a", "value": False}
        cases = [
            ("default", [observed(default)], "sat"),
            ("value", [observed(value)], "sat"),
            ("absent-node", [absent, observed(default)], "sat"),
            (
                "requires-node" if allocation_guarded else "unallocated-value",
                [absent, observed(value)],
                "unsat" if allocation_guarded else "sat",
            ),
            ("default-conflict", [observed(default), observed(value)], "unsat"),
            ("value-conflict", [observed(value), observed(other)], "unsat"),
            ("quorum-frame", [observed(value), quorum, observed(value)], "sat"),
            (
                "quorum-conflict",
                [observed(value), quorum, observed(default)],
                "unsat",
            ),
        ]
        return [
            (f"{kind}-{name}", instructions, expected)
            for name, instructions, expected in cases
        ]

    def test_retirement_index_observations(self):
        cases = [
            case
            for kind in RETIREMENT_FIELDS
            for case in self.framed_observation_cases(kind, None, 0, 10**30)
        ]
        cases.extend(
            (
                f"{kind}-beyond-log",
                [
                    {"kind": "logLength", "node": "a", "value": 0},
                    {"kind": kind, "node": "a", "value": 10**30},
                ],
                "sat",
            )
            for kind in RETIREMENT_FIELDS
        )
        independent = [
            {"kind": kind, "node": "a", "value": index}
            for index, kind in enumerate(RETIREMENT_FIELDS)
        ]
        cases.append(
            (
                "independent-retirement-fields",
                independent + [{"kind": "checkQuorum", "node": "a"}] + independent,
                "sat",
            )
        )
        scripts = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_voted_for_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = self.framed_observation_cases("votedFor", None, names[-1], "a")
        cases.extend(
            [
                (
                    "votedFor-self",
                    [{"kind": "votedFor", "node": "a", "value": "a"}],
                    "sat",
                ),
                (
                    "votedFor-absent-target-outside-bootstrap",
                    [
                        {"kind": "allocated", "node": names[-1], "value": False},
                        {"kind": "votedFor", "node": "a", "value": names[-1]},
                    ],
                    "sat",
                ),
            ]
        )
        scripts = self.encode(
            [
                {
                    "nodes": names,
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_vote_set_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = []
        for kind in VOTE_SET_FIELDS:
            cases.extend(self.framed_observation_cases(kind, [], [names[-1]], ["a"]))
            cases.extend(
                [
                    (
                        f"{kind}-order-and-duplicates",
                        [
                            {"kind": kind, "node": "a", "value": members}
                            for members in (
                                ["a", names[-1]],
                                [names[-1], "a", names[-1]],
                            )
                        ],
                        "sat",
                    ),
                    (
                        f"{kind}-absent-voter-outside-bootstrap",
                        [
                            {"kind": "allocated", "node": names[-1], "value": False},
                            {"kind": kind, "node": "a", "value": [names[-1]]},
                        ],
                        "sat",
                    ),
                ]
            )
        scripts = self.encode(
            [
                {
                    "nodes": names,
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_vote_set_independence(self):
        observed = [
            {"kind": "votesGranted", "node": "a", "value": ["a"]},
            {"kind": "preVotesGranted", "node": "a", "value": ["b"]},
        ]
        script = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a", "b"],
                    "instructions": observed
                    + [{"kind": "checkQuorum", "node": "a"}]
                    + observed,
                }
            ]
        )[0]
        self.solve(
            [{"name": "independent-vote-sets", "script": script, "expected": "sat"}]
        )

    def test_membership_observations(self):
        def observed(value):
            return {"kind": "membershipState", "node": "a", "value": value}

        quorum = {"kind": "checkQuorum", "node": "a"}
        cases = self.framed_observation_cases(
            "membershipState", "active", "retirementOrdered", "retiredCommitted"
        )
        for index, state in enumerate(MEMBERSHIP_STATES):
            cases.extend(
                [
                    (f"membership-{state}", [observed(state)], "sat"),
                    (
                        f"membership-{state}-conflict",
                        [
                            observed(state),
                            observed(
                                MEMBERSHIP_STATES[(index + 1) % len(MEMBERSHIP_STATES)]
                            ),
                        ],
                        "unsat",
                    ),
                    (
                        f"membership-{state}-frame",
                        [observed(state), quorum, observed(state)],
                        "sat",
                    ),
                    (
                        f"membership-{state}-absent",
                        [
                            {"kind": "allocated", "node": "a", "value": False},
                            observed(state),
                        ],
                        "sat" if state == "active" else "unsat",
                    ),
                ]
            )
        cases.append(
            (
                "membership-does-not-infer-retirement-indices",
                [observed("retiredCommitted")]
                + [
                    {"kind": kind, "node": "a", "value": None}
                    for kind in RETIREMENT_FIELDS
                ],
                "sat",
            )
        )
        scripts = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_peer_index_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = []
        for kind in PEER_INDEX_FIELDS:
            cases.extend(
                (
                    name,
                    [
                        dict(item, peer=names[-1]) if item["kind"] == kind else item
                        for item in instructions
                    ],
                    expected,
                )
                for name, instructions, expected in self.framed_observation_cases(
                    kind, 0, 10**30, 7
                )
            )
            cases.extend(
                [
                    (
                        f"{kind}-beyond-log",
                        [
                            {"kind": "logLength", "node": "a", "value": 0},
                            {
                                "kind": kind,
                                "node": "a",
                                "peer": names[-1],
                                "value": 10**30,
                            },
                        ],
                        "sat",
                    ),
                    (
                        f"{kind}-absent-peer",
                        [
                            {"kind": "allocated", "node": names[-1], "value": False},
                            {
                                "kind": kind,
                                "node": "a",
                                "peer": names[-1],
                                "value": 42,
                            },
                        ],
                        "sat",
                    ),
                    (
                        f"{kind}-independent-cells",
                        [
                            {"kind": kind, "node": "a", "peer": "a", "value": 1},
                            {"kind": kind, "node": "a", "peer": "b", "value": 2},
                            {"kind": kind, "node": "b", "peer": "a", "value": 3},
                        ],
                        "sat",
                    ),
                ]
            )
        scripts = self.encode(
            [
                {
                    "nodes": names,
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_complete_local_state_frame(self):
        values = {
            "allocated": True,
            "role": "leader",
            "newFollower": False,
            "logLength": 1,
            "commit": 9,
            "currentTerm": 3,
            "retirementIndex": None,
            "retirementCommittableIndex": 0,
            "retiredCommittedIndex": 10**30,
            "votedFor": "b",
            "votesGranted": ["a"],
            "preVotesGranted": ["b"],
            "membershipState": "retirementSigned",
        }
        observed = [
            {"kind": kind, "node": "a", "value": value}
            for kind, value in values.items()
        ] + [
            {
                "kind": "entry",
                "node": "a",
                "index": 0,
                "value": {"term": 10**30, "content": {"transaction": 42}},
            },
            {"kind": "sentIndex", "node": "a", "peer": "b", "value": 10**30},
            {"kind": "matchIndex", "node": "a", "peer": "b", "value": 3},
        ]
        after = [
            (
                dict(item, value="follower")
                if item["kind"] == "role"
                else dict(item, value=True) if item["kind"] == "newFollower" else item
            )
            for item in observed
        ]
        script = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a", "b"],
                    "instructions": observed
                    + [{"kind": "checkQuorum", "node": "a"}]
                    + after,
                }
            ]
        )[0]
        self.solve(
            [
                {
                    "name": "complete-local-state-frame",
                    "script": script,
                    "expected": "sat",
                }
            ]
        )

    def test_joined_set_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]

        def observed(value):
            return {"kind": "hasJoined", "value": value}

        quorum = {"kind": "checkQuorum", "node": "a"}
        cases = [
            ("joined-empty", [observed([])], "sat"),
            ("joined-all-identities", [observed(names)], "sat"),
            (
                "joined-order-and-duplicates",
                [observed(["a", names[-1]]), observed([names[-1], "a", "a"])],
                "sat",
            ),
            ("joined-empty-conflict", [observed([]), observed(["a"])], "unsat"),
            ("joined-value-conflict", [observed(["a"]), observed(["b"])], "unsat"),
            (
                "joined-independent-of-allocation",
                [{"kind": "allocated", "node": name, "value": False} for name in names]
                + [observed(names)],
                "sat",
            ),
            ("joined-empty-quorum-frame", [observed([]), quorum, observed([])], "sat"),
            ("joined-quorum-frame", [observed(["a"]), quorum, observed(["a"])], "sat"),
            (
                "joined-quorum-conflict",
                [observed(["a"]), quorum, observed(["b"])],
                "unsat",
            ),
        ]
        scripts = self.encode(
            [
                {
                    "nodes": names,
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_joined_node_observations(self):
        cases = self.framed_observation_cases(
            "joined", False, True, False, allocation_guarded=False
        )
        for joined in ([], ["a"], ["b"], ["a", "b"], ["b", "a", "a"], ["c"]):
            for node in ("a", "b"):
                for value in (False, True):
                    cases.append(
                        (
                            f"joined-node-{len(cases)}",
                            [
                                {"kind": "joined", "node": node, "value": value},
                                {"kind": "hasJoined", "value": joined},
                            ],
                            "sat" if (node in joined) == value else "unsat",
                        )
                    )
        documents = [
            {
                "nodes": ["a", "b", "c"],
                "bootstrap": ["a"],
                "instructions": instructions,
            }
            for _, instructions, _ in cases
        ]
        for width in (1, 3, 17, 65):
            names = [f"node-{index}" for index in range(width)]
            node = names[-1]
            for value in (False, True):
                for agrees in (False, True):
                    instructions = [
                        {"kind": "allocated", "node": name, "value": False}
                        for name in names
                    ] + [
                        {"kind": "joined", "node": node, "value": value},
                        {
                            "kind": "hasJoined",
                            "value": [node] if value == agrees else [],
                        },
                    ]
                    cases.append(
                        (
                            f"joined-node-{width}-{value}-{agrees}",
                            instructions,
                            "sat" if agrees else "unsat",
                        )
                    )
                    documents.append(
                        {
                            "nodes": names,
                            "bootstrap": [names[0]],
                            "instructions": instructions,
                        }
                    )
        scripts = self.encode(documents)
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_joined_node_input_errors(self):
        valid = {"kind": "joined", "node": "a", "value": True}
        invalid = [
            {key: value for key, value in valid.items() if key != missing}
            for missing in valid
        ]
        invalid.append(dict(valid, unexpected=0))
        invalid.extend(
            dict(valid, node=value) for value in ("missing", None, 0, [], {})
        )
        invalid.extend(
            dict(valid, value=value) for value in (None, 0, 1, "true", [], {})
        )
        self.assert_invalid_instructions(invalid)

    def test_membership_joined_node_sequence(self):
        document = json.loads(
            (ROOT / "Traces/native_membership_allocation_conflict.json").read_text()
        )
        document["instructions"][6] = {
            "kind": "joined", "node": "b", "value": False
        }
        document["instructions"][-1]["value"] = True
        document["instructions"].append(
            {"kind": "joined", "node": "b", "value": True}
        )
        conflict = deepcopy(document)
        conflict["instructions"][-1]["value"] = False
        scripts = self.encode([document, conflict])
        self.solve(
            [
                {"name": "joined-membership", "script": scripts[0], "expected": "sat"},
                {
                    "name": "joined-membership-conflict",
                    "script": scripts[1],
                    "expected": "unsat",
                },
            ]
        )

    def test_joined_node_explorer_core(self):
        self.assert_explorer_core(
            "Traces/native_joined_point_conflict.json", {0, 1}
        )

    def test_pre_vote_status_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = self.framed_observation_cases(
            "preVoteStatus", "capable", "enabled", "capable", allocation_guarded=False
        )
        mixed = [
            {
                "kind": "preVoteStatus",
                "node": node,
                "value": "enabled" if index % 2 else "capable",
            }
            for index, node in enumerate(names)
        ]
        cases.extend(
            [
                (
                    "pre-vote-independent-rows-and-joined-set",
                    mixed
                    + [
                        {"kind": "hasJoined", "value": [names[-1]]},
                        {"kind": "checkQuorum", "node": "a"},
                    ]
                    + mixed,
                    "sat",
                ),
                (
                    "pre-vote-all-nodes-absent",
                    [
                        {"kind": "allocated", "node": node, "value": False}
                        for node in names
                    ]
                    + mixed,
                    "sat",
                ),
            ]
        )
        scripts = self.encode(
            [
                {
                    "nodes": names,
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_pre_vote_status_input_errors(self):
        valid = {"kind": "preVoteStatus", "node": "a", "value": "capable"}
        self.assert_invalid_instructions(
            [
                dict(valid, value="unknown"),
                dict(valid, value=True),
                dict(valid, value=None),
                dict(valid, value=0),
                dict(valid, node="b"),
                dict(valid, peer="a"),
                {"kind": "preVoteStatus", "value": "capable"},
            ]
        )

    def test_retirement_completed_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = self.framed_observation_cases(
            "retirementCompleted", [], [names[-1]], ["a"], allocation_guarded=False
        )
        mixed = [
            {"kind": "retirementCompleted", "node": node, "value": names[: index + 1]}
            for index, node in enumerate(names)
        ]
        cases.extend(
            [
                (
                    "completed-order-and-duplicates",
                    [
                        {"kind": "retirementCompleted", "node": "a", "value": names},
                        {
                            "kind": "retirementCompleted",
                            "node": "a",
                            "value": list(reversed(names)) + names,
                        },
                    ],
                    "sat",
                ),
                (
                    "completed-independent-rows-and-local-state",
                    mixed
                    + [
                        {"kind": kind, "node": "a", "value": None}
                        for kind in RETIREMENT_FIELDS
                    ]
                    + [
                        {"kind": "membershipState", "node": "a", "value": "active"},
                        {"kind": "hasJoined", "value": []},
                        {"kind": "preVoteStatus", "node": "a", "value": "enabled"},
                        {"kind": "checkQuorum", "node": "a"},
                    ]
                    + mixed,
                    "sat",
                ),
                (
                    "completed-all-nodes-absent",
                    [
                        {"kind": "allocated", "node": node, "value": False}
                        for node in names
                    ]
                    + mixed,
                    "sat",
                ),
            ]
        )
        scripts = self.encode(
            [
                {
                    "nodes": names,
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_retirement_completed_input_errors(self):
        valid = {"kind": "retirementCompleted", "node": "a", "value": []}
        self.assert_invalid_instructions(
            [
                dict(valid, value=["b"]),
                dict(valid, value=[0]),
                dict(valid, value="a"),
                dict(valid, value=None),
                dict(valid, node="b"),
                dict(valid, peer="a"),
                {"kind": "retirementCompleted", "value": []},
            ]
        )

    def test_submitted_transaction_observations(self):
        names = ["a", "b"]

        def observed(tx_id, present):
            return {"kind": "submittedTxId", "txId": tx_id, "value": present}

        quorum = {"kind": "checkQuorum", "node": "a"}
        cases = []
        for tx_id in (0, 7, 10**30):
            for present in (False, True):
                observation = observed(tx_id, present)
                cases.extend(
                    [
                        (f"submitted-{tx_id}-{present}", [observation], "sat"),
                        (
                            f"submitted-{tx_id}-{present}-quorum-frame",
                            [observation, quorum, observation],
                            "sat",
                        ),
                        (
                            f"submitted-{tx_id}-{present}-conflict",
                            [observation, quorum, observed(tx_id, not present)],
                            "unsat",
                        ),
                    ]
                )
        cases.extend(
            [
                (
                    "submitted-observations-do-not-exhaust-set",
                    [observed(0, False), observed(7, False), observed(10**30, True)],
                    "sat",
                ),
                (
                    "submitted-independent-of-nodes-and-other-globals",
                    [
                        {"kind": "allocated", "node": node, "value": False}
                        for node in names
                    ]
                    + [
                        {"kind": "hasJoined", "value": []},
                        {"kind": "preVoteStatus", "node": "a", "value": "enabled"},
                        {"kind": "retirementCompleted", "node": "a", "value": ["b"]},
                        observed(0, True),
                        observed(7, False),
                        observed(10**30, True),
                    ],
                    "sat",
                ),
            ]
        )
        documents = [
            {
                "nodes": names,
                "bootstrap": names,
                "instructions": instructions,
            }
            for _, instructions, _ in cases
        ]
        for width in (1, 21):
            universe = [f"node-{index}" for index in range(width)]
            node = universe[0]
            instructions = [
                {"kind": "allocated", "node": node, "value": False},
                {"kind": "hasJoined", "value": universe},
                {"kind": "preVoteStatus", "node": node, "value": "enabled"},
                {"kind": "retirementCompleted", "node": node, "value": universe},
                observed(0, True),
                observed(7, False),
                observed(10**30, True),
            ]
            cases.append((f"submitted-global-sorts-{width}", instructions, "sat"))
            documents.append(
                {"nodes": universe, "bootstrap": [node], "instructions": instructions}
            )
        scripts = self.encode(documents)
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )
        sizes = {name: len(script) for (name, _, _), script in zip(cases, scripts)}
        # The index appears in both bounds and the cell read.
        self.assertEqual(
            sizes[f"submitted-{10**30}-False"] - sizes["submitted-0-False"], 3 * 30
        )

    def test_submitted_transaction_input_errors(self):
        valid = {"kind": "submittedTxId", "txId": 0, "value": True}
        self.assert_invalid_instructions(
            [
                dict(valid, txId=-1),
                dict(valid, txId=True),
                dict(valid, txId="0"),
                dict(valid, txId=None),
                dict(valid, value=0),
                dict(valid, value="true"),
                dict(valid, node="a"),
                {"kind": "submittedTxId", "value": True},
            ]
        )

    def test_queue_length_observations(self):
        def observed(source, destination, value):
            return {
                "kind": "queueLength",
                "source": source,
                "destination": destination,
                "value": value,
            }

        cases = []
        documents = []
        for width in (1, 2, 21):
            names = [f"node-{index}" for index in range(width)]
            source, destination = names[0], names[-1]
            quorum = {"kind": "checkQuorum", "node": source}
            for length in (0, 1, 10**30):
                observation = observed(source, destination, length)
                for suffix, instructions, expected in (
                    ("value", [observation], "sat"),
                    (
                        "unallocated-endpoints",
                        [
                            {"kind": "allocated", "node": node, "value": False}
                            for node in names
                        ]
                        + [observation],
                        "sat",
                    ),
                    (
                        "quorum-frame",
                        [observation, quorum, observation],
                        # checkQuorum requires a distinct configuration peer.
                        "sat" if width > 1 else "unsat",
                    ),
                    (
                        "value-conflict",
                        [observation, observed(source, destination, length + 1)],
                        "unsat",
                    ),
                    (
                        "quorum-conflict",
                        [
                            observation,
                            quorum,
                            observed(source, destination, length + 1),
                        ],
                        "unsat",
                    ),
                ):
                    cases.append((f"queue-length-{width}-{length}-{suffix}", expected))
                    documents.append(
                        {
                            "nodes": names,
                            "bootstrap": [source],
                            "instructions": instructions,
                        }
                    )
            if width > 1:
                pairs = [
                    (source, source),
                    (source, destination),
                    (destination, source),
                    (destination, destination),
                ]
                observations = [
                    observed(sender, receiver, index)
                    for index, (sender, receiver) in enumerate(pairs)
                ]
                cases.append((f"queue-length-{width}-independent-pairs", "sat"))
                documents.append(
                    {
                        "nodes": names,
                        "bootstrap": [source],
                        "instructions": observations + [quorum] + observations,
                    }
                )
        scripts = self.encode(documents)
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, expected), script in zip(cases, scripts)
            ]
        )
        sizes = {name: len(script) for (name, _), script in zip(cases, scripts)}
        for width in (1, 2, 21):
            self.assertEqual(
                sizes[f"queue-length-{width}-{10**30}-value"]
                - sizes[f"queue-length-{width}-0-value"],
                30,
            )

    def test_queue_length_input_errors(self):
        valid = {
            "kind": "queueLength",
            "source": "a",
            "destination": "a",
            "value": 0,
        }
        self.assert_invalid_instructions(
            [dict(valid, value=value) for value in (-1, True, "0", None, 1.5)]
            + [
                dict(valid, source="b"),
                dict(valid, destination="b"),
                dict(valid, source=0),
                dict(valid, destination=None),
                dict(valid, node="a"),
            ]
            + [
                {key: value for key, value in valid.items() if key != missing}
                for missing in ("source", "destination", "value")
            ]
        )

    def test_queue_point_observations(self):
        cases = []
        documents = []
        for names in (["a"], ["a", "b"]):
            source, destination = names[0], names[-1]
            quorum = {"kind": "checkQuorum", "node": source}
            for packet in packet_samples(source, destination):
                observation = packet_observation(packet)
                changed = packet_observation(dict(packet, term=packet["term"] + 1))
                length = {
                    "kind": "queueLength",
                    "source": source,
                    "destination": destination,
                    "value": 1,
                }
                variations = [
                    ("value", [observation], "sat"),
                    ("repeat", [observation, observation], "sat"),
                    ("conflict", [observation, changed], "unsat"),
                    ("known-length", [length, observation], "sat"),
                    ("empty", [dict(length, value=0), observation], "unsat"),
                    (
                        "unallocated-endpoints",
                        [
                            {"kind": "allocated", "node": node, "value": False}
                            for node in names
                        ]
                        + [observation],
                        "sat",
                    ),
                ]
                if len(names) > 1:
                    variations += [
                        ("quorum-frame", [observation, quorum, observation], "sat"),
                        ("quorum-conflict", [observation, quorum, changed], "unsat"),
                    ]
                for suffix, instructions, expected in variations:
                    cases.append(
                        (
                            f"queue-point-{len(names)}-{packet['kind']}-{suffix}",
                            expected,
                        )
                    )
                    documents.append(
                        {
                            "nodes": names,
                            "bootstrap": names,
                            "instructions": instructions,
                        }
                    )
        packets = packet_samples("a", "b")
        for index, packet in enumerate(packets):
            cases.append((f"queue-point-tag-{index}", "unsat"))
            documents.append(
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a", "b"],
                    "instructions": [
                        packet_observation(packet),
                        packet_observation(packets[(index + 1) % len(packets)]),
                    ],
                }
            )
        scripts = self.encode(documents)
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, expected), script in zip(cases, scripts)
            ]
        )

    def test_model_packet_json_roundtrips(self):
        generated = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeArrayTermFixtureMain.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(generated.stdout)
        packets = [
            instruction["value"]
            for fixture in fixtures
            for instruction in fixture["trace"]["instructions"]
            if instruction["kind"] == "queuePoint"
        ]
        self.assertEqual(len({packet["kind"] for packet in packets}), 7)
        decoded = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativePacketJsonFixtureMain.lean"],
            cwd=ROOT,
            input=json.dumps(packets),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(decoded.stdout), packets)

    def compile_packet_patterns(self, cases):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativePacketPatternFixtureMain.lean",
            ],
            cwd=ROOT,
            input=json.dumps(cases),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        fixtures = json.loads(result.stdout)
        self.assertEqual(
            [fixture["name"] for fixture in fixtures],
            [case["name"] for case in cases],
        )
        return fixtures

    def packet_pattern_cases(self):
        cases = []

        def add(packet, pattern, expected):
            cases.append(
                (
                    {
                        "name": f"packet-pattern-{len(cases)}",
                        "packet": packet,
                        "pattern": pattern,
                    },
                    expected,
                )
            )

        for source, destination in (("a", "b"), ("b", "a"), ("a", "a")):
            packets = packet_samples(source, destination)
            for packet in packets:
                add(packet, packet, "sat")
                for other in packets:
                    add(
                        packet,
                        {"kind": other["kind"]},
                        "sat" if packet["kind"] == other["kind"] else "unsat",
                    )
                for field, value in packet.items():
                    if field == "kind":
                        continue
                    add(packet, {"kind": packet["kind"], field: value}, "sat")
                    if isinstance(value, bool):
                        changed = not value
                    elif isinstance(value, int):
                        changed = value + 10**30
                    elif isinstance(value, str):
                        changed = "c"
                    else:
                        changed = []
                    add(packet, {"kind": packet["kind"], field: changed}, "unsat")
                zero_term = dict(packet, term=0)
                add(zero_term, {"kind": packet["kind"], "term": 0}, "sat")
                add(zero_term, {"kind": packet["kind"], "term": 1}, "unsat")

            append = packets[0]
            length_pattern = {"kind": append["kind"], "entriesLength": 4}
            for previous_term in (0, 3, 10**30):
                changed = deepcopy(append)
                changed["prevLogTerm"] = previous_term
                changed["entries"][0] = {
                    "term": previous_term,
                    "content": {"transaction": 10**30 + previous_term},
                }
                add(changed, length_pattern, "sat")
            add(append, dict(length_pattern, entriesLength=0), "unsat")
            add(dict(append, entries=[]), dict(length_pattern, entriesLength=0), "sat")
            add(append, dict(append, entriesLength=4), "sat")
            add(append, dict(append, entriesLength=3), "unsat")
        return cases

    def test_packet_patterns(self):
        cases = self.packet_pattern_cases()
        fixtures = self.compile_packet_patterns([case for case, _ in cases])
        self.assertEqual(
            [fixture.get("expected") for fixture in fixtures],
            [expected for _, expected in cases],
        )
        self.solve(fixtures)

    def test_public_packet_patterns(self):
        cases = self.packet_pattern_cases()
        documents = [
            {
                "nodes": ["a", "b", "c"],
                "bootstrap": ["a"],
                "instructions": [
                    packet_observation(case["packet"]),
                    dict(
                        packet_observation(case["packet"]),
                        kind="queuePattern",
                        value=case["pattern"],
                    ),
                ],
            }
            for case, _ in cases
        ]
        scripts = self.encode(documents)
        self.solve(
            [
                {
                    "name": f"public-{case['name']}",
                    "script": script,
                    "expected": expected,
                }
                for (case, expected), script in zip(cases, scripts)
            ]
        )

    def test_queue_pattern_input_errors(self):
        valid = {
            "kind": "queuePattern",
            "source": "a",
            "destination": "b",
            "index": 0,
            "value": {"kind": "appendEntriesRequest", "entriesLength": 1},
        }
        invalid = [
            {key: value for key, value in valid.items() if key != missing}
            for missing in valid
        ]
        invalid.append(dict(valid, unexpected=0))
        for field in ("source", "destination"):
            invalid.extend(
                dict(valid, **{field: value})
                for value in ("missing", None, False, 0, [], {})
            )
        invalid.extend(
            dict(valid, index=value) for value in (None, False, -1, 1.5, "0")
        )
        invalid.extend(
            dict(valid, value=value)
            for value in (
                None,
                {},
                {"kind": "unknown"},
                {"kind": "appendEntriesRequest", "entriesLength": None},
                {"kind": "appendEntriesRequest", "entriesLength": -1},
                {"kind": "appendEntriesRequest", "success": True},
                {"kind": "requestVoteRequest", "source": "missing"},
            )
        )
        self.assert_invalid_instructions(invalid)

    def test_queue_pattern_explorer_core(self):
        path = "Traces/native_partial_packet_conflict.json"
        self.assert_explorer_core(path, {0, 1})
        document = json.loads((ROOT / path).read_text())
        document["instructions"][1]["value"]["entriesLength"] = 1
        corrected = self.encode([document])[0]
        self.solve(
            [
                {
                    "name": "partial-packet-conflict-corrected",
                    "script": corrected,
                    "expected": "sat",
                }
            ]
        )

    def test_queue_pattern_array_hint_boundaries(self):
        lengths = [0, 1, 2, 8, 16, 32, 33, 10**30]
        documents = [
            {
                "nodes": ["a", "b"],
                "bootstrap": ["a"],
                "instructions": [
                    {
                        "kind": "queuePattern",
                        "source": "a",
                        "destination": "b",
                        "index": 0,
                        "value": {
                            "kind": "appendEntriesRequest",
                            "entriesLength": length,
                        },
                    }
                ],
            }
            for length in lengths
        ]
        scripts = self.encode(documents)
        fixtures = []
        for length, script in zip(lengths, scripts):
            self.assertEqual(script.count("(store "), length if length <= 32 else 0)
            if length <= 32:
                fixtures.append(
                    {
                        "name": f"queue-pattern-hint-{length}",
                        "script": script,
                        "expected": "sat",
                    }
                )
        fallback = []
        packet = dict(packet_samples("a", "b")[0], entries=[])
        for document in documents[-2:]:
            conflict = deepcopy(document)
            conflict["instructions"].insert(0, packet_observation(packet))
            fallback.append(conflict)
        large = deepcopy(documents[-2])
        packet = dict(packet, entries=[{"term": 0, "content": "signature"}] * 33)
        large["instructions"].insert(0, packet_observation(packet))
        fallback.append(large)
        fallback_scripts = self.encode(fallback)
        fixtures.extend(
            {
                "name": f"queue-pattern-hint-fallback-{index}",
                "script": script,
                "expected": "sat" if index == 2 else "unsat",
            }
            for index, script in enumerate(fallback_scripts)
        )
        self.solve(fixtures)

    def test_packet_pattern_errors(self):
        packet = packet_samples("a", "b")[0]
        patterns = [{}, None, [], {"kind": "unknown"}, {"kind": None}]
        for sample in packet_samples("a", "b"):
            for field, value in sample.items():
                if field == "kind":
                    continue
                if isinstance(value, bool):
                    invalid = [None, 0, 1, "true"]
                elif isinstance(value, int):
                    invalid = [None, True, -1, 1.5, "1"]
                elif isinstance(value, str):
                    invalid = [None, 0, "undeclared"]
                else:
                    invalid = [None, "signature", [{}]]
                patterns.extend(
                    {"kind": sample["kind"], field: bad} for bad in invalid
                )
            patterns.append({"kind": sample["kind"], "unexpected": 0})
        patterns.extend(
            [
                {"kind": "appendEntriesResponse", "prevLogIndex": 0},
                {"kind": "requestVoteRequest", "voteGranted": True},
                {"kind": "proposeVoteRequest", "entries": []},
                {"kind": "appendEntriesRequest", "entriesLength": -1},
                {"kind": "appendEntriesRequest", "entriesLength": None},
                {"kind": "appendEntriesRequest", "entriesLength": True},
            ]
        )
        fixtures = self.compile_packet_patterns(
            [
                {
                    "name": f"packet-pattern-error-{index}",
                    "packet": packet,
                    "pattern": pattern,
                }
                for index, pattern in enumerate(patterns)
            ]
        )
        for fixture in fixtures:
            with self.subTest(name=fixture["name"]):
                self.assertEqual(set(fixture), {"name", "error"})
                self.assertTrue(fixture["error"])

    def test_queue_patterns(self):
        cases = []
        expected = []

        def add(packet, pattern, verdict, **queue):
            cases.append(
                dict(
                    {
                        "name": f"queue-pattern-{len(cases)}",
                        "packet": packet,
                        "pattern": pattern,
                        "source": packet["source"],
                        "head": 0,
                        "length": 1,
                        "index": 0,
                        "invalidTerm": False,
                    },
                    **queue,
                )
            )
            expected.append(verdict)

        for packet in packet_samples("a", "b"):
            for head in (0, 10**30):
                for length, index in (
                    (0, 0),
                    (1, 0),
                    (1, 1),
                    (3, 2),
                    (10**30, 10**30 - 1),
                    (10**30, 10**30),
                ):
                    add(
                        packet,
                        packet,
                        "sat" if index < length else "unsat",
                        head=head,
                        length=length,
                        index=index,
                    )
            for source, invalid in (("a", True), ("c", False)):
                queue = {"source": source, "invalidTerm": invalid, "head": 10**30}
                add(packet, packet, "unsat", **queue)
                add(
                    packet,
                    {
                        "kind": "proposeVoteRequest",
                        "term": 0,
                        "source": source,
                        "destination": source,
                    },
                    "sat",
                    **queue,
                )
            add(packet, {"kind": packet["kind"]}, "sat")
            other = (
                "proposeVoteRequest"
                if packet["kind"] != "proposeVoteRequest"
                else "appendEntriesRequest"
            )
            add(packet, {"kind": other}, "unsat")

        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeQueuePatternFixtureMain.lean",
            ],
            cwd=ROOT,
            input=json.dumps(cases),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        fixtures = json.loads(result.stdout)
        self.assertEqual(
            [fixture["name"] for fixture in fixtures],
            [case["name"] for case in cases],
        )
        self.assertEqual([fixture["expected"] for fixture in fixtures], expected)
        self.solve(fixtures)

    def test_queue_packet_fields_and_ranges(self):
        packets = packet_samples("a", "b")
        cases = []
        for packet in packets:
            for field, value in packet.items():
                if field in ("kind", "source", "destination", "entries"):
                    continue
                changed = dict(
                    packet,
                    **{field: not value if isinstance(value, bool) else value + 1},
                )
                cases.append(
                    (
                        f"packet-field-{packet['kind']}-{field}",
                        [packet_observation(packet), packet_observation(changed)],
                        "unsat",
                    )
                )
        append = packets[0]
        for label, entries in (
            ("length", append["entries"][:-1]),
            ("order", list(reversed(append["entries"]))),
            ("duplicate", append["entries"] + append["entries"]),
        ):
            cases.append(
                (
                    f"packet-entries-{label}",
                    [
                        packet_observation(append),
                        packet_observation(dict(append, entries=entries)),
                    ],
                    "unsat",
                )
            )
        reordered = deepcopy(append)
        reordered["entries"][2]["content"]["reconfiguration"] = ["b", "a", "a"]
        cases.append(
            (
                "packet-entry-set-order",
                [packet_observation(append), packet_observation(reordered)],
                "sat",
            )
        )
        default = {
            "kind": "proposeVoteRequest",
            "term": 0,
            "source": "a",
            "destination": "a",
        }
        cases.extend(
            [
                ("packet-default", [packet_observation(default)], "sat"),
                (
                    "packet-default-conflict",
                    [
                        packet_observation(default),
                        packet_observation(dict(default, term=1)),
                    ],
                    "unsat",
                ),
                (
                    "packet-destination-is-not-queue-destination",
                    [packet_observation(default, destination="b")],
                    "sat",
                ),
                (
                    "packet-source-must-match-partition",
                    [packet_observation(dict(default, source="b"), source="a")],
                    "unsat",
                ),
            ]
        )
        for size in (2, 10**30):
            length = {
                "kind": "queueLength",
                "source": "a",
                "destination": "b",
                "value": size,
            }
            cases.extend(
                [
                    (
                        f"packet-duplicate-positions-{size}",
                        [
                            length,
                            packet_observation(packets[-1]),
                            packet_observation(packets[-1], index=size - 1),
                        ],
                        "sat",
                    ),
                    (
                        f"packet-at-tail-{size}",
                        [length, packet_observation(packets[-1], index=size)],
                        "unsat",
                    ),
                ]
            )
        scripts = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )
        sizes = {name: len(script) for (name, _, _), script in zip(cases, scripts)}
        self.assertLess(
            sizes[f"packet-duplicate-positions-{10**30}"]
            - sizes["packet-duplicate-positions-2"],
            5000,
        )

    def test_queue_point_identity_matrix(self):
        names = [f"node-{index}" for index in range(21)]
        first, last = names[0], names[-1]
        observations = [
            packet_observation(
                dict(packet_samples(source, source)[-1], term=index),
                destination=destination,
            )
            for index, (source, destination) in enumerate(
                ((first, first), (first, last), (last, first), (last, last))
            )
        ]
        huge = packet_observation(packet_samples(last, first)[0], index=10**30 - 1)
        scripts = self.encode(
            [
                {
                    "nodes": names,
                    "bootstrap": [first, last],
                    "instructions": observations
                    + [{"kind": "checkQuorum", "node": first}]
                    + observations
                    + [huge],
                }
            ]
        )
        self.solve(
            [
                {
                    "name": "queue-point-identity-matrix",
                    "script": scripts[0],
                    "expected": "sat",
                }
            ]
        )
        self.assertLess(len(scripts[0]), 150_000)

    def test_queue_point_input_errors(self):
        packets = packet_samples("a", "a")
        invalid = []
        numeric_fields = set()
        for packet in packets:
            invalid.append(packet_observation(dict(packet, extra=0)))
            payload_fields = [
                key
                for key in packet
                if key not in ("kind", "term", "source", "destination")
            ]
            if payload_fields:
                invalid.append(
                    packet_observation(
                        {
                            key: value
                            for key, value in packet.items()
                            if key != payload_fields[0]
                        }
                    )
                )
            for field, value in packet.items():
                if isinstance(value, bool):
                    invalid.append(packet_observation(dict(packet, **{field: 1})))
                elif isinstance(value, int) and field not in numeric_fields:
                    numeric_fields.add(field)
                    invalid.append(packet_observation(dict(packet, **{field: -1})))
        packet = packets[-1]
        invalid += [
            packet_observation(dict(packet, kind="unknown")),
            packet_observation(dict(packet, term=True)),
            packet_observation(dict(packet, term=1.5)),
            packet_observation(dict(packet, source="b"), source="a", destination="a"),
            packet_observation(
                dict(packet, destination="b"), source="a", destination="a"
            ),
            packet_observation(dict(packet, source=0), source="a", destination="a"),
            packet_observation(
                dict(packet, destination=None), source="a", destination="a"
            ),
            packet_observation(packet, source="b"),
            packet_observation(packet, destination="b"),
        ]
        invalid += [
            packet_observation(packet, index=value) for value in (-1, True, 1.5, "0")
        ]
        for field in ("kind", "term", "source", "destination"):
            invalid.append(
                packet_observation(
                    {key: value for key, value in packet.items() if key != field},
                    source="a",
                    destination="a",
                )
            )
        observation = packet_observation(packet)
        invalid += [
            {key: value for key, value in observation.items() if key != field}
            for field in ("source", "destination", "index", "value")
        ]
        invalid.append(dict(observation, value=None))
        invalid += [
            packet_observation(dict(packets[0], entries=value))
            for value in (
                None,
                {},
                [{"term": -1, "content": "signature"}],
                [{"term": 0, "content": {"transaction": -1}}],
                [{"term": 0, "content": {"reconfiguration": ["b"]}}],
                [{"term": 0, "content": {"unexpected": 0}}],
            )
        ]
        self.assert_invalid_instructions(invalid)

    def assert_invalid_instructions(self, instructions):
        self.assert_input_errors(
            [
                (
                    f"instruction-{index}",
                    json.dumps(
                        {
                            "nodes": ["a"],
                            "bootstrap": ["a"],
                            "instructions": [instruction],
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                )
                for index, instruction in enumerate(instructions)
            ]
        )

    def test_decoded_bootstrap_sets(self):
        variants = [["a", "b"], ["b", "a"], ["b", "a", "a"], ["a"]]
        scripts = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": bootstrap,
                    "instructions": [{"kind": "checkQuorum", "node": "a"}],
                }
                for bootstrap in variants
            ]
        )
        self.assertEqual(scripts[1:3], [scripts[0], scripts[0]])
        self.assertNotEqual(scripts[0], scripts[3])

    def test_input_errors_do_not_emit_smt(self):
        valid = {"nodes": ["a"], "bootstrap": ["a"], "instructions": []}
        invalid = [
            (
                "duplicate-field",
                '{"bootstrap":["a"],"instructions":[],"nodes":["a"],"nodes":["a"]}',
            ),
            (
                "unsupported-instruction",
                json.dumps(
                    dict(valid, instructions=[{"kind": "receive", "node": "a"}]),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ),
            (
                "undeclared-node",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {"kind": "allocated", "node": "b", "value": True}
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ),
        ]
        invalid.extend(
            (
                name,
                json.dumps(
                    dict(valid, bootstrap=bootstrap),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for name, bootstrap in [
                ("empty-bootstrap", []),
                ("undeclared-bootstrap-node", ["b"]),
                ("non-array-bootstrap", "a"),
                ("non-string-bootstrap-node", [0]),
            ]
        )
        invalid.extend(
            (
                f"{kind}-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {
                                "kind": kind,
                                "node": "a",
                                "value": value,
                            }
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for kind in RETIREMENT_FIELDS
            for name, value in [
                ("negative", -1),
                ("fractional", 1.5),
                ("boolean", True),
                ("string", "1"),
            ]
        )
        invalid.extend(
            (
                f"votedFor-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {"kind": "votedFor", "node": "a", "value": value}
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for name, value in [
                ("undeclared", "b"),
                ("numeric", 0),
                ("boolean", False),
                ("array", ["a"]),
            ]
        )
        invalid.extend(
            (
                f"{kind}-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[{"kind": kind, "node": "a", "value": value}],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for kind in VOTE_SET_FIELDS
            for name, value in [
                ("undeclared", ["b"]),
                ("numeric", [0]),
                ("non-array", "a"),
                ("null", None),
            ]
        )
        invalid.extend(
            (
                f"membership-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {"kind": "membershipState", "node": "a", "value": value}
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for name, value in [
                ("unknown", "retired"),
                ("numeric", 0),
                ("boolean", False),
                ("null", None),
            ]
        )
        invalid.extend(
            (
                f"{kind}-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {"kind": kind, "node": "a", "peer": peer, "value": value}
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for kind in PEER_INDEX_FIELDS
            for name, peer, value in [
                ("undeclared-peer", "b", 0),
                ("numeric-peer", 0, 0),
                ("negative-index", "a", -1),
                ("null-index", "a", None),
            ]
        )
        invalid.extend(
            (
                f"hasJoined-{name}",
                json.dumps(
                    dict(valid, instructions=[instruction]),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for name, instruction in [
                ("undeclared", {"kind": "hasJoined", "value": ["b"]}),
                ("numeric-member", {"kind": "hasJoined", "value": [0]}),
                ("non-array", {"kind": "hasJoined", "value": "a"}),
                ("null", {"kind": "hasJoined", "value": None}),
                ("extra-node", {"kind": "hasJoined", "node": "a", "value": []}),
            ]
        )
        self.assert_input_errors(invalid)

    def assert_input_errors(self, invalid):
        for name, document in invalid:
            with self.subTest(name=name):
                result = subprocess.run(
                    ["lake", "env", "lean", "--run", "Sparse/NativeEncodeMain.lean"],
                    cwd=ROOT,
                    input=document,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("native encoding error:", result.stderr)

    def test_python_wrapper_and_solver_outcomes(self):
        requested = os.environ.get("Z3")
        solver = find_z3(Path(requested) if requested else None)
        name = "node-\u03bb"
        with tempfile.TemporaryDirectory(prefix="native-lean-cli-") as temporary:
            directory = Path(temporary)
            unknown = directory / "unknown-z3"
            unknown.write_text(
                f"#!{sys.executable}\nimport sys\n"
                "for line in sys.stdin:\n"
                "    if line.strip() == '(check-sat)':\n"
                "        print('unknown', flush=True)\n"
                "        break\n",
                encoding="ascii",
            )
            unknown.chmod(0o755)
            for label, status, instructions, executable in [
                ("sat", "sat", [], solver),
                (
                    "joined",
                    "unsat",
                    [
                        {"kind": "hasJoined", "value": [name]},
                        {"kind": "hasJoined", "value": []},
                    ],
                    solver,
                ),
                (
                    "submitted",
                    "unsat",
                    [
                        {"kind": "submittedTxId", "txId": 10**30, "value": True},
                        {"kind": "submittedTxId", "txId": 10**30, "value": False},
                    ],
                    solver,
                ),
                (
                    "packet",
                    "unsat",
                    [
                        packet_observation(
                            dict(packet_samples(name, name)[-1], term=term)
                        )
                        for term in (7, 8)
                    ],
                    solver,
                ),
                ("unknown", "unknown", [], unknown),
            ]:
                with self.subTest(label=label):
                    path = directory / f"{label}.json"
                    path.write_text(
                        json.dumps(
                            {
                                "nodes": [name],
                                "bootstrap": [name],
                                "instructions": instructions,
                            },
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                    output = directory / label
                    result = subprocess.run(
                        [
                            sys.executable,
                            "native_lean.py",
                            str(path),
                            "--output-dir",
                            str(output),
                            "--z3",
                            str(executable),
                        ],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    summary = json.loads(result.stdout)
                    self.assertEqual(summary["status"], status)
                    self.assertEqual(summary["encoder"], "native-lean-experimental")
                    self.assertEqual(summary["solver"], "z3")
                    for artifact in ("trace.smt2", "trace.stdout", "trace.stderr"):
                        self.assertTrue((output / artifact).is_file())
                    snapshot = NativeRun.load(output)
                    api = ExplorerApi(snapshot)
                    self.assertEqual(api.get("/api/run")["result"]["status"], status)
                    self.assertEqual(
                        api.get("/api/instructions")["total"], len(instructions)
                    )
                    self.assertEqual(
                        bool(api.get("/api/core")["clauses"]), status == "unsat"
                    )
                    if status == "unsat":
                        self.assertEqual(api.get("/api/core")["instructions"], [0, 1])
                        for index, item in enumerate(instructions):
                            self.assertEqual(
                                api.get(f"/api/instructions/{index}")["instruction"],
                                item,
                            )


if __name__ == "__main__":
    unittest.main()
