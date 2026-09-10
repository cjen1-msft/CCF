# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Control traces follow Model guards and preserve named causal assignments."""

from __future__ import annotations

import copy
import json
import subprocess
import time
import unittest

from tests.test_client_request_encoding import (
    CVC5,
    ROOT,
    SOLVER_TESTS,
    CertificateRejected,
    ClientRequestSliceTestCase,
    _observation,
    _request,
)
from tests.test_leader_writes import action, trace
from tests.test_replication_encoding import queued_entry, send
from tests.test_template_client_requests import NODE_COUNT, entry_state, local_state
from Shared.smt import restrict_to_assertions, write_formula
from Shared.solver import run_solver

UNARY_ACTIONS = [
    "advanceCommitIndex",
    "timeout",
    "becomePreVoteCandidate",
    "becomeCandidate",
    "checkQuorum",
    "becomeLeader",
]
PEER_ACTIONS = [
    "requestVote",
    "requestPreVote",
    "updateTerm",
    "proposeVote",
    "advanceCommitIndexAndProposeVote",
]


def entry(role: str = "follower", *, pre_vote: bool = False) -> dict[str, object]:
    local = local_state()
    local.update(
        role=role,
        currentTerm=1,
        log=[],
        votedFor=None,
        votesGranted=[0, 1, 2],
        preVotesGranted=[0, 1, 2],
    )
    state = entry_state(local)
    state["nodes"] = [
        copy.deepcopy(local) if node < 5 else None for node in range(NODE_COUNT)
    ]
    state["submittedTxIds"] = []
    state["hasJoined"] = list(range(5))
    if pre_vote:
        state["preVoteStatus"][0] = "enabled"
    return state


def log_entry(kind: str, **fields: object) -> dict[str, object]:
    return {"term": 1, "content": {"kind": kind, **fields}}


def committable_entry(*, terminal: bool = False) -> dict[str, object]:
    state = entry("leader")
    local = state["nodes"][0]
    if terminal:
        local["log"] = [
            log_entry("reconfiguration", nodes=[1, 2, 3, 4]),
            log_entry("signature"),
            log_entry("retiredCommitted", nodes=[0]),
            log_entry("signature"),
        ]
        local["commitIndex"] = 2
        local["matchIndex"] = [4] * NODE_COUNT
    else:
        local["log"] = [log_entry("signature")]
        local["matchIndex"] = [1] * NODE_COUNT
    return state


def promotable_entry() -> dict[str, object]:
    state = entry("candidate")
    state["nodes"][0]["log"] = [
        log_entry("transaction", transaction=0),
        log_entry("signature"),
        log_entry("transaction", transaction=0),
    ]
    state["nodes"][0]["matchIndex"] = [1] * NODE_COUNT
    return state


@SOLVER_TESTS
class ControlEncodingTests(ClientRequestSliceTestCase):
    def test_duplicate_send_encoding_scales_linearly(self):
        encoder = ROOT / ".lake/build/bin/encode_trace"
        self.assertTrue(encoder.is_file(), "Build encode_trace before this native test")
        for family, prefix, packet, destination, initial in [
            (
                "requestVote",
                [action("timeout", node=1)],
                action("requestVote", node=1, destination=0),
                0,
                "bootstrap",
            ),
            (
                "requestPreVote",
                [action("becomePreVoteCandidate")],
                action("requestPreVote", destination=1),
                1,
                entry(pre_vote=True),
            ),
            ("proposeVote", [], action("proposeVote", destination=1), 1, "bootstrap"),
            ("appendEntries", [], send(batch_end=0), 1, "bootstrap"),
        ]:
            with self.subTest(family=family):
                certificates = {}
                for count in (12, 15, 24, 48):
                    name = f"{family}-{count}"
                    certificate = self.workspace / f"{name}.json"
                    certificate.write_text(
                        json.dumps(
                            trace(
                                prefix
                                + [packet] * count
                                + [_observation("queueLength", 1, node=destination)],
                                entry=initial,
                                queue_capacity=1,
                            )
                        ),
                        encoding="utf-8",
                    )
                    certificates[count] = certificate

                counted = subprocess.run(
                    [
                        "nice",
                        "-n",
                        "10",
                        "lake",
                        "env",
                        "lean",
                        "--run",
                        "MachineGenerated/ControlTraceScalingMain.lean",
                        str(certificates[12]),
                        str(certificates[15]),
                    ],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                counts = [
                    json.loads(line)["binding_occurrences"]
                    for line in counted.stdout.splitlines()
                ]
                self.assertEqual(len(counts), 2)
                self.assertGreater(counts[0], 0)
                self.assertLessEqual(counts[1], 2 * counts[0])
                print(
                    f"{family}: 12/15 sends, {counts[0]}/{counts[1]} binding occurrences",
                    flush=True,
                )

                measurements = []
                for count in (24, 48):
                    name = f"{family}-{count}"
                    output = self.workspace / name
                    started = time.perf_counter()
                    subprocess.run(
                        [str(encoder), str(certificates[count]), str(output)],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    elapsed = time.perf_counter() - started
                    size = sum(
                        (output / filename).stat().st_size
                        for filename in ("formula.smt2", "constraint-map.json")
                    )
                    measurements.append((elapsed, size))
                    assert CVC5 is not None
                    result = run_solver(
                        CVC5, output / "formula.smt2", output, "scaling"
                    )
                    self.assertEqual(result.status, "sat")
                    print(
                        f"{family}: {count} sends, {elapsed:.3f}s native encoding, "
                        f"{size} output bytes",
                        flush=True,
                    )
                small, large = measurements
                self.assertLessEqual(large[1], 3 * small[1])

    def test_vote_snapshot_keeps_truncation_of_the_selected_log_term(self):
        state = promotable_entry()
        state["nodes"][0]["commitIndex"] = 3
        state["nodes"][0]["log"][2]["term"] = 9
        state["network"][1] = [
            {
                "kind": "requestVoteRequest",
                "term": 2,
                "source": 0,
                "destination": 1,
                "lastCommittableTerm": 9,
                "lastCommittableIndex": 3,
            }
        ]
        status, output = self.run_runner(
            trace(
                [
                    action("becomeLeader"),
                    action("checkQuorum"),
                    action("timeout"),
                    action("requestVote", destination=1),
                    _observation("queueLength", 1, node=1),
                ],
                entry=state,
                term_count=12,
                index_count=8,
                queue_capacity=3,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_append_queue_deduplication_keeps_the_term_writer(self):
        state = entry("follower")
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0]),
            log_entry("signature"),
        ]
        state["nodes"][0]["commitIndex"] = 1
        state["network"][1] = [
            {
                "kind": "appendEntriesRequest",
                "term": 1,
                "source": 0,
                "destination": 1,
                "prevLogIndex": 2,
                "prevLogTerm": 1,
                "entries": [],
                "leaderCommit": 1,
            }
        ]
        status, output = self.run_runner(
            trace(
                [
                    action("timeout"),
                    action("becomeLeader"),
                    send(batch_end=2),
                    _observation("queueLength", 1, node=1),
                ],
                entry=state,
                index_count=8,
                queue_capacity=3,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_control_queue_deduplication_keeps_the_signature_writer(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [log_entry("transaction", transaction=0)]
        state["network"][1] = [
            {
                "kind": "requestVoteRequest",
                "term": 2,
                "source": 0,
                "destination": 1,
                "lastCommittableTerm": 1,
                "lastCommittableIndex": 1,
            }
        ]
        status, output = self.run_runner(
            trace(
                [
                    action("signCommittableMessages"),
                    action("checkQuorum"),
                    action("timeout"),
                    action("requestVote", destination=1),
                    _observation("queueLength", 1, node=1),
                ],
                entry=state,
                queue_capacity=3,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_pre_vote_queue_deduplication_keeps_the_term_copy(self):
        state = entry("follower")
        state["preVoteStatus"][1] = "enabled"
        state["network"][0] = [
            {
                "kind": "requestPreVote",
                "term": 1,
                "source": 1,
                "destination": 0,
                "lastCommittableTerm": 0,
                "lastCommittableIndex": 0,
            }
        ]
        state["network"][1] = [
            {
                "kind": "requestVoteRequest",
                "term": 2,
                "source": 0,
                "destination": 1,
                "lastCommittableTerm": 0,
                "lastCommittableIndex": 0,
            }
        ]
        status, output = self.run_runner(
            trace(
                [
                    action("updateTerm", node=0, destination=1),
                    action("becomePreVoteCandidate", node=1),
                    action("requestPreVote", node=1, destination=0),
                    _observation("queueLength", 1),
                ],
                entry=state,
                queue_capacity=3,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_control_queue_deduplication_keeps_the_term_writer(self):
        state = entry("candidate")
        state["network"][0] = [
            {
                "kind": "requestVoteRequest",
                "term": 1,
                "source": 1,
                "destination": 0,
                "lastCommittableTerm": 0,
                "lastCommittableIndex": 0,
            }
        ]
        status, output = self.run_runner(
            trace(
                [
                    action("timeout", node=1),
                    action("requestVote", node=1, destination=0),
                    _observation("queueLength", 1),
                ],
                entry=state,
                queue_capacity=3,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_configuration_allocation_and_join_keep_the_prior_truncation(self):
        state = entry("candidate")
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0, 1, 2, 3, 4, 5])
        ]
        state["nodes"][0]["votesGranted"] = [0, 1, 2, 3]
        for field in ("allocated", "joined"):
            with self.subTest(field=field):
                status, output = self.run_runner(
                    trace(
                        [
                            action("becomeLeader"),
                            action("changeConfiguration", configuration=[0, 5]),
                            _observation(field, False, node=5),
                        ],
                        entry=state,
                        index_count=8,
                        log_capacity=8,
                    ),
                    name=field,
                )
                self.assertEqual(status, "unsat")
                self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_pending_retirement_guard_keeps_the_refresh_writer(self):
        state = entry("leader")
        state["retirementCompleted"][0] = [1]
        self.assert_core(
            trace(
                [action("appendRetiredCommitted"), action("appendRetiredCommitted")],
                entry=state,
            ),
            {"group_1", "group_2"},
        )

    def test_commit_frontier_choice_keeps_the_election(self):
        state = entry("follower")
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0]),
            {"term": 2, "content": {"kind": "signature"}},
            {"term": 3, "content": {"kind": "signature"}},
        ]
        state["nodes"][0]["commitIndex"] = 1
        status, output = self.run_runner(
            trace(
                [
                    action("timeout"),
                    action("becomeLeader"),
                    action("advanceCommitIndex"),
                    _observation("commitIndex", 3),
                ],
                entry=state,
                index_count=8,
                log_capacity=8,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_terminal_retirement_write_guard_keeps_the_commit(self):
        self.assert_core(
            trace(
                [
                    action("advanceCommitIndexAndProposeVote", destination=1),
                    _request(0),
                ],
                entry=committable_entry(terminal=True),
                index_count=10,
                log_capacity=8,
                queue_capacity=1,
            ),
            {"group_1", "group_2"},
        )

    def test_successor_progress_guard_keeps_the_promotion_reset(self):
        state = entry("candidate")
        state["nodes"][0]["log"] = [
            log_entry("transaction", transaction=0),
            log_entry("signature"),
            log_entry("reconfiguration", nodes=[0, 1]),
            log_entry("signature"),
        ]
        state["nodes"][0]["matchIndex"][2] = 9
        self.assert_core(
            trace(
                [action("becomeLeader"), action("proposeVote", destination=2)],
                entry=state,
                index_count=12,
                log_capacity=8,
                queue_capacity=1,
            ),
            {"group_1", "group_2"},
        )

    def test_repeated_configuration_guard_keeps_the_first_write(self):
        self.assert_core(
            trace(
                [
                    action("changeConfiguration", configuration=[0, 1]),
                    action("changeConfiguration", configuration=[0, 1]),
                ]
            ),
            {"group_1", "group_2"},
        )

    def test_latest_configuration_guard_keeps_the_truncation(self):
        state = entry("candidate")
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0, 1, 2, 3, 4, 5])
        ]
        state["nodes"][0]["votesGranted"] = [0, 1, 2, 3]
        self.assert_core(
            trace(
                [
                    action("becomeLeader"),
                    action("changeConfiguration", configuration=[0, 1, 2, 3, 4]),
                ],
                entry=state,
            ),
            {"group_1", "group_2"},
        )

    def test_removed_configuration_keeps_the_promotion_in_the_send_core(self):
        state = entry("candidate")
        state["nodes"][0]["log"] = [log_entry("reconfiguration", nodes=[5])]
        state["nodes"][0]["votesGranted"] = [0, 1, 2, 5]
        state["nodes"][5] = copy.deepcopy(state["nodes"][1])
        state["hasJoined"].append(5)
        status, output = self.run_runner(
            trace(
                [
                    action("becomeLeader"),
                    action("checkQuorum"),
                    action("timeout"),
                    action("requestVote", destination=5),
                ],
                entry=state,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_configuration_activation_keeps_the_commit_writer(self):
        state = committable_entry()
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0, 1]),
            log_entry("signature"),
        ]
        state["nodes"][0]["matchIndex"] = [2] * NODE_COUNT
        status, output = self.run_runner(
            trace(
                [
                    action("advanceCommitIndex"),
                    action("checkQuorum"),
                    action("timeout"),
                    action("requestVote", destination=2),
                ],
                entry=state,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_commit_current_term_guard_keeps_the_election(self):
        state = committable_entry()
        state["nodes"][0]["role"] = "follower"
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0]),
            log_entry("signature"),
        ]
        state["nodes"][0]["commitIndex"] = 1
        state["nodes"][0]["matchIndex"] = [2] * NODE_COUNT
        status, output = self.run_runner(
            trace(
                [
                    action("timeout"),
                    action("becomeLeader"),
                    action("advanceCommitIndex"),
                ],
                entry=state,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_pre_vote_majority_guard_keeps_the_reset(self):
        self.assert_core(
            trace(
                [action("becomePreVoteCandidate"), action("becomeCandidate")],
                entry=entry(pre_vote=True),
            ),
            {"group_1", "group_2"},
        )

    def test_repeated_term_update_guard_keeps_the_first_copy(self):
        status, output = self.run_runner(
            trace(
                [
                    action("timeout", node=1),
                    action("requestVote", node=1, destination=0),
                    action("updateTerm", node=1, destination=0),
                    action("updateTerm", node=1, destination=0),
                ],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_3", self._core_names(output / "unsat-core.txt"))

    def test_append_batch_guard_keeps_the_log_writer(self):
        self.assert_core(
            trace([_request(0), send(batch_end=0)], queue_capacity=1),
            {"group_1", "group_2"},
        )

    def test_configuration_rejoin_guard_keeps_the_original_join(self):
        status, output = self.run_runner(
            trace(
                [
                    action("changeConfiguration", configuration=[0, 1, 2, 3, 4, 5]),
                    action("changeConfiguration", configuration=[0, 1, 2, 3, 4]),
                    action("changeConfiguration", configuration=[0, 1, 2, 3, 4, 5]),
                ],
                log_capacity=4,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_copied_log_term_bound_keeps_the_election(self):
        state = entry("follower")
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0]),
            log_entry("signature"),
        ]
        state["nodes"][0]["commitIndex"] = 1
        status, output = self.run_runner(
            trace(
                [action("timeout"), action("becomeLeader"), _request(0)],
                entry=state,
                term_count=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_copied_packet_index_bound_keeps_the_signature(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [log_entry("reconfiguration", nodes=[0, 1])]
        state["nodes"][0]["commitIndex"] = 1
        status, output = self.run_runner(
            trace(
                [
                    action("signCommittableMessages"),
                    action("checkQuorum"),
                    action("timeout"),
                    action("requestVote", destination=1),
                ],
                entry=state,
                index_count=2,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_empty_signature_guard_keeps_the_truncation(self):
        state = entry("candidate")
        state["nodes"][0]["log"] = [log_entry("transaction", transaction=0)]
        self.assert_core(
            trace(
                [action("becomeLeader"), action("signCommittableMessages")],
                entry=state,
            ),
            {"group_1", "group_2"},
        )

    def test_election_majority_guard_keeps_the_vote_reset(self):
        self.assert_core(
            trace([action("timeout"), action("becomeLeader")], entry=entry()),
            {"group_1", "group_2"},
        )

    def test_copied_message_term_core_needs_the_sender_election(self):
        self.assert_core(
            trace(
                [
                    action("timeout", node=1),
                    action("requestVote", node=1, destination=0),
                    action("updateTerm", node=1, destination=0),
                    _observation("currentTerm", 3),
                ],
                queue_capacity=1,
            ),
            {"group_1", "group_2", "group_3", "group_4"},
        )

    def test_packet_term_snapshot_survives_a_later_sender_election(self):
        self.assert_core(
            trace(
                [
                    action("timeout", node=1),
                    action("requestVote", node=1, destination=0),
                    action("timeout", node=1),
                    action("updateTerm", node=1, destination=0),
                    _observation("currentTerm", 3),
                ],
                queue_capacity=1,
            ),
            {"group_1", "group_2", "group_4", "group_5"},
        )

    def test_commit_frontier_core_needs_the_signature_writer(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [log_entry("transaction", transaction=0)]
        state["nodes"][0]["matchIndex"] = [2] * NODE_COUNT
        self.assert_core(
            trace(
                [
                    action("signCommittableMessages"),
                    action("advanceCommitIndex"),
                    _observation("commitIndex", 1),
                ],
                entry=state,
            ),
            {"group_1", "group_2", "group_3"},
        )

    def test_disabled_write_core_needs_the_demotion(self):
        self.assert_core(
            trace([action("checkQuorum"), _request(0)]),
            {"group_1", "group_2"},
        )

    def test_packet_term_bound_does_not_bypass_the_election(self):
        status, output = self.run_runner(
            trace(
                [
                    action("timeout", node=1),
                    action("requestVote", node=1, destination=0),
                ],
                term_count=2,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_disabled_send_core_needs_the_demotion(self):
        self.assert_core(
            trace(
                [action("checkQuorum"), send(batch_end=0)],
                queue_capacity=1,
            ),
            {"group_1", "group_2"},
        )

    def assert_core(self, certificate, names, *, name="run"):
        status, output = self.run_runner(certificate, name=name)
        self.assertEqual(status, "unsat")
        self.assertEqual(self._core_names(output / "unsat-core.txt"), names)
        return output

    def assert_minimal_causal_core(self, certificate, names, *, name="run"):
        status, output = self.run_runner(certificate, name=name)
        self.assertEqual(status, "unsat")
        formula = (output / "formula.smt2").read_text(encoding="utf-8")
        assert CVC5 is not None
        for removed in [None, *sorted(names)]:
            selected = names if removed is None else names - {removed}
            stem = "expected-core" if removed is None else f"without-{removed}"
            path = output / f"{stem}.smt2"
            write_formula(path, restrict_to_assertions(formula, sorted(selected)))
            result = run_solver(CVC5, path, output, stem)
            self.assertEqual(result.status, "unsat" if removed is None else "sat", stem)

    def test_every_control_rejects_absent_acting_nodes(self):
        for name in UNARY_ACTIONS + PEER_ACTIONS:
            with self.subTest(action=name):
                parameters = {"destination": 8} if name in PEER_ACTIONS else {}
                status, _ = self.run_runner(
                    trace([action(name, node=7, **parameters)]), name=name
                )
                self.assertEqual(status, "unsat")

    def test_peer_actions_require_destination_and_reject_extra_arguments(self):
        for name in PEER_ACTIONS:
            for parameters in ({}, {"destination": 1, "batchEnd": 0}):
                with self.subTest(action=name, parameters=parameters):
                    with self.assertRaises(CertificateRejected):
                        self.run_runner(trace([action(name, **parameters)]), name=name)

    def test_legacy_schema_rejects_every_control(self):
        for name in UNARY_ACTIONS + PEER_ACTIONS:
            with self.subTest(action=name):
                parameters = {"destination": 1} if name in PEER_ACTIONS else {}
                certificate = trace([action(name, **parameters)])
                certificate["schema_version"] = "ccfraft-client-request/v2"
                with self.assertRaises(CertificateRejected):
                    self.run_runner(certificate, name=name)

    def test_timeout_increments_term_and_preserves_candidate_role_ancestry(self):
        status, _ = self.run_runner(
            trace(
                [
                    action("timeout", node=1),
                    action("timeout", node=1),
                    _observation("currentTerm", 3, node=1),
                    _observation("role", "candidate", node=1),
                ]
            )
        )
        self.assertEqual(status, "sat")
        self.assert_core(
            trace(
                [
                    action("timeout", node=1),
                    action("timeout", node=1),
                    _observation("currentTerm", 1, node=1),
                ]
            ),
            {"group_1", "group_2", "group_3"},
            name="terms",
        )
        self.assert_core(
            trace(
                [
                    action("timeout", node=1),
                    action("timeout", node=1),
                    _observation("role", "follower", node=1),
                ]
            ),
            {"group_1", "group_3"},
            name="role",
        )

    def test_timeout_term_bound_is_owned_by_the_election(self):
        self.assert_core(
            trace([action("timeout", node=1)], term_count=2),
            {"group_1", "group_2"},
        )

    def test_term_binding_can_be_inspected_at_clause_granularity(self):
        status, output = self.run_runner(
            trace(
                [action("timeout", node=1), action("timeout", node=1)],
                term_count=3,
            ),
            inspect_group=2,
        )
        self.assertEqual(status, "unsat")
        core = self._core_names(output / "unsat-core.txt")
        self.assertTrue({"group_1", "group_3"}.issubset(core))
        self.assertTrue(any(name.startswith("group_2_clause_") for name in core))
        diagnosis = json.loads((output / "diagnosis.json").read_text(encoding="utf-8"))
        self.assertTrue(
            any("current term" in item.get("label", "") for item in diagnosis["items"])
        )

    def test_pre_vote_and_candidate_transitions_use_actual_guards(self):
        cases = [
            ("becomePreVoteCandidate", entry(pre_vote=True), "preVoteCandidate", 1),
            (
                "becomeCandidate",
                entry("preVoteCandidate", pre_vote=True),
                "candidate",
                2,
            ),
        ]
        for name, state, role, term in cases:
            with self.subTest(action=name):
                status, _ = self.run_runner(
                    trace(
                        [
                            action(name),
                            _observation("role", role),
                            _observation("currentTerm", term),
                        ],
                        entry=state,
                    ),
                    name=name,
                )
                self.assertEqual(status, "sat")
                self.assert_core(
                    trace([action(name), _observation("role", "leader")], entry=state),
                    {"group_1", "group_2"},
                    name=f"{name}-core",
                )
        for name, state in [
            ("timeout", entry(pre_vote=True)),
            ("becomePreVoteCandidate", entry()),
            ("becomeCandidate", entry("preVoteCandidate")),
        ]:
            with self.subTest(disabled=name):
                status, _ = self.run_runner(
                    trace([action(name)], entry=state), name=f"{name}-disabled"
                )
                self.assertEqual(status, "unsat")
        state = entry("preVoteCandidate", pre_vote=True)
        state["nodes"][0]["preVotesGranted"] = [0]
        status, _ = self.run_runner(
            trace([action("becomeCandidate")], entry=state), name="no-majority"
        )
        self.assertEqual(status, "unsat")

    def test_vote_sends_after_elections_deduplicate_and_keep_original_core(self):
        for election, send_action, state in [
            ("timeout", "requestVote", entry()),
            ("becomePreVoteCandidate", "requestPreVote", entry(pre_vote=True)),
        ]:
            with self.subTest(action=send_action):
                steps = [
                    action(election),
                    action(send_action, destination=1),
                    action(send_action, destination=1),
                ]
                status, _ = self.run_runner(
                    trace(
                        steps + [_observation("queueLength", 1, node=1)],
                        entry=state,
                        queue_capacity=1,
                    ),
                    name=send_action,
                )
                self.assertEqual(status, "sat")
                self.assert_core(
                    trace(
                        steps + [_observation("queueLength", 0, node=1)],
                        entry=state,
                        queue_capacity=1,
                    ),
                    {"group_2", "group_4"},
                    name=f"{send_action}-core",
                )
                self.assert_core(
                    trace(steps[:2], entry=state, queue_capacity=0),
                    {"group_2", "group_3"},
                    name=f"{send_action}-capacity",
                )
                status, _ = self.run_runner(
                    trace(
                        [action(send_action, destination=1)],
                        entry=state,
                        queue_capacity=1,
                    ),
                    name=f"{send_action}-disabled",
                )
                self.assertEqual(status, "unsat")

    def test_check_quorum_steps_down_without_a_failure_or_timer_flag(self):
        status, _ = self.run_runner(
            trace(
                [
                    action("checkQuorum"),
                    _observation("role", "follower"),
                    _observation("currentTerm", 1),
                    action("timeout"),
                    action("requestVote", destination=1),
                ],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "sat")
        self.assert_core(
            trace([action("checkQuorum"), _observation("role", "leader")]),
            {"group_1", "group_2"},
            name="core",
        )
        for subsequent in (_request(0), send(batch_end=0)):
            status, _ = self.run_runner(
                trace([action("checkQuorum"), subsequent], queue_capacity=1),
                name=subsequent["action"],
            )
            self.assertEqual(status, "unsat")

    def test_update_term_selects_the_first_source_message_without_consuming_it(self):
        state = entry("leader")
        state["network"][0] = [
            {
                "kind": "requestVoteRequest",
                "term": 3,
                "source": 1,
                "destination": 0,
                "lastCommittableTerm": 0,
                "lastCommittableIndex": 0,
            }
        ]
        steps = [
            action("updateTerm", node=1, destination=0),
            _observation("role", "follower"),
            _observation("currentTerm", 3),
            _observation("queueLength", 1),
        ]
        status, _ = self.run_runner(trace(steps, entry=state, queue_capacity=1))
        self.assertEqual(status, "sat")
        for variable, value in (("role", "leader"), ("currentTerm", 1)):
            self.assert_core(
                trace(
                    [steps[0], _observation(variable, value)],
                    entry=state,
                    queue_capacity=1,
                ),
                {"group_1", "group_2"},
                name=variable,
            )
        first = copy.deepcopy(state["network"][0][0])
        first["term"] = 1
        state["network"][0].insert(0, first)
        status, _ = self.run_runner(
            trace([steps[0]], entry=state, queue_capacity=2), name="first-only"
        )
        self.assertEqual(status, "unsat")

    def test_new_vote_packet_updates_the_destination_term(self):
        status, _ = self.run_runner(
            trace(
                [
                    action("timeout", node=1),
                    action("requestVote", node=1, destination=0),
                    action("updateTerm", node=1, destination=0),
                    _observation("currentTerm", 2),
                    _observation("role", "follower"),
                    _observation("queueLength", 1),
                    _observation("role", "candidate", node=1),
                ],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "sat")

    def test_become_leader_truncates_then_writes_and_sends(self):
        status, _ = self.run_runner(
            trace(
                [
                    action("becomeLeader"),
                    _observation("logLength", 2),
                    _request(1),
                    send(batch_end=3),
                    _observation("logLength", 3),
                    _observation("queueLength", 1, node=1),
                ],
                entry=promotable_entry(),
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "sat")
        self.assert_core(
            trace(
                [
                    action("becomeLeader"),
                    _request(1),
                    _observation("logLength", 4),
                ],
                entry=promotable_entry(),
            ),
            {"group_1", "group_2", "group_3"},
            name="truncation-core",
        )
        state = promotable_entry()
        state["nodes"][0]["votesGranted"] = [0]
        status, _ = self.run_runner(
            trace([action("becomeLeader")], entry=state), name="no-majority"
        )
        self.assertEqual(status, "unsat")

    def test_become_leader_sent_index_bound_is_causal(self):
        self.assert_core(
            trace(
                [action("becomeLeader")],
                entry=promotable_entry(),
                index_count=2,
            ),
            {"group_1", "group_2"},
        )

    def test_truncation_core_does_not_need_a_discarded_write(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0]),
            log_entry("signature"),
        ]
        state["nodes"][0]["commitIndex"] = 1
        state["network"][0] = [
            {
                "kind": "requestVoteRequest",
                "term": 2,
                "source": 1,
                "destination": 0,
                "lastCommittableTerm": 0,
                "lastCommittableIndex": 0,
            }
        ]
        steps = [
            _request(0),
            action("updateTerm", node=1, destination=0),
            action("timeout"),
            action("becomeLeader"),
        ]
        status, _ = self.run_runner(
            trace(
                steps + [_observation("logLength", 2)],
                entry=state,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "sat")
        self.assert_core(
            trace(
                steps + [_observation("logLength", 3)],
                entry=state,
                queue_capacity=1,
            ),
            {"group_4", "group_5"},
            name="truncation-core",
        )

    def test_promotion_core_retains_the_signature_position_writer(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0]),
            log_entry("signature"),
        ]
        state["nodes"][0]["commitIndex"] = 1
        state["network"][0] = [
            {
                "kind": "requestVoteRequest",
                "term": 2,
                "source": 1,
                "destination": 0,
                "lastCommittableTerm": 0,
                "lastCommittableIndex": 0,
            }
        ]
        self.assert_minimal_causal_core(
            trace(
                [
                    _request(0),
                    action("signCommittableMessages"),
                    _request(1),
                    action("updateTerm", node=1, destination=0),
                    action("timeout"),
                    action("becomeLeader"),
                    _observation("logLength", 5),
                ],
                entry=state,
                log_capacity=8,
                index_count=9,
                queue_capacity=1,
            ),
            {"group_1", "group_2", "group_6", "group_7"},
        )

    def test_commit_advances_and_retains_its_causal_observation(self):
        steps = [
            action("advanceCommitIndex"),
            _observation("commitIndex", 1),
            _request(1),
            send(batch_end=1),
        ]
        status, _ = self.run_runner(
            trace(steps, entry=committable_entry(), queue_capacity=1)
        )
        self.assertEqual(status, "sat")
        self.assert_core(
            trace(
                [steps[0], _observation("commitIndex", 0)],
                entry=committable_entry(),
            ),
            {"group_1", "group_2"},
            name="core",
        )
        status, _ = self.run_runner(
            trace([action("advanceCommitIndex")]), name="no-signature"
        )
        self.assertEqual(status, "unsat")

    def test_commit_index_bound_uses_the_action_binding(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[0]),
            log_entry("signature"),
        ]
        state["nodes"][0]["commitIndex"] = 1
        self.assert_core(
            trace([action("advanceCommitIndex")], entry=state, index_count=2),
            {"group_1", "group_2"},
        )

    def test_propose_vote_is_a_deduplicated_send_not_a_local_election(self):
        steps = [
            action("proposeVote", destination=1),
            action("proposeVote", destination=1),
        ]
        status, _ = self.run_runner(
            trace(
                steps
                + [
                    _observation("role", "leader"),
                    _observation("role", "follower", node=1),
                    _observation("queueLength", 1, node=1),
                ],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "sat")
        self.assert_core(
            trace(
                steps + [_observation("queueLength", 0, node=1)],
                queue_capacity=1,
            ),
            {"group_1", "group_3"},
            name="core",
        )
        state = entry("leader")
        state["nodes"][0]["matchIndex"][2] = 1
        status, _ = self.run_runner(
            trace(
                [action("proposeVote", destination=1)], entry=state, queue_capacity=1
            ),
            name="not-best-successor",
        )
        self.assertEqual(status, "unsat")

    def test_terminal_commit_demotes_and_sends_atomically(self):
        state = committable_entry(terminal=True)
        terminal = action("advanceCommitIndexAndProposeVote", destination=1)
        status, _ = self.run_runner(
            trace(
                [
                    terminal,
                    _observation("commitIndex", 4),
                    _observation("role", "follower"),
                    _observation("queueLength", 1, node=1),
                ],
                entry=state,
                index_count=5,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "sat")
        for variable, value, node in [
            ("commitIndex", 2, 0),
            ("role", "leader", 0),
            ("queueLength", 0, 1),
        ]:
            self.assert_core(
                trace(
                    [terminal, _observation(variable, value, node=node)],
                    entry=state,
                    index_count=5,
                    queue_capacity=1,
                ),
                {"group_1", "group_2"},
                name=variable,
            )
        for name, candidate in [
            ("ordinary-terminal", action("advanceCommitIndex")),
            ("repeat-terminal", terminal),
        ]:
            steps = (
                [candidate] if name == "ordinary-terminal" else [terminal, candidate]
            )
            status, _ = self.run_runner(
                trace(steps, entry=state, index_count=5, queue_capacity=1), name=name
            )
            self.assertEqual(status, "unsat")
        status, _ = self.run_runner(
            trace([terminal], entry=committable_entry(), queue_capacity=1),
            name="nonterminal",
        )
        self.assertEqual(status, "unsat")

    def test_terminal_commit_preserves_an_existing_duplicate_packet(self):
        state = committable_entry(terminal=True)
        state["network"][1] = [
            {
                "kind": "proposeVoteRequest",
                "term": 1,
                "source": 0,
                "destination": 1,
            }
        ]
        status, _ = self.run_runner(
            trace(
                [
                    action("advanceCommitIndexAndProposeVote", destination=1),
                    _observation("commitIndex", 4),
                    _observation("role", "follower"),
                    _observation("queueLength", 1, node=1),
                ],
                entry=state,
                index_count=5,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "sat")

    def test_control_bindings_survive_symbolic_send_branches(self):
        state = queued_entry()
        state["nodes"][1]["votesGranted"] = [0, 1, 2]
        for same in (True, False):
            with self.subTest(alias=same):
                steps = [
                    send(node=1, destination=0),
                    action("checkQuorum", node=1),
                    action("timeout", node=1),
                    _observation("currentTerm", 8, node=1),
                    action("requestVote", node=1, destination=0),
                    _observation("queueLength", 2 if same else 3, node=0),
                ]
                # The submitted old transaction determines whether the queued payload aliases.
                steps.insert(
                    0,
                    {
                        "kind": "observation",
                        "variable": "submitted",
                        "transaction": {"unknown": "queued"},
                        "value": same,
                    },
                )
                status, output = self.run_runner(
                    trace(
                        steps,
                        entry=state,
                        unknowns=["old", "queued"],
                        term_count=9,
                        queue_capacity=3,
                    ),
                    name=f"alias-{same}",
                )
                self.assertEqual(status, "sat")
                mapping = json.loads(
                    (output / "constraint-map.json").read_text(encoding="utf-8")
                )
                self.assertEqual(len(mapping["groups"]), len(steps) + 2)


if __name__ == "__main__":
    unittest.main()
