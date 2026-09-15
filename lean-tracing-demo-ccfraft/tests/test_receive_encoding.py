# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Concrete receive traces preserve guarded aliases and actual packet semantics."""

import json
import subprocess
import unittest

from tests.test_client_request_encoding import (
    CVC5,
    ROOT,
    SOLVER_TESTS,
    ClientRequestSliceTestCase,
    _observation,
    _submitted,
)
from tests.test_control_encoding import committable_entry, entry, log_entry
from tests.test_leader_writes import action, trace
from tests.test_replication_encoding import send
from Shared.smt import restrict_to_assertions, write_formula
from Shared.solver import run_solver


def packet(kind, *, source=1, destination=0, term=1, **fields):
    return {
        "kind": kind,
        "term": term,
        "source": source,
        "destination": destination,
        **fields,
    }


def receive(source=1, destination=0):
    return action("receive", node=source, destination=destination)


def request(kind="appendEntriesRequest", **fields):
    defaults = (
        dict(prevLogIndex=0, prevLogTerm=0, entries=[], leaderCommit=0)
        if kind == "appendEntriesRequest"
        else dict(lastCommittableIndex=0, lastCommittableTerm=0)
    )
    defaults.update(fields)
    return packet(kind, **defaults)


class ReceiveBindingGrowthTests(unittest.TestCase):
    @SOLVER_TESTS
    def test_repeated_stale_append_does_not_duplicate_prior_state(self):
        result = subprocess.run(
            [
                "nice",
                "-n",
                "10",
                "lake",
                "env",
                "lean",
                "--run",
                "MachineGenerated/ReceiveTraceScalingMain.lean",
                "stale",
                "12",
                "15",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([row["repetitions"] for row in rows], [12, 15])
        for row in rows:
            count = row["repetitions"]
            # Each iteration adds at most 42 operators; the initial graph adds 16.
            node_budget = 42 * count + 16
            byte_budget = node_budget * (128 + 8 * len(str(node_budget))) + 2048
            for field in ("log", "commit"):
                self.assertEqual(row[f"{field}_bindings"], 2)
                self.assertGreaterEqual(row[f"{field}_dag_nodes"], count)
                self.assertLessEqual(row[f"{field}_dag_nodes"], node_budget)
                self.assertLessEqual(row[f"{field}_bytes"], byte_budget)
            self.assertLessEqual(row["formula_bytes"], byte_budget)
            for field, expected in (("smt", "sat"), ("wrong_smt", "unsat")):
                solved = subprocess.run(
                    [CVC5, "--lang=smt2"],
                    input=row[field],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(solved.stdout.strip(), expected)
        self.assertLessEqual(
            rows[1]["formula_bytes"] * rows[0]["repetitions"],
            rows[0]["formula_bytes"] * (rows[1]["repetitions"] + 1),
        )

    def test_conditional_nack_clamp_does_not_duplicate_prior_history(self):
        result = subprocess.run(
            [
                "nice",
                "-n",
                "10",
                "lake",
                "env",
                "lean",
                "--run",
                "MachineGenerated/ReceiveTraceScalingMain.lean",
                "12",
                "15",
                "64",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([row["actual"] for row in rows], [2, 2, 2])
        self.assertEqual([row["unconditional_bindings"] for row in rows], [14, 17, 66])
        self.assertEqual([row["conditional_bindings"] for row in rows], [26, 32, 130])
        for row in rows:
            count = row["repetitions"]
            self.assertLessEqual(
                row["conditional_bytes"], count * (320 + 8 * len(str(count))) + 128
            )


@SOLVER_TESTS
class ReceiveEncodingTests(ClientRequestSliceTestCase):
    def assert_producer_necessary(self, output, producer):
        metadata = json.loads((output / "constraint-map.json").read_text())
        names = [
            group["name"] for group in metadata["groups"] if group["name"] != producer
        ]
        formula = (output / "formula.smt2").read_text()
        path = output / f"without-{producer}.smt2"
        write_formula(path, restrict_to_assertions(formula, names))
        self.assertEqual(
            run_solver(CVC5, path, output, f"without-{producer}").status, "sat"
        )

    def test_stale_append_noop_keeps_the_election_cause(self):
        for variable in ("logLength", "commitIndex"):
            with self.subTest(variable=variable):
                state = entry()
                state["network"][0] = [
                    request(entries=[log_entry("signature")], leaderCommit=1)
                ]
                status, output = self.run_runner(
                    trace(
                        [action("timeout"), receive(), _observation(variable, 1)],
                        entry=state,
                        queue_capacity=2,
                    ),
                    name=f"stale-{variable}",
                )
                self.assertEqual(status, "unsat")
                self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))
                self.assert_producer_necessary(output, "group_1")
                status, _ = self.run_runner(
                    trace(
                        [receive(), _observation(variable, 1)],
                        entry=state,
                        queue_capacity=2,
                    ),
                    name=f"accepted-{variable}",
                )
                self.assertEqual(status, "sat")

    def test_dequeue_keeps_prior_candidate_stepdown(self):
        state = entry("candidate")
        state["network"][0] = [request()]
        status, output = self.run_runner(
            trace([receive(), receive(), receive()], entry=state, queue_capacity=2),
            name="third-receive",
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))
        self.assert_producer_necessary(output, "group_1")
        status, _ = self.run_runner(
            trace([receive(), receive()], entry=state, queue_capacity=2),
            name="without-first-receive",
        )
        self.assertEqual(status, "sat")

    def test_conflict_retry_consumes_new_follower_permission(self):
        state = entry("candidate")
        old = log_entry("transaction", transaction=0)
        old["term"] = 0
        newer = log_entry("transaction", transaction=0)
        newer["term"] = 2
        state["nodes"][0]["log"] = [old]
        state["network"][0] = [
            request(entries=[log_entry("transaction", transaction=0)]),
            request(entries=[newer]),
        ]
        status, _ = self.run_runner(
            trace(
                [receive(), receive(), _observation("logLength", 1)],
                entry=state,
                queue_capacity=2,
            ),
            name="first-conflict",
        )
        self.assertEqual(status, "sat")
        status, output = self.run_runner(
            trace(
                [receive(), receive(), receive()],
                entry=state,
                queue_capacity=2,
            ),
            name="second-conflict",
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_2", self._core_names(output / "unsat-core.txt"))

    def test_received_retirement_record_disables_later_election(self):
        state = entry()
        state["nodes"][0]["log"] = [
            log_entry("reconfiguration", nodes=[1, 2, 3, 4]),
            log_entry("signature"),
        ]
        state["network"][0] = [
            request(
                prevLogIndex=2,
                prevLogTerm=1,
                entries=[
                    log_entry("retiredCommitted", nodes=[0]),
                    log_entry("signature"),
                ],
                leaderCommit=4,
            )
        ]
        status, _ = self.run_runner(
            trace(
                [receive(), _observation("commitIndex", 4)],
                entry=state,
                queue_capacity=2,
                index_count=8,
            ),
            name="retired",
        )
        self.assertEqual(status, "sat")
        status, output = self.run_runner(
            trace(
                [receive(), action("timeout")],
                entry=state,
                queue_capacity=2,
                index_count=8,
            ),
            name="retired-election",
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_rejected_append_refreshes_stale_retirement_completed(self):
        state = entry("leader")
        state["retirementCompleted"][0] = [1]
        state["network"][0] = [request(term=0)]
        status, output = self.run_runner(
            trace(
                [receive(), action("appendRetiredCommitted")],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_signature_only_receive_does_not_own_unchanged_configuration(self):
        state = entry()
        state["network"][0] = [request(entries=[log_entry("signature")])]
        state["nodes"][0]["votesGranted"] = [0, 1, 2]
        status, output = self.run_runner(
            trace(
                [receive(), action("timeout"), action("becomeLeader")],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertNotIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_extension_content_mismatch_keeps_the_signature_writer(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [log_entry("transaction", transaction=0)]
        state["network"][0] = [
            request(
                entries=[
                    log_entry("transaction", transaction=0),
                    log_entry("transaction", transaction=1),
                    log_entry("signature"),
                ]
            )
        ]
        status, output = self.run_runner(
            trace(
                [action("signCommittableMessages"), action("checkQuorum"), receive()],
                entry=state,
                transaction_count=2,
                queue_capacity=2,
                index_count=8,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_vote_reply_deduplication_keeps_signature_denial(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [log_entry("transaction", transaction=0)]
        state["network"][0] = [request("requestVoteRequest")]
        state["network"][1] = [
            packet("requestVoteResponse", source=0, destination=1, voteGranted=True)
        ]
        status, output = self.run_runner(
            trace(
                [
                    action("signCommittableMessages"),
                    receive(),
                    _observation("queueLength", 1, node=1),
                ],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_append_reply_deduplication_keeps_receiver_election(self):
        state = entry()
        state["network"][0] = [request()]
        state["network"][1] = [
            packet(
                "appendEntriesResponse",
                source=0,
                destination=1,
                success=True,
                lastLogIndex=0,
                term=1,
            )
        ]
        status, output = self.run_runner(
            trace(
                [action("timeout"), receive(), _observation("queueLength", 1, node=1)],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_append_stepdown_keeps_the_receiver_term_writer(self):
        state = entry("candidate")
        state["network"][0] = [request(term=2)]
        status, output = self.run_runner(
            trace(
                [action("timeout"), receive(), _observation("role", "candidate")],
                entry=state,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_received_configuration_keeps_the_configuration_writer(self):
        state = entry("leader")
        state["nodes"][1]["role"] = "follower"
        state["network"][1] = [
            packet(
                "requestVoteResponse", source=2, destination=1, term=2, voteGranted=True
            ),
            packet(
                "requestVoteResponse", source=3, destination=1, term=2, voteGranted=True
            ),
        ]
        status, output = self.run_runner(
            trace(
                [
                    action("changeConfiguration", configuration=[4]),
                    send(),
                    receive(source=0, destination=1),
                    action("timeout", node=1),
                    receive(source=2, destination=1),
                    receive(source=3, destination=1),
                    action("becomeLeader", node=1),
                ],
                entry=state,
                queue_capacity=3,
                index_count=8,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_received_commit_keeps_the_leader_commit_writer(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [
            log_entry("transaction", transaction=0),
            log_entry("signature"),
        ]
        state["nodes"][0]["matchIndex"] = [2] * len(state["nodes"])
        state["nodes"][1]["role"] = "follower"
        status, output = self.run_runner(
            trace(
                [
                    action("advanceCommitIndex"),
                    send(),
                    receive(source=0, destination=1),
                    send(batch_end=2),
                    receive(source=0, destination=1),
                    _observation("commitIndex", 0, node=1),
                ],
                entry=state,
                queue_capacity=3,
                index_count=8,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_received_log_length_keeps_the_packet_sender(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [log_entry("transaction", transaction=0)]
        state["nodes"][1]["role"] = "follower"
        status, output = self.run_runner(
            trace(
                [
                    action("signCommittableMessages"),
                    send(),
                    receive(source=0, destination=1),
                    send(batch_end=2),
                    receive(source=0, destination=1),
                    _observation("logLength", 3, node=1),
                ],
                entry=state,
                queue_capacity=3,
                index_count=8,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_4", self._core_names(output / "unsat-core.txt"))

    def test_received_log_term_keeps_sender_in_later_vote_snapshot(self):
        state = entry("leader")
        signature = log_entry("signature")
        signature["term"] = 2
        state["nodes"][0]["log"] = [signature]
        state["nodes"][1]["role"] = "follower"
        state["network"][2] = [
            request(
                "requestVoteRequest",
                source=1,
                destination=2,
                term=2,
                lastCommittableIndex=1,
                lastCommittableTerm=1,
            )
        ]
        status, output = self.run_runner(
            trace(
                [
                    send(),
                    receive(source=0, destination=1),
                    action("timeout", node=1),
                    action("requestVote", node=1, destination=2),
                    _observation("queueLength", 1, node=2),
                ],
                entry=state,
                queue_capacity=3,
                index_count=8,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_append_failure_term_keeps_the_receiver_election(self):
        state = entry()
        state["network"][0] = [request()]
        status, output = self.run_runner(
            trace(
                [
                    action("timeout"),
                    receive(),
                    action("updateTerm", node=0, destination=1),
                    _observation("currentTerm", 3, node=1),
                ],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_append_failure_index_keeps_the_signature_writer(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [log_entry("transaction", transaction=0)]
        state["nodes"][1]["log"] = [
            log_entry("transaction", transaction=0) for _ in range(3)
        ]
        state["nodes"][1]["sentIndex"][0] = 3
        state["network"][0] = [request(term=0)]
        status, output = self.run_runner(
            trace(
                [
                    action("signCommittableMessages"),
                    receive(),
                    receive(source=0, destination=1),
                    send(node=1, destination=0, batch_end=2),
                ],
                entry=state,
                queue_capacity=2,
                index_count=8,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_append_commit_guard_keeps_the_commit_writer(self):
        state = committable_entry()
        state["network"][0] = [request()]
        status, output = self.run_runner(
            trace(
                [action("advanceCommitIndex"), action("checkQuorum"), receive()],
                entry=state,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_nack_search_keeps_the_signature_writer_in_later_send_guard(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [log_entry("transaction", transaction=0)]
        state["nodes"][0]["sentIndex"][1] = 3
        state["network"][0] = [
            packet("appendEntriesResponse", success=False, lastLogIndex=2)
        ]
        status, output = self.run_runner(
            trace(
                [action("signCommittableMessages"), receive(), send(batch_end=1)],
                entry=state,
                queue_capacity=2,
                index_count=8,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_nack_clamps_against_match_even_in_unreachable_entry(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [
            log_entry("transaction", transaction=0),
            log_entry("signature"),
        ]
        state["nodes"][0]["matchIndex"][1] = 1
        state["nodes"][0]["sentIndex"][1] = 0
        state["network"][0] = [
            packet("appendEntriesResponse", success=False, lastLogIndex=0)
        ]
        status, _ = self.run_runner(
            trace(
                [receive(), send(batch_end=2)],
                entry=state,
                queue_capacity=2,
                index_count=8,
            )
        )
        self.assertEqual(status, "sat")

    def test_ack_leaves_sent_index_below_match_unchanged(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [
            log_entry("transaction", transaction=0),
            log_entry("signature"),
        ]
        state["nodes"][0]["matchIndex"][1] = 2
        state["nodes"][0]["sentIndex"][1] = 0
        state["network"][0] = [
            packet("appendEntriesResponse", success=True, lastLogIndex=1)
        ]
        status, _ = self.run_runner(
            trace(
                [receive(), send(batch_end=1)],
                entry=state,
                queue_capacity=2,
                index_count=8,
            )
        )
        self.assertEqual(status, "sat")

    def test_proposal_term_update_keeps_the_proposal_sender(self):
        status, output = self.run_runner(
            trace(
                [
                    action("proposeVote", destination=1),
                    receive(source=0, destination=1),
                    _observation("currentTerm", 1, node=1),
                ],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_proposal_role_update_keeps_the_prior_demotion(self):
        state = entry("leader")
        state["network"][0] = [packet("proposeVoteRequest")]
        status, output = self.run_runner(
            trace(
                [action("checkQuorum"), receive(), _observation("role", "leader")],
                entry=state,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_stale_proposal_has_no_spurious_term_writer(self):
        state = entry()
        state["nodes"][0]["currentTerm"] = 2
        state["nodes"][1]["role"] = "leader"
        status, output = self.run_runner(
            trace(
                [
                    action("proposeVote", node=1, destination=0),
                    receive(),
                    _observation("currentTerm", 3),
                ],
                entry=state,
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        core = self._core_names(output / "unsat-core.txt")
        self.assertIn("group_1", core)
        self.assertNotIn("group_2", core)

    def test_proposal_election_ignores_pre_vote_status_and_resets_votes(self):
        state = entry(pre_vote=True)
        state["network"][0] = [packet("proposeVoteRequest")]
        status, _ = self.run_runner(
            trace(
                [
                    receive(),
                    _observation("role", "candidate"),
                    _observation("currentTerm", 2),
                ],
                entry=state,
                queue_capacity=1,
            ),
            name="candidate",
        )
        self.assertEqual(status, "sat")
        status, output = self.run_runner(
            trace([receive(), action("becomeLeader")], entry=state, queue_capacity=1),
            name="reset-votes",
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_vote_tally_keeps_the_signature_that_caused_denial(self):
        state = entry("leader")
        state["nodes"][0]["log"] = [log_entry("transaction", transaction=0)]
        state["nodes"][1]["role"] = "candidate"
        state["nodes"][1]["votesGranted"] = [1, 2]
        status, output = self.run_runner(
            trace(
                [
                    action("signCommittableMessages"),
                    action("requestVote", node=1, destination=0),
                    receive(),
                    receive(source=0, destination=1),
                    action("becomeLeader", node=1),
                ],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_prior_vote_assignment_explains_a_later_denial(self):
        state = entry()
        state["nodes"][2]["role"] = "candidate"
        state["nodes"][2]["votesGranted"] = [2, 3]
        state["network"][0] = [
            request("requestVoteRequest"),
            request("requestVoteRequest", source=2),
        ]
        status, output = self.run_runner(
            trace(
                [
                    receive(),
                    receive(source=2),
                    receive(source=0, destination=2),
                    action("becomeLeader", node=2),
                ],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_vote_reply_term_keeps_the_receiver_election(self):
        state = entry("leader")
        state["nodes"][1]["role"] = "follower"
        state["network"][0] = [request("requestVoteRequest")]
        status, output = self.run_runner(
            trace(
                [
                    action("checkQuorum"),
                    action("timeout"),
                    receive(),
                    action("updateTerm", node=0, destination=1),
                    _observation("currentTerm", 3, node=1),
                ],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_2", self._core_names(output / "unsat-core.txt"))

    def test_newer_vote_request_guard_keeps_the_sender_election(self):
        status, output = self.run_runner(
            trace(
                [
                    action("timeout", node=1),
                    action("requestVote", node=1, destination=0),
                    receive(),
                ],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_future_vote_response_guard_keeps_the_receiver_election(self):
        state = entry()
        state["network"][0] = [packet("requestVoteResponse", term=3, voteGranted=True)]
        status, output = self.run_runner(
            trace([action("timeout"), receive()], entry=state, queue_capacity=1)
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_empty_source_guard_keeps_the_consuming_receive(self):
        state = entry()
        state["network"][0] = [
            request("requestVoteRequest"),
            request("requestVoteRequest", source=2),
        ]
        status, output = self.run_runner(
            trace([receive(), receive()], entry=state, queue_capacity=2)
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_later_term_copy_keeps_first_packet_removal(self):
        state = entry()
        state["nodes"][0]["currentTerm"] = 0
        state["network"][0] = [
            packet("requestVoteResponse", voteGranted=True),
            request("requestVoteRequest", term=2),
        ]
        status, output = self.run_runner(
            trace(
                [
                    receive(),
                    action("updateTerm", node=1, destination=0),
                    _observation("currentTerm", 1),
                ],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertIn("group_1", self._core_names(output / "unsat-core.txt"))

    def test_all_seven_packet_families(self):
        for message, role, reply in [
            (request(), "follower", True),
            (
                packet("appendEntriesResponse", success=True, lastLogIndex=1),
                "leader",
                False,
            ),
            (request("requestVoteRequest"), "follower", True),
            (packet("requestVoteResponse", voteGranted=True), "candidate", False),
            (request("requestPreVote"), "follower", True),
            (
                packet("requestPreVoteResponse", voteGranted=True),
                "preVoteCandidate",
                False,
            ),
            (packet("proposeVoteRequest"), "follower", False),
        ]:
            with self.subTest(kind=message["kind"]):
                state = entry(role)
                state["network"][0] = [message]
                status, _ = self.run_runner(
                    trace(
                        [
                            receive(),
                            _observation("queueLength", 0),
                            _observation("queueLength", int(reply), node=1),
                        ],
                        entry=state,
                        queue_capacity=2,
                        index_count=8,
                    ),
                    name=message["kind"],
                )
                self.assertEqual(status, "sat")

    def test_empty_queue_and_absent_destination_are_disabled(self):
        for absent in (False, True):
            with self.subTest(absent=absent):
                state = entry()
                if absent:
                    state["nodes"][0] = None
                    state["network"][0] = [request()]
                status, _ = self.run_runner(
                    trace([receive()], entry=state, queue_capacity=2),
                    name=f"absent-{absent}",
                )
                self.assertEqual(status, "unsat")

    def test_first_matching_source_is_selected_not_queue_head(self):
        state = entry()
        state["network"][0] = [
            request("requestVoteRequest", source=2, term=2),
            request("requestVoteRequest"),
        ]
        status, _ = self.run_runner(
            trace(
                [receive(), _observation("queueLength", 1)],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "sat")

    def test_does_not_skip_a_disabled_first_packet_from_the_same_source(self):
        state = entry()
        state["network"][0] = [
            request("requestVoteRequest", term=2),
            request("requestVoteRequest"),
        ]
        status, _ = self.run_runner(trace([receive()], entry=state, queue_capacity=2))
        self.assertEqual(status, "unsat")

    def test_self_receive_deduplicates_against_the_post_dequeue_queue(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                state = entry()
                state["network"][0] = [request("requestPreVote", source=0)]
                if existing:
                    state["network"][0].append(
                        packet("requestPreVoteResponse", source=0, voteGranted=True)
                    )
                status, _ = self.run_runner(
                    trace(
                        [receive(source=0), _observation("queueLength", 1)],
                        entry=state,
                        queue_capacity=2,
                    ),
                    name=f"existing-{existing}",
                )
                self.assertEqual(status, "sat")

    def test_same_term_candidate_steps_down_without_consuming_or_replying(self):
        state = entry("candidate")
        state["network"][0] = [request()]
        status, _ = self.run_runner(
            trace(
                [
                    receive(),
                    _observation("role", "follower"),
                    _observation("queueLength", 1),
                    _observation("queueLength", 0, node=1),
                    receive(),
                    _observation("queueLength", 0),
                    _observation("queueLength", 1, node=1),
                ],
                entry=state,
                queue_capacity=2,
            )
        )
        self.assertEqual(status, "sat")

    def test_transaction_alias_controls_prefix_extension_enabledness(self):
        for aliases in (False, True):
            with self.subTest(aliases=aliases):
                state = entry()
                state["submittedTxIds"] = [0]
                state["nodes"][0]["log"] = [
                    log_entry("transaction", transaction={"unknown": "old"})
                ]
                state["network"][0] = [
                    request(
                        entries=[
                            log_entry("transaction", transaction=0),
                            log_entry("signature"),
                        ]
                    )
                ]
                status, _ = self.run_runner(
                    trace(
                        [
                            _submitted({"unknown": "old"}, aliases),
                            receive(),
                            _observation("logLength", 2),
                        ],
                        entry=state,
                        unknowns=["old"],
                        queue_capacity=2,
                    ),
                    name=f"aliases-{aliases}",
                )
                self.assertEqual(status, "sat" if aliases else "unsat")

    def test_received_votes_enable_later_control_actions(self):
        for pre_vote in (False, True):
            with self.subTest(pre_vote=pre_vote):
                state = entry(
                    "preVoteCandidate" if pre_vote else "candidate", pre_vote=pre_vote
                )
                state["nodes"][0]["preVotesGranted" if pre_vote else "votesGranted"] = [
                    0,
                    1,
                ]
                state["network"][0] = [
                    packet(
                        "requestPreVoteResponse" if pre_vote else "requestVoteResponse",
                        source=2,
                        voteGranted=True,
                    )
                ]
                status, _ = self.run_runner(
                    trace(
                        [
                            receive(source=2),
                            action("becomeCandidate" if pre_vote else "becomeLeader"),
                        ],
                        entry=state,
                        queue_capacity=1,
                    ),
                    name=f"pre-vote-{pre_vote}",
                )
                self.assertEqual(status, "sat")
