# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Exercise symbolic certificates through the audited native encoder and solver."""

from __future__ import annotations

import json
import unittest

from Shared.smt import restrict_to_assertions
from Shared.solver import ValidationError, run_solver
from tests.test_client_request_encoding import (
    CVC5,
    SOLVER_TESTS,
    SYMBOLIC_THEOREM,
    CertificateRejected,
    ClientRequestSliceTestCase,
    _observation,
    _request,
    _submitted,
)
from tests.test_leader_writes import action, trace


def symbolic_trace(steps: list[dict[str, object]], **bounds: int) -> dict[str, object]:
    document = trace(steps, entry="symbolic", **bounds)
    document["schema_version"] = "ccfraft-symbolic-trace/v1"
    return document


ZERO_BOUNDS = {
    "transaction_count": 0,
    "term_count": 0,
    "index_count": 0,
    "log_capacity": 0,
    "queue_capacity": 0,
}


@SOLVER_TESTS
class SymbolicBackendTests(ClientRequestSliceTestCase):
    def test_zero_bounds_allow_an_empty_absent_entry(self) -> None:
        status, output = self.run_runner(symbolic_trace([], **ZERO_BOUNDS))
        self.assertEqual(status, "sat")
        assurance = self.result(output)["assurance"]
        self.assertEqual(assurance["entry"], "symbolic")
        self.assertEqual(assurance["encoder_theorem"], SYMBOLIC_THEOREM)
        self.assertEqual(len(assurance["supported_actions"]), 17)

    def test_zero_transaction_domain_rejects_a_declared_unknown(self) -> None:
        document = symbolic_trace([], **ZERO_BOUNDS)
        document["unknowns"] = ["tx"]
        status, output = self.run_runner(document)
        self.assertEqual(status, "unsat")
        self.assertEqual(self._core_names(output / "unsat-core.txt"), {"group_0"})

    def test_entry_is_not_restricted_to_bootstrap_or_low_node_ids(self) -> None:
        document = symbolic_trace(
            [
                _observation("allocated", True, node=14),
                _observation("role", "follower", node=14),
                _observation("currentTerm", 2, node=14),
            ],
            transaction_count=0,
            term_count=3,
            index_count=1,
            log_capacity=0,
            queue_capacity=0,
        )
        status, _ = self.run_runner(document)
        self.assertEqual(status, "sat")

    def test_transaction_names_may_alias(self) -> None:
        document = symbolic_trace(
            [
                _submitted({"unknown": "a"}, True),
                _submitted({"unknown": "b"}, True),
            ],
            **{**ZERO_BOUNDS, "transaction_count": 1},
        )
        document["unknowns"] = ["a", "b"]
        status, _ = self.run_runner(document)
        self.assertEqual(status, "sat")

    def test_all_actions_reject_an_absent_zero_bound_actor(self) -> None:
        actions = [
            _request(0),
            action("signCommittableMessages"),
            action("changeConfiguration", configuration=[0]),
            action("appendRetiredCommitted"),
            action("appendEntries", destination=1, batchEnd=0),
            action("receive", destination=0),
            *[
                action(name)
                for name in (
                    "timeout",
                    "becomePreVoteCandidate",
                    "becomeCandidate",
                    "advanceCommitIndex",
                    "checkQuorum",
                    "becomeLeader",
                )
            ],
            *[
                action(name, destination=1)
                for name in (
                    "updateTerm",
                    "requestVote",
                    "requestPreVote",
                    "proposeVote",
                    "advanceCommitIndexAndProposeVote",
                )
            ],
        ]
        self.assertEqual(len(actions), 17)
        for instruction in actions:
            with self.subTest(action=instruction["action"]):
                status, _ = self.run_runner(
                    symbolic_trace([instruction], **ZERO_BOUNDS),
                    name=str(instruction["action"]),
                )
                self.assertEqual(status, "unsat")

    def test_client_successor_and_causal_definition(self) -> None:
        before = [
            _observation("allocated", True),
            _observation("role", "leader"),
            _observation("membershipState", "active"),
            _observation("logLength", 0),
        ]
        action_index = len(before) + 1
        for length in (1, 0):
            with self.subTest(log_length=length):
                document = symbolic_trace(
                    [*before, _request(0), _observation("logLength", length)],
                    transaction_count=1,
                    term_count=1,
                    index_count=2,
                    log_capacity=1,
                    queue_capacity=0,
                )
                status, output = self.run_runner(
                    document, name=f"client-{length}", inspect_group=action_index
                )
                self.assertEqual(status, "sat" if length == 1 else "unsat")
                if length == 0:
                    mapping = json.loads(
                        (output / "constraint-map.json").read_text(encoding="utf-8")
                    )
                    definitions = {
                        clause["name"]
                        for clause in mapping["groups"][action_index]["clauses"]
                        if clause["label"] == "successor_definition"
                    }
                    self.assertTrue(definitions)
                    self.assertTrue(
                        definitions & self._core_names(output / "unsat-core.txt")
                    )

    def test_inspection_requires_an_action(self) -> None:
        document = symbolic_trace([_observation("allocated", False)], **ZERO_BOUNDS)
        with self.assertRaisesRegex(ValidationError, "starts at 1"):
            self.run_runner(document, inspect_group=0, name="inspect-0")
        for index in (1, 2):
            with self.subTest(index=index), self.assertRaises(CertificateRejected):
                self.run_runner(
                    document,
                    inspect_group=index,
                    name=f"inspect-{index}",
                )

    def test_network_write_does_not_own_an_unchanged_log(self) -> None:
        before = [
            _observation("allocated", True),
            _observation("allocated", True, node=1),
            _observation("role", "candidate"),
            _observation("logLength", 0),
            _observation("queueLength", 0, node=1),
        ]
        writer = f"group_{len(before) + 1}"
        for length in (0, 1):
            with self.subTest(log_length=length):
                document = symbolic_trace(
                    [
                        *before,
                        action("requestVote", destination=1),
                        _observation("logLength", length),
                    ],
                    transaction_count=0,
                    term_count=2,
                    index_count=2,
                    log_capacity=1,
                    queue_capacity=1,
                )
                status, output = self.run_runner(document, name=f"network-{length}")
                self.assertEqual(status, "sat" if length == 0 else "unsat")
                if length == 1:
                    mapping = json.loads(
                        (output / "constraint-map.json").read_text(encoding="utf-8")
                    )
                    remaining = [
                        group["name"]
                        for group in mapping["groups"]
                        if group["name"] != writer
                    ]
                    formula = output / "without-network-writer.smt2"
                    formula.write_text(
                        restrict_to_assertions(
                            (output / "formula.smt2").read_text(encoding="utf-8"),
                            remaining,
                        ),
                        encoding="utf-8",
                    )
                    assert CVC5 is not None
                    self.assertEqual(
                        run_solver(
                            CVC5, formula, output, "without-network-writer"
                        ).status,
                        "unsat",
                    )


if __name__ == "__main__":
    unittest.main()
