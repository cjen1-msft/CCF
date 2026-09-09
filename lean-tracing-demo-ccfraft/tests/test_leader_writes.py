# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Checked leader writes use model transitions and retain causal SMT bindings."""

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
)
from tests.test_template_client_requests import NODE_COUNT, entry_state


def action(name: str, node: int = 0, **parameters: object) -> dict[str, object]:
    return {"kind": "action", "action": name, "node": node, **parameters}


def trace(
    steps: list[dict[str, object]],
    *,
    entry: str | dict[str, object] = "bootstrap",
    unknowns: list[str] | None = None,
    transaction_count: int = 2,
    term_count: int = 8,
    index_count: int = 4,
    log_capacity: int = 4,
) -> dict[str, object]:
    return {
        "schema_version": "ccfraft-trace/v1",
        "entry": entry,
        "unknowns": [] if unknowns is None else unknowns,
        "bounds": {
            "transaction_count": transaction_count,
            "term_count": term_count,
            "index_count": index_count,
            "log_capacity": log_capacity,
            "queue_capacity": 0,
        },
        "steps": steps,
    }


class LeaderWriteFixtureTests(unittest.TestCase):
    def test_persistent_example_matches_the_builder(self) -> None:
        example = json.loads(
            (ROOT / "Traces/LeaderWrites/bootstrap-writes.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            example,
            trace(
                [
                    _request({"unknown": "tx"}),
                    action("signCommittableMessages"),
                    action("changeConfiguration", configuration=[0, 7]),
                    _observation("allocated", True, node=7),
                    _observation("joined", True, node=7),
                    _observation("logLength", 3),
                ],
                unknowns=["tx"],
                transaction_count=1,
                term_count=2,
            ),
        )


@SOLVER_TESTS
class LeaderWriteTests(ClientRequestSliceTestCase):
    def test_a_signature_appends_after_a_client_request(self) -> None:
        status, output = self.run_runner(
            trace(
                [
                    _request(0),
                    action("signCommittableMessages"),
                    _observation("logLength", 2),
                ]
            )
        )
        self.assertEqual(status, "sat")
        self.assertEqual(
            self.result(output)["assurance"]["supported_actions"],
            [
                "clientRequest",
                "signCommittableMessages",
                "changeConfiguration",
                "appendRetiredCommitted",
            ],
        )
        mapping = json.loads(
            (output / "constraint-map.json").read_text(encoding="utf-8")
        )
        self.assertEqual(mapping["groups"][2]["kind"], "action")

    def test_a_signature_cannot_sign_an_empty_log(self) -> None:
        status, _ = self.run_runner(trace([action("signCommittableMessages")]))
        self.assertEqual(status, "unsat")

    def test_configuration_adds_fresh_nodes_and_join_history(self) -> None:
        status, _ = self.run_runner(
            trace(
                [
                    action("changeConfiguration", configuration=[0, 7]),
                    _observation("allocated", True, node=7),
                    _observation("joined", True, node=7),
                    _observation("role", "none", node=7),
                    _observation("currentTerm", 0, node=7),
                    _observation("logLength", 0, node=7),
                    _observation("logLength", 1, node=0),
                ]
            )
        )
        self.assertEqual(status, "sat")

    def test_allocation_and_join_cores_keep_the_configuration_action(self) -> None:
        for variable in ("allocated", "joined"):
            with self.subTest(variable=variable):
                status, output = self.run_runner(
                    trace(
                        [
                            action("changeConfiguration", configuration=[0, 7]),
                            _observation(variable, False, node=7),
                        ]
                    ),
                    name=variable,
                )
                self.assertEqual(status, "unsat")
                self.assertEqual(
                    self._core_names(output / "unsat-core.txt"),
                    {"group_1", "group_2"},
                )

    def test_sent_index_bound_keeps_both_causal_writes(self) -> None:
        status, output = self.run_runner(
            trace(
                [_request(0), action("changeConfiguration", configuration=[0, 7])],
                index_count=1,
                log_capacity=2,
            )
        )
        self.assertEqual(status, "unsat")
        self.assertEqual(
            self._core_names(output / "unsat-core.txt"),
            {"group_1", "group_2", "group_3"},
        )

    def test_configuration_can_be_inspected_at_clause_granularity(self) -> None:
        status, output = self.run_runner(
            trace(
                [_request(0), action("changeConfiguration", configuration=[0, 7])],
                index_count=1,
                log_capacity=2,
            ),
            inspect_group=2,
        )
        self.assertEqual(status, "unsat")
        core = self._core_names(output / "unsat-core.txt")
        self.assertTrue({"group_1", "group_3"}.issubset(core))
        self.assertTrue(any(name.startswith("group_2_clause_") for name in core))
        diagnosis = json.loads((output / "diagnosis.json").read_text(encoding="utf-8"))
        self.assertTrue(
            any("sent index" in item.get("label", "") for item in diagnosis["items"])
        )

    def test_repeating_the_current_configuration_is_disabled(self) -> None:
        change = action("changeConfiguration", configuration=[0, 7])
        status, _ = self.run_runner(trace([change, change]))
        self.assertEqual(status, "unsat")

    def test_completed_retirements_can_be_appended(self) -> None:
        entry = entry_state()
        entry["retirementCompleted"] = [
            [2] if node == 1 else [] for node in range(NODE_COUNT)
        ]
        status, _ = self.run_runner(
            trace(
                [
                    action("appendRetiredCommitted", node=1),
                    _observation("logLength", 2, node=1),
                ],
                entry=entry,
                unknowns=["old"],
            )
        )
        self.assertEqual(status, "sat")

    def test_retirement_append_requires_pending_nodes(self) -> None:
        status, _ = self.run_runner(
            trace(
                [action("appendRetiredCommitted", node=1)],
                entry=entry_state(),
                unknowns=["old"],
            )
        )
        self.assertEqual(status, "unsat")

    def test_general_schema_still_rejects_unimplemented_actions(self) -> None:
        with self.assertRaises(CertificateRejected):
            self.run_runner(trace([action("receive", source=1)]))


if __name__ == "__main__":
    unittest.main()
