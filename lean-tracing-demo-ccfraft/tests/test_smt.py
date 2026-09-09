# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import shutil
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reduction import build_certificate
from ccfraft_projection import ROLE_VALUES, build_formula
from Shared.smt import (
    parse_unsat_core,
    reduce_unsat_core,
    restrict_to_assertions,
)
from Shared.trace_io import read_ndjson
from validate import validate

CAPTURED = ROOT / "Traces" / "Captured"
MUTATED = ROOT / "Traces" / "Mutated"
ARTIFACTS = ROOT / "Artifacts" / "solver-tests"
CVC5 = os.environ.get("CVC5")


def _observations(certificate: dict[str, object]) -> list[dict[str, object]]:
    steps = certificate["steps"]
    assert isinstance(steps, list)
    return [step for step in steps if step["kind"] == "observation"]


def _single_action_certificate(
    kind: str,
    node: str,
    **parameters: object,
) -> dict[str, object]:
    return {
        "artifact_kind": "ccfraft_reduction_certificate",
        "schema_version": "ccfraft-reduction-certificate/v2",
        "steps": [
            {
                "action": kind,
                "kind": "action",
                "node": node,
                "provenance": [
                    {
                        "function": "test",
                        "line": 1,
                        "timestamp": "1",
                    }
                ],
                "rule": "test",
                **parameters,
            }
        ],
    }


class SmtFormulaTests(unittest.TestCase):
    def test_formula_generation_is_deterministic_and_fully_named(self) -> None:
        for trace_path in sorted(CAPTURED.glob("*.ndjson")):
            certificate = build_certificate(read_ndjson(trace_path))
            first = build_formula(certificate)
            second = build_formula(certificate)
            self.assertEqual(first, second)
            self.assertIn("(set-logic QF_AUFLIA)", first.text)
            self.assertTrue(first.text.endswith("(check-sat)\n"))

            action_count = certificate["counts"]["actions"]
            self.assertEqual(
                first.text.count(":named transition_instruction_"),
                action_count,
            )
            observations = _observations(certificate)
            self.assertEqual(
                first.text.count(":named observation_instruction_")
                + first.text.count(":named evidence_instruction_"),
                len(observations),
            )
            self.assertEqual(
                first.text.count(":named valid_entry_node_"),
                len(first.nodes),
            )
            action_boundary = 0
            for instruction_index, instruction in enumerate(certificate["steps"], 1):
                if instruction["kind"] != "action":
                    continue
                action_boundary += 1
                line = min(item["line"] for item in instruction["provenance"])
                expected = (
                    f":named transition_instruction_{instruction_index:04d}_"
                    f"action_boundary_{action_boundary:04d}_"
                    f"line_{line:04d}_{instruction['action']}"
                )
                self.assertIn(expected, first.text)

    def test_entry_state_is_existential_and_has_the_valid_projection(self) -> None:
        certificate = build_certificate(read_ndjson(CAPTURED / "soft_rollback.ndjson"))
        formula = build_formula(certificate)
        self.assertNotIn("(forall", formula.text)
        self.assertNotIn("(exists", formula.text)
        for node_index in range(len(formula.nodes)):
            allocated = f"(select state_0000_allocated {node_index})"
            joined = f"(select state_0000_joined {node_index})"
            commit = f"(select state_0000_commit_index {node_index})"
            log_length = f"(select state_0000_log_length {node_index})"
            self.assertIn(f"(= {allocated} {joined})", formula.text)
            self.assertIn(f"(>= {commit} 0)", formula.text)
            self.assertIn(f"(<= {commit} {log_length})", formula.text)

    def test_configuration_does_not_assume_old_members_were_allocated(self) -> None:
        formula = build_formula(
            _single_action_certificate(
                "changeConfiguration",
                "0",
                configuration=["0", "1"],
            )
        )
        self.assertNotIn("(= (select state_0001_allocated 1) true)", formula.text)
        self.assertIn(
            "(= (select state_0001_allocated 1) " "(select state_0001_joined 1))",
            formula.text,
        )
        self.assertIn(
            "(=> (select state_0000_allocated 1) " "(select state_0001_allocated 1))",
            formula.text,
        )

    def test_leader_promotion_may_truncate_the_log_projection(self) -> None:
        formula = build_formula(_single_action_certificate("becomeLeader", "0"))
        self.assertIn(
            "(<= (select state_0001_log_length 0) " "(select state_0000_log_length 0))",
            formula.text,
        )
        self.assertNotIn(
            "(>= (select state_0001_log_length 0) "
            "(select state_0000_commit_index 0))",
            formula.text,
        )

    def test_pre_vote_actions_use_distinct_roles_and_term_updates(self) -> None:
        pre_vote = build_formula(
            _single_action_certificate("becomePreVoteCandidate", "0")
        ).text
        self.assertIn(
            f"(= (select state_0001_role 0) " f"{ROLE_VALUES['preVoteCandidate']})",
            pre_vote,
        )
        self.assertIn("(= (select state_0000_pre_vote_status 0) true)", pre_vote)
        self.assertIn("(= state_0001_term state_0000_term)", pre_vote)

        candidate = build_formula(
            _single_action_certificate("becomeCandidate", "0")
        ).text
        self.assertIn(
            f"(= (select state_0000_role 0) " f"{ROLE_VALUES['preVoteCandidate']})",
            candidate,
        )
        self.assertIn(
            "(= (select state_0001_term 0) " "(+ (select state_0000_term 0) 1))",
            candidate,
        )

        request = build_formula(
            _single_action_certificate(
                "requestPreVote",
                "0",
                destination="1",
            )
        ).text
        self.assertIn(
            f"(= (select state_0000_role 0) " f"{ROLE_VALUES['preVoteCandidate']})",
            request,
        )

    def test_retirement_and_nomination_actions_are_distinct(self) -> None:
        retired = build_formula(
            _single_action_certificate("appendRetiredCommitted", "0")
        ).text
        self.assertIn(
            f"(= (select state_0000_role 0) {ROLE_VALUES['leader']})",
            retired,
        )
        self.assertIn(
            "(+ (select state_0000_log_length 0) 1)",
            retired,
        )

        step_down = build_formula(_single_action_certificate("checkQuorum", "0")).text
        self.assertIn(
            f"(= (select state_0001_role 0) {ROLE_VALUES['follower']})",
            step_down,
        )

        nomination = build_formula(
            _single_action_certificate(
                "proposeVote",
                "0",
                destination="1",
            )
        ).text
        self.assertIn(
            f"(= (select state_0000_role 0) {ROLE_VALUES['leader']})",
            nomination,
        )

    def test_retirement_observations_encode_optional_indices(self) -> None:
        certificate = {
            "artifact_kind": "ccfraft_reduction_certificate",
            "schema_version": "ccfraft-reduction-certificate/v2",
            "steps": [
                {
                    "kind": "observation",
                    "node": "0",
                    "provenance": [
                        {
                            "function": "test",
                            "line": 1,
                            "timestamp": "1",
                        }
                    ],
                    "rule": "test",
                    "value": "retirementSigned",
                    "variable": "membershipState",
                },
                {
                    "kind": "observation",
                    "node": "0",
                    "provenance": [
                        {
                            "function": "test",
                            "line": 1,
                            "timestamp": "1",
                        }
                    ],
                    "rule": "test",
                    "value": None,
                    "variable": "retiredCommittedIndex",
                },
            ],
        }
        formula = build_formula(certificate).text
        self.assertIn("(= (select state_0000_membership_state 0) 2)", formula)
        self.assertIn("(= (select state_0000_retired_committed_index 0) -1)", formula)

    def test_first_message_is_validated_but_queue_selection_is_unencoded(
        self,
    ) -> None:
        certificate = {
            "artifact_kind": "ccfraft_reduction_certificate",
            "schema_version": "ccfraft-reduction-certificate/v2",
            "steps": [
                {
                    "kind": "observation",
                    "node": "1",
                    "provenance": [
                        {
                            "function": "recv_request_vote",
                            "line": 1,
                            "timestamp": "1",
                        }
                    ],
                    "rule": "test",
                    "value": {
                        "batchCount": 1,
                        "batchPosition": 1,
                        "lastCommittableIndex": 0,
                        "lastCommittableTerm": 0,
                        "messageType": "raft_request_vote",
                        "source": "0",
                        "term": 1,
                    },
                    "variable": "firstMessageFrom",
                },
                {
                    "action": "receive",
                    "evidence": {"messageType": "raft_request_vote"},
                    "kind": "action",
                    "node": "1",
                    "provenance": [
                        {
                            "function": "recv_request_vote",
                            "line": 1,
                            "timestamp": "1",
                        }
                    ],
                    "rule": "test",
                    "source": "0",
                },
            ],
        }
        formula = build_formula(certificate)
        self.assertIn(
            "queue selection is an unencoded projection constraint", formula.text
        )
        self.assertIn("firstMessageFrom_unencoded_projection", formula.text)
        self.assertIn(
            "(assert (! true :named evidence_instruction_0001_",
            formula.text,
        )

    def test_unsat_core_restriction_keeps_only_selected_assertions(self) -> None:
        formula = "\n".join(
            [
                "(set-logic QF_UF)",
                "(declare-const value Bool)",
                "(assert (! value :named keep))",
                "(assert (! (not value) :named drop))",
                "(check-sat)",
                "",
            ]
        )
        names = parse_unsat_core("(\nkeep\n)")
        restricted = restrict_to_assertions(formula, names)
        self.assertIn(":named keep", restricted)
        self.assertNotIn(":named drop", restricted)
        self.assertTrue(restricted.endswith("(check-sat)\n"))

    def test_budgeted_core_reduction_removes_chunks_before_individuals(self) -> None:
        required = {"second", "fourth"}

        def check(names: tuple[str, ...], _: float) -> str:
            return "unsat" if required.issubset(names) else "sat"

        reduced = reduce_unsat_core(
            ("first", "second", "third", "fourth", "fifth"),
            check,
            budget_seconds=1,
        )
        self.assertEqual(set(reduced.names), required)
        self.assertTrue(reduced.complete)
        self.assertGreater(reduced.checks, 0)

    def test_inconclusive_check_prevents_minimality_claim(self) -> None:
        def check(_: tuple[str, ...], __: float) -> str:
            return "inconclusive"

        reduced = reduce_unsat_core(
            ("first", "second"),
            check,
            budget_seconds=1,
        )
        self.assertFalse(reduced.complete)
        self.assertEqual(reduced.names, ("first", "second"))


@unittest.skipUnless(CVC5, "set CVC5 to an explicit cvc5 executable")
class Cvc5IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        shutil.rmtree(ARTIFACTS, ignore_errors=True)
        ARTIFACTS.mkdir(parents=True)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(ARTIFACTS, ignore_errors=True)

    def _validate(self, trace_path: pathlib.Path) -> tuple[str, pathlib.Path, str]:
        output_directory = ARTIFACTS / trace_path.stem
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = validate(
                trace_path,
                output_directory,
                cvc5=pathlib.Path(CVC5),
            )
        emitted = stdout.getvalue()
        self.assertEqual(emitted.splitlines()[0], status)
        self.assertEqual(
            (output_directory / "cvc5-status.stdout")
            .read_text(encoding="utf-8")
            .splitlines()[0],
            status,
        )
        self.assertTrue((output_directory / "cvc5-status.stderr").is_file())
        result = json.loads(
            (output_directory / "result.json").read_text(encoding="utf-8")
        )
        phases = result["phase_wall_ms"]
        for phase in (
            "certificate_write",
            "ndjson_parse",
            "preprocess",
            "reduction",
            "smt_build",
            "smt_write",
        ):
            self.assertGreaterEqual(phases[phase], 0)
        self.assertGreaterEqual(result["validation_wall_ms"], 0)
        self.assertGreaterEqual(result["check_sat_wall_ms"], 0)
        self.assertGreaterEqual(result["total_solver_wall_ms"], 0)
        return status, output_directory, emitted

    def test_captured_traces_are_sat(self) -> None:
        trace_paths = sorted(CAPTURED.glob("*.ndjson"))
        self.assertEqual(len(trace_paths), 2)
        statuses = []
        for trace_path in trace_paths:
            with self.subTest(trace=trace_path.name):
                status, output_directory, emitted = self._validate(trace_path)
                statuses.append(status)
                self.assertEqual(status, "sat")
                self.assertEqual(emitted, "sat\n")
                self.assertFalse((output_directory / "proof.txt").exists())
                self.assertFalse((output_directory / "unsat-core.txt").exists())
        self.assertEqual(statuses, ["sat", "sat"])

    def test_mutated_traces_are_unsat_with_solver_evidence(self) -> None:
        trace_paths = sorted(MUTATED.glob("*.ndjson"))
        self.assertEqual(len(trace_paths), 4)
        statuses = []
        for trace_path in trace_paths:
            with self.subTest(trace=trace_path.name):
                status, output_directory, emitted = self._validate(trace_path)
                statuses.append(status)
                self.assertEqual(
                    status,
                    "unsat",
                    f"{trace_path.name} remained {status}",
                )
                self.assertEqual(emitted, "unsat\n")
                self.assertTrue(
                    (output_directory / "proof.txt").read_text(encoding="utf-8").strip()
                )
                self.assertTrue(
                    (output_directory / "unsat-core.txt")
                    .read_text(encoding="utf-8")
                    .strip()
                )
                result = (output_directory / "result.json").read_text(encoding="utf-8")
                self.assertIn('"proof_checked_by_cvc5": true', result)
                self.assertIn('"unsat_core_checked_by_cvc5": true', result)
                parsed = json.loads(result)
                self.assertLess(
                    parsed["reduced_unsat_core_assertions"],
                    parsed["original_unsat_core_assertions"],
                )
                self.assertTrue((output_directory / "formula-reduced.smt2").is_file())
                self.assertTrue(
                    (output_directory / "formula-reduced-proof.smt2").is_file()
                )
                diagnosis = json.loads(
                    (output_directory / "diagnosis.json").read_text(encoding="utf-8")
                )
                self.assertEqual(parsed["proof_scope"], diagnosis["core_kind"])
                self.assertEqual(
                    len(diagnosis["items"]),
                    parsed["reduced_unsat_core_assertions"],
                )
                for item in diagnosis["items"]:
                    if item["category"] in {"observation", "transition"}:
                        self.assertIn("instruction_index", item)
                        self.assertIn("action_boundary", item)
                if trace_path.stem.endswith("-direct"):
                    self.assertTrue(parsed["core_reduction_complete"])
                    self.assertEqual(parsed["reduced_unsat_core_assertions"], 2)
                self.assertGreaterEqual(parsed["unsat_core_wall_ms"], 0)
                self.assertGreaterEqual(parsed["proof_wall_ms"], 0)
                self.assertGreaterEqual(
                    parsed["total_solver_wall_ms"],
                    parsed["check_sat_wall_ms"],
                )
        self.assertEqual(statuses, ["unsat"] * 4)


if __name__ == "__main__":
    unittest.main()
