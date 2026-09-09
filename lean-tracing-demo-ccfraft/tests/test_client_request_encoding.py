# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Tests for the Lean-checked bootstrap client-request slice.

The solver and Lean tests are skipped when cvc5 or lake are unavailable. The
constraint-map, assurance, and SMT-query tests run everywhere.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from Shared.smt import SmtEncodingError, add_query  # noqa: E402
from Shared.solver import ValidationError  # noqa: E402
from validate_checked import (  # noqa: E402
    CONSTRAINT_MAP_SCHEMA,
    CertificateRejected,
    build_proof_gate,
    core_diagnosis,
    encoder_failure,
    explain_unsat,
    main,
    read_constraint_map,
    reduce_core,
    run_encoder,
    validate_checked,
)

ASSERTION_NAME = re.compile(r":named (\S+)\)\)$", re.MULTILINE)
GENERATED_NAME = re.compile(r"^group_\d+(?:_clause_\d+)?$")

LEADER = 0
FOLLOWER = 1
UNALLOCATED = 7


def _cvc5() -> pathlib.Path | None:
    requested = os.environ.get("CVC5")
    if requested:
        return pathlib.Path(requested)
    located = shutil.which("cvc5")
    if located is not None:
        return pathlib.Path(located)
    candidates = sorted(pathlib.Path("/nix/store").glob("*-cvc5-*/bin/cvc5"))
    return candidates[-1] if candidates else None


CVC5 = _cvc5()
LAKE = shutil.which("lake")
SOLVER_TESTS = unittest.skipUnless(
    CVC5 is not None and LAKE is not None,
    "needs cvc5 and lake; set CVC5 to an explicit executable",
)


def _certificate(
    steps: list[dict[str, object]],
    *,
    unknowns: list[str] | None = None,
    transaction_count: int = 4,
    log_capacity: int = 4,
    entry: str = "bootstrap",
    schema_version: str = "ccfraft-client-request/v1",
) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "entry": entry,
        "bounds": {
            "transaction_count": transaction_count,
            "log_capacity": log_capacity,
        },
        "unknowns": [] if unknowns is None else unknowns,
        "steps": steps,
    }


def _request(transaction: object, node: int = LEADER) -> dict[str, object]:
    return {
        "kind": "action",
        "action": "clientRequest",
        "node": node,
        "transaction": transaction,
    }


def _observation(variable: str, value: object, node: int = LEADER) -> dict[str, object]:
    return {
        "kind": "observation",
        "node": node,
        "variable": variable,
        "value": value,
    }


def _submitted(transaction: object, value: bool) -> dict[str, object]:
    return {
        "kind": "observation",
        "variable": "submitted",
        "transaction": transaction,
        "value": value,
    }


class ClientRequestSliceTestCase(unittest.TestCase):
    """Run the runner in a temporary directory with a written certificate."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory(
            prefix="client-request-", dir=ROOT / "Artifacts"
        )
        self.addCleanup(self._directory.cleanup)
        self.workspace = pathlib.Path(self._directory.name)

    def run_runner(
        self,
        certificate: dict[str, object],
        *,
        inspect_group: int | None = None,
        name: str = "run",
    ) -> tuple[str, pathlib.Path]:
        certificate_path = self.workspace / f"{name}.json"
        certificate_path.write_text(
            json.dumps(certificate, indent=2) + "\n", encoding="utf-8"
        )
        output_directory = self.workspace / name
        assert CVC5 is not None
        status = validate_checked(
            certificate_path,
            output_directory,
            cvc5=CVC5,
            inspect_group=inspect_group,
            core_reduction_budget_seconds=5.0,
        )
        return status, output_directory

    def _core_names(self, path: pathlib.Path) -> set[str]:
        return set(path.read_text(encoding="utf-8").strip().strip("()").split())

    def result(self, output_directory: pathlib.Path) -> dict[str, object]:
        return json.loads(
            (output_directory / "result.json").read_text(encoding="utf-8")
        )


@SOLVER_TESTS
class SatisfiableCertificateTests(ClientRequestSliceTestCase):
    def test_distinct_symbolic_transactions_are_satisfiable(self) -> None:
        certificate = _certificate(
            [
                _request({"unknown": "first"}),
                _request({"unknown": "second"}),
                _observation("logLength", 2),
                _observation("role", "leader"),
                _observation("currentTerm", 1),
                _observation("commitIndex", 0),
                _observation("allocated", True),
                _observation("joined", True),
                _submitted({"unknown": "first"}, True),
            ],
            unknowns=["first", "second"],
        )
        status, output_directory = self.run_runner(certificate)
        self.assertEqual(status, "sat")
        result = self.result(output_directory)
        self.assertEqual(result["status"], "sat")
        self.assertNotIn("diagnosis", result)
        assurance = result["assurance"]
        self.assertEqual(assurance["claim"], "bounded-trace")
        self.assertEqual(assurance["supported_actions"], ["clientRequest"])
        self.assertEqual(assurance["scope"], "bounded")
        self.assertEqual(assurance["entry"], "bootstrap")
        self.assertEqual(
            assurance["bounds"],
            {
                "transaction_count": 4,
                "log_capacity": 4,
                "term_count": 2,
                "index_count": 1,
                "queue_capacity": 0,
            },
        )
        self.assertEqual(assurance["unknowns"], ["first", "second"])
        self.assertEqual(assurance["granularity"], "group")
        self.assertIsNone(assurance["inspect_group"])
        self.assertTrue(result["proof_gate"]["checked"])
        self.assertIn("encoded", result["interpretation"])
        self.assertIn("declared bounds", result["interpretation"])

    def test_concrete_transactions_and_unallocated_nodes_are_satisfiable(self) -> None:
        certificate = _certificate(
            [
                _request(0),
                _observation("logLength", 1),
                _observation("logLength", 0, node=FOLLOWER),
                _observation("role", "follower", node=FOLLOWER),
                _observation("role", "none", node=UNALLOCATED),
                _observation("allocated", False, node=UNALLOCATED),
                _observation("joined", False, node=UNALLOCATED),
                _observation("currentTerm", 0, node=UNALLOCATED),
                _submitted(0, True),
                _submitted(1, False),
            ]
        )
        status, _ = self.run_runner(certificate)
        self.assertEqual(status, "sat")


@SOLVER_TESTS
class UnsatisfiableCertificateTests(ClientRequestSliceTestCase):
    def assert_unsat_with_evidence(
        self,
        certificate: dict[str, object],
        *,
        name: str,
    ) -> dict[str, object]:
        status, output_directory = self.run_runner(certificate, name=name)
        self.assertEqual(status, "unsat")
        result = self.result(output_directory)
        self.assertIn(
            result["core_kind"],
            {"subset-minimal", "heuristically reduced within budget"},
        )
        self.assertTrue((output_directory / "unsat-core-original.txt").is_file())
        self.assertTrue((output_directory / "unsat-core.txt").is_file())
        self.assertTrue((output_directory / "formula-reduced.smt2").is_file())
        diagnosis = json.loads(
            (output_directory / "diagnosis.json").read_text(encoding="utf-8")
        )
        self.assertTrue(diagnosis["named_assertions"])
        self.assertLessEqual(
            result["reduced_unsat_core_assertions"],
            result["original_unsat_core_assertions"],
        )
        for item in diagnosis["items"]:
            self.assertIn(item["granularity"], {"group", "clause"})
            self.assertIn(item["group_kind"], {"action", "observation", "bounds"})
        return diagnosis

    def test_reusing_one_unknown_violates_transaction_freshness(self) -> None:
        certificate = _certificate(
            [
                _request({"unknown": "reused"}),
                _request({"unknown": "reused"}),
            ],
            unknowns=["reused"],
        )
        diagnosis = self.assert_unsat_with_evidence(certificate, name="freshness")
        labels = {item["group_label"] for item in diagnosis["items"]}
        self.assertIn("clientRequest", labels)

    def test_transaction_domain_smaller_than_the_trace_is_unsatisfiable(self) -> None:
        certificate = _certificate(
            [
                _request({"unknown": "first"}),
                _request({"unknown": "second"}),
            ],
            unknowns=["first", "second"],
            transaction_count=1,
        )
        self.assert_unsat_with_evidence(certificate, name="domain")

    def test_wrong_log_length_is_unsatisfiable(self) -> None:
        certificate = _certificate(
            [_request(0), _observation("logLength", 5)],
        )
        self.assert_unsat_with_evidence(certificate, name="log-length")

    def test_wrong_role_is_unsatisfiable(self) -> None:
        certificate = _certificate(
            [_request(0), _observation("role", "leader", node=FOLLOWER)],
        )
        self.assert_unsat_with_evidence(certificate, name="role")

    def test_non_leader_client_request_is_unsatisfiable(self) -> None:
        certificate = _certificate([_request(0, node=FOLLOWER)])
        self.assert_unsat_with_evidence(certificate, name="non-leader")

    def test_exceeding_the_log_capacity_is_unsatisfiable(self) -> None:
        certificate = _certificate(
            [_request(0), _request(1)],
            log_capacity=1,
        )
        self.assert_unsat_with_evidence(certificate, name="capacity")


@SOLVER_TESTS
class ExampleTraceTests(ClientRequestSliceTestCase):
    """Run the checked-in example certificates the parent project ships."""

    EXAMPLES = ROOT / "Traces" / "ClientRequests"

    def _run_example(
        self, name: str, *, inspect_group: int | None = None
    ) -> tuple[str, pathlib.Path]:
        certificate_path = self.EXAMPLES / name
        if not certificate_path.is_file():
            self.skipTest(f"example certificate is absent: {certificate_path}")
        suffix = "" if inspect_group is None else f"-group-{inspect_group}"
        output_directory = self.workspace / (certificate_path.stem + suffix)
        assert CVC5 is not None
        status = validate_checked(
            certificate_path,
            output_directory,
            cvc5=CVC5,
            inspect_group=inspect_group,
        )
        return status, output_directory

    def test_two_requests_example_is_satisfiable(self) -> None:
        status, output_directory = self._run_example("two-requests.json")
        self.assertEqual(status, "sat")
        result = json.loads(
            (output_directory / "result.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            result["assurance"]["bounds"],
            {
                "transaction_count": 2,
                "log_capacity": 2,
                "term_count": 2,
                "index_count": 1,
                "queue_capacity": 0,
            },
        )
        self.assertEqual(result["assurance"]["unknowns"], ["first", "second"])

    def test_wrong_log_length_example_is_unsatisfiable(self) -> None:
        status, output_directory = self._run_example("wrong-log-length.json")
        self.assertEqual(status, "unsat")
        diagnosis = json.loads(
            (output_directory / "diagnosis.json").read_text(encoding="utf-8")
        )
        self.assertTrue(diagnosis["named_assertions"])

    def test_wrong_log_length_core_keeps_both_causal_actions(self) -> None:
        """Both requests extend the log, so both must be blamed alongside it."""

        status, output_directory = self._run_example("wrong-log-length.json")
        self.assertEqual(status, "unsat")
        diagnosis = json.loads(
            (output_directory / "diagnosis.json").read_text(encoding="utf-8")
        )
        blamed = {item["name"]: item for item in diagnosis["items"]}
        self.assertLessEqual({"group_1", "group_2", "group_3"}, set(blamed))
        self.assertEqual(blamed["group_1"]["group_kind"], "action")
        self.assertEqual(blamed["group_2"]["group_kind"], "action")
        self.assertEqual(blamed["group_3"]["group_kind"], "observation")
        for index in (1, 2, 3):
            self.assertEqual(blamed[f"group_{index}"]["instruction_index"], index)

    def test_inspecting_the_second_request_blames_its_log_length_binding(self) -> None:
        status, output_directory = self._run_example(
            "wrong-log-length.json", inspect_group=2
        )
        self.assertEqual(status, "unsat")
        diagnosis = json.loads(
            (output_directory / "diagnosis.json").read_text(encoding="utf-8")
        )
        clauses = [
            item
            for item in diagnosis["items"]
            if item["granularity"] == "clause" and item["group_index"] == 2
        ]
        self.assertTrue(clauses, "the inspected action contributed no clause")
        labels = {item["label"] for item in clauses}
        self.assertIn("next log length", labels)
        for item in clauses:
            self.assertTrue(item["expression"])
        core = self._core_names(output_directory / "unsat-core.txt")
        self.assertIn("group_1", core)
        self.assertIn("group_3", core)


@SOLVER_TESTS
class RejectedCertificateTests(ClientRequestSliceTestCase):
    def assert_rejected(
        self,
        certificate: dict[str, object],
        expected: str,
        *,
        name: str,
    ) -> None:
        with self.assertRaises(CertificateRejected) as raised:
            self.run_runner(certificate, name=name)
        message = str(raised.exception)
        self.assertIn("rejected this certificate", message)
        self.assertIn(expected, message)
        self.assertFalse((self.workspace / name / "formula.smt2").is_file())
        self.assertFalse((self.workspace / name / "result.json").is_file())
        failure = json.loads(
            (self.workspace / name / "error.json").read_text(encoding="utf-8")
        )
        self.assertTrue(failure["certificate_rejected"])

    def test_a_reused_directory_never_shows_the_previous_verdict(self) -> None:
        """A rejected rerun must not leave the earlier sat result readable."""

        accepted = _certificate([_request(0), _observation("logLength", 1)])
        status, output_directory = self.run_runner(accepted, name="reused")
        self.assertEqual(status, "sat")
        self.assertEqual(self.result(output_directory)["status"], "sat")
        stale = sorted(path.name for path in output_directory.iterdir())
        self.assertIn("result.json", stale)
        self.assertIn("formula.smt2", stale)

        rejected = _certificate(
            [{"kind": "action", "action": "timeout", "node": LEADER, "transaction": 0}]
        )
        certificate_path = self.workspace / "reused.json"
        certificate_path.write_text(json.dumps(rejected, indent=2), encoding="utf-8")
        assert CVC5 is not None
        with self.assertRaises(CertificateRejected):
            validate_checked(certificate_path, output_directory, cvc5=CVC5)

        for name in (
            "result.json",
            "formula.smt2",
            "constraint-map.json",
            "diagnosis.json",
            "unsat-core.txt",
        ):
            self.assertFalse(
                (output_directory / name).is_file(),
                f"{name} survived a rejected rerun",
            )
        for path in output_directory.iterdir():
            self.assertFalse(path.name.startswith("cvc5-"), f"{path.name} is stale")
        failure = json.loads(
            (output_directory / "error.json").read_text(encoding="utf-8")
        )
        self.assertEqual(failure["status"], "error")
        self.assertTrue(failure["certificate_rejected"])
        self.assertIn("timeout", failure["error"])

    def test_a_missing_certificate_clears_an_earlier_verdict(self) -> None:
        accepted = _certificate([_request(0), _observation("logLength", 1)])
        status, output_directory = self.run_runner(accepted, name="vanished")
        self.assertEqual(status, "sat")

        assert CVC5 is not None
        with self.assertRaises(ValidationError):
            validate_checked(
                self.workspace / "absent.json", output_directory, cvc5=CVC5
            )
        self.assertFalse((output_directory / "result.json").is_file())
        failure = json.loads(
            (output_directory / "error.json").read_text(encoding="utf-8")
        )
        self.assertFalse(failure["certificate_rejected"])
        self.assertIn("does not exist", failure["error"])

    def test_unsupported_action_is_rejected(self) -> None:
        certificate = _certificate(
            [{"kind": "action", "action": "timeout", "node": LEADER, "transaction": 0}]
        )
        self.assert_rejected(certificate, "timeout", name="action")

    def test_mid_trace_entry_is_rejected(self) -> None:
        certificate = _certificate([_request(0)], entry="mid-trace")
        self.assert_rejected(certificate, "bootstrap", name="entry")

    def test_unsupported_schema_version_is_rejected(self) -> None:
        certificate = _certificate([_request(0)], schema_version="ccfraft/v0")
        self.assert_rejected(certificate, "schema_version", name="schema")

    def test_undeclared_unknown_is_rejected(self) -> None:
        certificate = _certificate(
            [_request({"unknown": "absent"})], unknowns=["declared"]
        )
        self.assert_rejected(certificate, "absent", name="unknown")

    def test_unsupported_observation_is_rejected(self) -> None:
        certificate = _certificate([_observation("votedFor", 1)])
        self.assert_rejected(certificate, "votedFor", name="observation")

    def test_unsupported_field_is_rejected(self) -> None:
        certificate = _certificate(
            [{**_request(0), "unexpected_field": "surprise"}],
        )
        self.assert_rejected(certificate, "unexpected_field", name="field")

    def test_node_outside_the_model_is_rejected(self) -> None:
        certificate = _certificate([_request(0, node=99)])
        self.assert_rejected(certificate, "99", name="node")

    def test_submitted_observation_may_not_carry_a_node(self) -> None:
        certificate = _certificate([{**_submitted(0, True), "node": LEADER}])
        self.assert_rejected(certificate, "node", name="submitted-node")


@SOLVER_TESTS
class InspectGroupTests(ClientRequestSliceTestCase):
    def _injected_certificate(self) -> dict[str, object]:
        injection = "evil :named injected) (assert false) (assert (! true :named x"
        return _certificate(
            [
                {
                    **_request({"unknown": "reused"}),
                    "provenance": injection,
                    "rule": injection,
                },
                {
                    **_request({"unknown": "reused"}),
                    "provenance": injection,
                    "rule": injection,
                },
            ],
            unknowns=["reused"],
        )

    def test_inspect_group_keeps_the_verdict_and_names_clauses(self) -> None:
        certificate = self._injected_certificate()
        coarse_status, coarse_output = self.run_runner(certificate, name="coarse")
        fine_status, fine_output = self.run_runner(
            certificate, inspect_group=2, name="fine"
        )
        self.assertEqual(coarse_status, "unsat")
        self.assertEqual(fine_status, coarse_status)

        fine_result = self.result(fine_output)
        self.assertEqual(fine_result["assurance"]["granularity"], "clause")
        self.assertEqual(fine_result["assurance"]["inspect_group"], 2)
        note = fine_result["inspect_group_note"]
        self.assertIn("naming granularity, not a second encoding", note)
        self.assertIn("holds those other assertions fixed", note)

        fine_map = json.loads(
            (fine_output / "constraint-map.json").read_text(encoding="utf-8")
        )
        self.assertEqual(fine_map["inspect_group"], 2)
        selected = next(group for group in fine_map["groups"] if group["index"] == 2)
        self.assertEqual(selected["kind"], "action")
        self.assertGreater(len(selected["clauses"]), 1)

        fine_diagnosis = json.loads(
            (fine_output / "diagnosis.json").read_text(encoding="utf-8")
        )
        granularities = {item["granularity"] for item in fine_diagnosis["items"]}
        self.assertIn("clause", granularities)
        for item in fine_diagnosis["items"]:
            if item["granularity"] == "clause":
                self.assertEqual(item["group_index"], 2)
                self.assertTrue(item["label"])
                self.assertTrue(item["expression"])

        coarse_diagnosis = json.loads(
            (coarse_output / "diagnosis.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {item["granularity"] for item in coarse_diagnosis["items"]}, {"group"}
        )

    def test_reduction_holds_other_groups_fixed(self) -> None:
        certificate = self._injected_certificate()
        _, output_directory = self.run_runner(
            certificate, inspect_group=2, name="fixed-context"
        )
        result = self.result(output_directory)
        self.assertIn("group_2", result["core_reduction_scope"])
        self.assertIn("fixed context", result["core_reduction_scope"])

        original = self._core_names(output_directory / "unsat-core-original.txt")
        reduced = self._core_names(output_directory / "unsat-core.txt")
        context = {name for name in original if not name.startswith("group_2_clause_")}
        self.assertTrue(
            context.issubset(reduced),
            "context assertions must never be removed in inspect mode",
        )
        self.assertTrue((reduced - context).issubset(original))
        self.assertEqual(result["core_fixed_context_assertions"], len(context))

    def test_certificate_text_never_reaches_assertion_names(self) -> None:
        certificate = self._injected_certificate()
        _, output_directory = self.run_runner(
            certificate, inspect_group=1, name="injection"
        )
        formula = (output_directory / "formula.smt2").read_text(encoding="utf-8")
        self.assertNotIn("injected", formula)
        self.assertNotIn("evil", formula)
        names = ASSERTION_NAME.findall(formula)
        self.assertTrue(names)
        for name in names:
            self.assertRegex(name, GENERATED_NAME)

        constraint_map = json.loads(
            (output_directory / "constraint-map.json").read_text(encoding="utf-8")
        )
        declared = {group["name"] for group in constraint_map["groups"]}
        declared.update(
            clause["name"]
            for group in constraint_map["groups"]
            for clause in group["clauses"]
        )
        self.assertEqual(len(names), len(set(names)), "assertion names repeat")
        self.assertEqual(set(names) - declared, set(), "formula names outside the map")
        self.assertEqual(
            formula.count(":named"),
            len(names),
            "every named assertion must sit on one line for core restriction",
        )

    def test_inspect_group_must_select_a_client_request(self) -> None:
        certificate = _certificate([_request(0), _observation("logLength", 1)])
        with self.assertRaises(CertificateRejected) as raised:
            self.run_runner(certificate, inspect_group=2, name="inspect-observation")
        self.assertIn("clientRequest", str(raised.exception))

    def test_inspect_group_zero_is_rejected_before_any_build(self) -> None:
        certificate = _certificate([_request(0)])
        with self.assertRaises(ValidationError) as raised:
            self.run_runner(certificate, inspect_group=0, name="inspect-zero")
        self.assertIn("starts at 1", str(raised.exception))


@SOLVER_TESTS
class CommandLineTests(ClientRequestSliceTestCase):
    def test_exit_codes_report_status_and_rejection(self) -> None:
        assert CVC5 is not None
        accepted = self.workspace / "accepted.json"
        accepted.write_text(
            json.dumps(_certificate([_request(0), _observation("logLength", 1)])),
            encoding="utf-8",
        )
        self.assertEqual(
            main(
                [
                    str(accepted),
                    str(self.workspace / "accepted"),
                    "--cvc5",
                    str(CVC5),
                    "--core-reduction-budget-seconds",
                    "5",
                ]
            ),
            0,
        )
        rejected = self.workspace / "rejected.json"
        rejected.write_text(
            json.dumps(_certificate([_request(0)], entry="mid-trace")),
            encoding="utf-8",
        )
        self.assertEqual(
            main(
                [str(rejected), str(self.workspace / "rejected"), "--cvc5", str(CVC5)]
            ),
            2,
        )


class ConstraintMapTests(unittest.TestCase):
    """Check map handling without running Lean or cvc5."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory(
            prefix="constraint-map-", dir=ROOT / "Artifacts"
        )
        self.addCleanup(self._directory.cleanup)
        self.workspace = pathlib.Path(self._directory.name)
        self.constraint_map = {
            "schema_version": CONSTRAINT_MAP_SCHEMA,
            "certificate_schema": "ccfraft-client-request/v1",
            "supported_actions": ["clientRequest"],
            "entry": "bootstrap",
            "bounds": {"transaction_count": 2, "log_capacity": 2},
            "unknowns": ["first"],
            "inspect_group": None,
            "theorem": "CCFRaft.TraceEncoding.encode_correct",
            "compiler": "an unknown field the runner ignores",
            "groups": [
                {
                    "index": 0,
                    "name": "group_0",
                    "label": "unknown transaction domains",
                    "instruction_index": None,
                    "instruction": None,
                    "kind": "bounds",
                    "clauses": [
                        {
                            "name": "group_0_clause_0",
                            "label": "unknown 0 domain",
                            "expression": "(< unknown_0 2)",
                        }
                    ],
                },
                {
                    "index": 1,
                    "name": "group_1",
                    "label": "clientRequest",
                    "instruction_index": 1,
                    "instruction": {"kind": "action", "action": "clientRequest"},
                    "kind": "action",
                    "clauses": [
                        {
                            "name": "group_1_clause_0",
                            "label": "transaction freshness",
                            "expression": "true",
                        }
                    ],
                },
            ],
        }

    def _write(self, payload: object) -> pathlib.Path:
        path = self.workspace / "constraint-map.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_valid_map_is_accepted_and_extra_fields_are_ignored(self) -> None:
        loaded = read_constraint_map(
            self._write(self.constraint_map), inspect_group=None
        )
        self.assertEqual(loaded["unknowns"], ["first"])

    def test_template_map_preserves_its_entry_profile(self) -> None:
        payload = {**self.constraint_map, "entry": "template"}
        loaded = read_constraint_map(self._write(payload), inspect_group=None)
        self.assertEqual(loaded["entry"], "template")

    def test_missing_or_empty_schema_coverage_is_rejected(self) -> None:
        for field, value in (
            ("certificate_schema", None),
            ("certificate_schema", ""),
            ("supported_actions", None),
            ("supported_actions", []),
            ("supported_actions", [""]),
            ("supported_actions", [False]),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(
                ValidationError
            ):
                read_constraint_map(
                    self._write({**self.constraint_map, field: value}),
                    inspect_group=None,
                )

    def test_unrecognized_entry_profiles_are_rejected(self) -> None:
        for entry in ("unrestricted", {}, None):
            with self.subTest(entry=entry), self.assertRaises(ValidationError):
                read_constraint_map(
                    self._write({**self.constraint_map, "entry": entry}),
                    inspect_group=None,
                )

    def test_extra_clauses_per_group_are_accepted(self) -> None:
        group = self.constraint_map["groups"][1]
        group["clauses"] = group["clauses"] + [
            {
                "name": "group_1_clause_1",
                "label": "log entry binding",
                "expression": "(= term_1 1)",
            },
            {
                "name": "group_1_clause_2",
                "label": "log length binding",
                "expression": "(= length_1 (+ length_0 1))",
            },
        ]
        loaded = read_constraint_map(
            self._write(self.constraint_map), inspect_group=None
        )
        self.assertEqual(len(loaded["groups"][1]["clauses"]), 3)

    def test_a_clause_without_metadata_is_rejected(self) -> None:
        del self.constraint_map["groups"][1]["clauses"][0]["expression"]
        with self.assertRaises(ValidationError) as raised:
            read_constraint_map(self._write(self.constraint_map), inspect_group=None)
        self.assertIn("no string expression", str(raised.exception))

    def test_wrong_schema_version_is_rejected(self) -> None:
        payload = {**self.constraint_map, "schema_version": "other/v9"}
        with self.assertRaises(ValidationError) as raised:
            read_constraint_map(self._write(payload), inspect_group=None)
        self.assertIn("schema_version", str(raised.exception))

    def test_mismatched_inspect_group_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            read_constraint_map(self._write(self.constraint_map), inspect_group=1)

    def test_missing_map_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            read_constraint_map(self.workspace / "absent.json", inspect_group=None)

    def test_diagnosis_binds_group_and_clause_names(self) -> None:
        diagnosis = core_diagnosis(
            self.constraint_map,
            ["group_0", "group_1_clause_0"],
            core_kind="subset-minimal",
        )
        self.assertEqual(diagnosis["core_kind"], "subset-minimal")
        group_item, clause_item = diagnosis["items"]
        self.assertEqual(group_item["granularity"], "group")
        self.assertEqual(group_item["group_label"], "unknown transaction domains")
        self.assertEqual(clause_item["granularity"], "clause")
        self.assertEqual(clause_item["label"], "transaction freshness")
        self.assertEqual(clause_item["instruction_index"], 1)

    def test_unknown_core_name_is_an_error_not_infrastructure(self) -> None:
        with self.assertRaises(ValidationError) as raised:
            core_diagnosis(
                self.constraint_map,
                ["group_7"],
                core_kind="subset-minimal",
            )
        self.assertIn("group_7", str(raised.exception))


class ToolchainFailureTests(unittest.TestCase):
    """A broken toolchain must surface, never degrade to another backend."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory(
            prefix="toolchain-", dir=ROOT / "Artifacts"
        )
        self.addCleanup(self._directory.cleanup)
        self.workspace = pathlib.Path(self._directory.name)

    def test_missing_encoder_entry_point_is_an_error(self) -> None:
        certificate = self.workspace / "certificate.json"
        certificate.write_text(json.dumps(_certificate([])), encoding="utf-8")
        with self.assertRaises(ValidationError) as raised:
            run_encoder(
                self.workspace,
                certificate,
                self.workspace,
                inspect_group=None,
            )
        self.assertIn("encoder entry point", str(raised.exception))

    @unittest.skipUnless(LAKE is not None, "needs lake")
    def test_a_failing_proof_gate_stops_the_run(self) -> None:
        log = self.workspace / "lake-build.log"
        with self.assertRaises(ValidationError) as raised:
            build_proof_gate(self.workspace, log)
        self.assertIn("proof gate", str(raised.exception))
        self.assertTrue(log.is_file())

    def test_missing_certificate_is_reported_before_building(self) -> None:
        with self.assertRaises(ValidationError) as raised:
            validate_checked(
                self.workspace / "absent.json",
                self.workspace / "output",
                cvc5=CVC5,
            )
        self.assertIn("does not exist", str(raised.exception))

    def test_a_decoder_verdict_is_not_confused_with_a_broken_build(self) -> None:
        rejection = encoder_failure(
            1, "", "encoding error: unsupported action in checked slice: timeout\n"
        )
        self.assertIsInstance(rejection, CertificateRejected)
        self.assertIn("timeout", str(rejection))

        broken = encoder_failure(
            1,
            "",
            "EncodeTrace.lean:11:37: error: unknown constant `checkedEncoder`",
        )
        self.assertIsInstance(broken, ValidationError)
        self.assertNotIsInstance(broken, CertificateRejected)
        self.assertIn("toolchain failure", str(broken))


@unittest.skipUnless(CVC5 is not None, "needs cvc5")
class UnsatEvidenceTests(unittest.TestCase):
    """Exercise the core, reduction, and diagnosis path on a fixed formula."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory(
            prefix="unsat-evidence-", dir=ROOT / "Artifacts"
        )
        self.addCleanup(self._directory.cleanup)
        self.workspace = pathlib.Path(self._directory.name)

    def test_core_reduction_and_diagnosis_bind_group_names(self) -> None:
        formula = (
            "(set-logic QF_LIA)\n"
            "(declare-const unknown_0 Int)\n"
            "(assert (>= unknown_0 0))\n"
            "(assert (! (< unknown_0 2) :named group_0))\n"
            "(assert (! (= unknown_0 5) :named group_1))\n"
            "(assert (! true :named group_2))\n"
            "(check-sat)\n"
        )
        constraint_map = {
            "schema_version": CONSTRAINT_MAP_SCHEMA,
            "entry": "bootstrap",
            "bounds": {"transaction_count": 2, "log_capacity": 2},
            "unknowns": ["first"],
            "inspect_group": None,
            "groups": [
                {
                    "index": index,
                    "name": f"group_{index}",
                    "label": label,
                    "instruction_index": None if index == 0 else index,
                    "kind": kind,
                    "clauses": [
                        {
                            "name": f"group_{index}_clause_0",
                            "label": label,
                            "expression": "true",
                        }
                    ],
                }
                for index, (label, kind) in enumerate(
                    [
                        ("unknown transaction domains", "bounds"),
                        ("clientRequest", "action"),
                        ("final state bounds", "bounds"),
                    ]
                )
            ],
        }
        assert CVC5 is not None
        evidence = explain_unsat(
            CVC5,
            formula,
            self.workspace,
            constraint_map,
            core_reduction_budget_seconds=5.0,
        )
        self.assertTrue(evidence["unsat_core_checked_by_cvc5"])
        self.assertLessEqual(
            evidence["reduced_unsat_core_assertions"],
            evidence["original_unsat_core_assertions"],
        )
        diagnosis = json.loads(
            (self.workspace / "diagnosis.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(diagnosis["named_assertions"]), {"group_0", "group_1"})
        reduced = (self.workspace / "formula-reduced.smt2").read_text(encoding="utf-8")
        self.assertIn("(assert (>= unknown_0 0))", reduced)
        self.assertNotIn("group_2", reduced)

    def test_a_core_name_outside_the_map_stops_the_run(self) -> None:
        formula = (
            "(set-logic QF_LIA)\n" "(assert (! false :named group_9))\n" "(check-sat)\n"
        )
        constraint_map = {
            "schema_version": CONSTRAINT_MAP_SCHEMA,
            "entry": "bootstrap",
            "bounds": {"transaction_count": 1, "log_capacity": 1},
            "unknowns": [],
            "inspect_group": None,
            "groups": [
                {
                    "index": 0,
                    "name": "group_0",
                    "label": "unknown transaction domains",
                    "instruction_index": None,
                    "kind": "bounds",
                    "clauses": [],
                }
            ],
        }
        assert CVC5 is not None
        with self.assertRaises(ValidationError) as raised:
            explain_unsat(
                CVC5,
                formula,
                self.workspace,
                constraint_map,
                core_reduction_budget_seconds=5.0,
            )
        self.assertIn("group_9", str(raised.exception))

    def test_unknown_candidate_keeps_the_checked_core(self) -> None:
        run = subprocess.run

        def unknown_candidate(command, **kwargs):
            if str(command[-1]).endswith("formula-core-candidate.smt2"):
                return subprocess.CompletedProcess(command, 0, "unknown\n", "")
            return run(command, **kwargs)

        with patch("validate_checked.subprocess.run", unknown_candidate):
            self.test_core_reduction_and_diagnosis_bind_group_names()
        diagnosis = json.loads(
            (self.workspace / "diagnosis.json").read_text(encoding="utf-8")
        )
        self.assertIn("heuristically reduced", diagnosis["core_kind"])


class CoreReductionScopeTests(unittest.TestCase):
    """The reduction driver's branches, without a solver."""

    CONTEXT = ("group_0", "group_3")
    CLAUSES = ("group_2_clause_0", "group_2_clause_1")
    CORE = ("group_0", "group_2_clause_0", "group_2_clause_1", "group_3")

    def test_context_check_spends_the_same_budget_as_reduction(self) -> None:
        clock = [0]
        offered: list[float] = []

        def check(candidate: tuple[str, ...], remaining: float) -> str:
            offered.append(remaining)
            clock[0] = 2_000_000_000
            return "sat"

        with patch("validate_checked.time.perf_counter_ns", lambda: clock[0]):
            reduce_core(
                self.CORE,
                self.CONTEXT,
                self.CLAUSES,
                check,
                budget_seconds=5.0,
                inspect_group=2,
            )
        self.assertEqual(offered[0], 5.0)
        self.assertGreater(len(offered), 1)
        self.assertTrue(all(0 < remaining <= 3 for remaining in offered[1:]))

    def test_inconclusive_context_cannot_prove_a_single_clause_necessary(self) -> None:
        outcome = reduce_core(
            ("group_0", "group_2_clause_0"),
            ("group_0",),
            ("group_2_clause_0",),
            lambda candidate, remaining: "inconclusive",
            budget_seconds=5.0,
            inspect_group=2,
        )
        self.assertFalse(outcome.complete)

    def test_a_whole_core_is_reduced_when_no_group_is_inspected(self) -> None:
        def check(candidate: tuple[str, ...], remaining: float) -> str:
            return "unsat" if "group_0" in candidate else "sat"

        outcome = reduce_core(
            self.CORE,
            (),
            self.CORE,
            check,
            budget_seconds=5.0,
            inspect_group=None,
        )
        self.assertEqual(outcome.names, ("group_0",))
        self.assertEqual(outcome.kind, "subset-minimal")
        self.assertEqual(outcome.scope, "every core assertion")

    def test_only_the_inspected_clauses_are_offered_for_removal(self) -> None:
        seen: list[tuple[str, ...]] = []

        def check(candidate: tuple[str, ...], remaining: float) -> str:
            seen.append(candidate)
            if not candidate:
                return "sat"
            return "unsat" if "group_2_clause_1" in candidate else "sat"

        outcome = reduce_core(
            self.CORE,
            self.CONTEXT,
            self.CLAUSES,
            check,
            budget_seconds=5.0,
            inspect_group=2,
        )
        self.assertEqual(outcome.names, ("group_0", "group_2_clause_1", "group_3"))
        self.assertIn("clause-minimal inside group_2", outcome.kind)
        self.assertIn("fixed context", outcome.scope)
        for candidate in seen:
            self.assertTrue(set(candidate).issubset(self.CLAUSES))

    def test_context_that_is_unsat_alone_drops_the_inspected_clauses(self) -> None:
        def check(candidate: tuple[str, ...], remaining: float) -> str:
            return "unsat"

        outcome = reduce_core(
            self.CORE,
            self.CONTEXT,
            self.CLAUSES,
            check,
            budget_seconds=5.0,
            inspect_group=2,
        )
        self.assertEqual(outcome.names, self.CONTEXT)
        self.assertIn("are not required", outcome.kind)
        self.assertEqual(outcome.checks, 1)

    def test_an_absent_group_leaves_the_core_untouched(self) -> None:
        def check(candidate: tuple[str, ...], remaining: float) -> str:
            raise AssertionError("no solver call is needed")

        outcome = reduce_core(
            self.CORE,
            self.CORE,
            (),
            check,
            budget_seconds=5.0,
            inspect_group=7,
        )
        self.assertEqual(outcome.names, self.CORE)
        self.assertIn("contributed no assertion", outcome.kind)
        self.assertTrue(outcome.complete)
        self.assertEqual(outcome.checks, 0)

    def test_an_exhausted_budget_never_claims_minimality(self) -> None:
        def check(candidate: tuple[str, ...], remaining: float) -> str:
            return "inconclusive"

        outcome = reduce_core(
            self.CORE,
            self.CONTEXT,
            self.CLAUSES,
            check,
            budget_seconds=5.0,
            inspect_group=2,
        )
        self.assertFalse(outcome.complete)
        self.assertIn("heuristically reduced", outcome.kind)


class SmtQueryTests(unittest.TestCase):
    """The shared query helper must serve both backends' logics."""

    def test_query_options_follow_a_single_logic_line(self) -> None:
        formula = "(set-logic QF_LIA)\n(assert (! true :named group_0))\n(check-sat)\n"
        with_core = add_query(formula, "get-unsat-core")
        lines = with_core.splitlines()
        self.assertEqual(lines[0], "(set-logic QF_LIA)")
        self.assertEqual(lines[1], "(set-option :produce-unsat-cores true)")
        self.assertEqual(lines[2], "(set-option :check-unsat-cores true)")
        self.assertEqual(lines[-1], "(get-unsat-core)")

        legacy = "(set-logic QF_AUFLIA)\n(assert true)\n(check-sat)\n"
        self.assertIn(
            "(set-option :produce-proofs true)", add_query(legacy, "get-proof")
        )

    def test_missing_or_repeated_logic_is_rejected(self) -> None:
        with self.assertRaises(SmtEncodingError):
            add_query("(assert true)\n(check-sat)\n", "get-unsat-core")
        repeated = "(set-logic QF_LIA)\n(set-logic QF_UF)\n(check-sat)\n"
        with self.assertRaises(SmtEncodingError):
            add_query(repeated, "get-unsat-core")


if __name__ == "__main__":
    unittest.main()
