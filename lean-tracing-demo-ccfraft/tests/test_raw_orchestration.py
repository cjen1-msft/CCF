# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Mocked routing and artifact tests, not evidence of raw-model semantics."""

from __future__ import annotations

import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
from types import MappingProxyType
import unittest
from unittest.mock import patch

from raw_normalization import ACTION_PARAMETERS, normalize
from reduction import ReductionError, build_certificate, write_certificate
from Shared.solver import SolverRun, ValidationError
from Shared.trace_io import NDJSONError, read_ndjson
import validate
import validate_checked as checked

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "Traces/Captured/bad_network.ndjson"
BOUNDS = {
    "transaction_count": 3,
    "term_count": 4,
    "index_count": 16,
    "log_capacity": 2,
    "queue_capacity": 2,
}


def fake_result(status: str = "sat") -> dict[str, object]:
    return {
        "status": status,
        "validation_wall_ms": 8.0,
        "check_sat_wall_ms": 1.0,
        "total_solver_wall_ms": 1.0,
        "encoder_wall_ms": 2.0,
        "cvc5": "/mock/cvc5",
        "proof_gate": {"checked": True, "target": "mock-only"},
        "assurance": {"entry": "symbolic", "scope": "mock-only"},
    }


def fake_backend(certificate: Path, output: Path, **kwargs: object) -> str:
    write_certificate(output / "result.json", fake_result())
    print("sat")
    return "sat"


class RawOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="raw-orchestration-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "output"
        # No test in this module may accidentally start a native build or solver.
        self.process = self.enterContext(
            patch("subprocess.run", side_effect=AssertionError("unexpected subprocess"))
        )

    def read(self, name: str) -> dict:
        return json.loads((self.output / name).read_text(encoding="utf-8"))

    def call(self, **kwargs: object) -> str:
        with contextlib.redirect_stdout(io.StringIO()):
            return validate.validate(TRACE, self.output, **kwargs)

    def test_exact_route_and_artifacts_for_all_six_saved_raw_fixtures(self) -> None:
        sources = sorted((ROOT / "Traces/Captured").glob("*.ndjson"))
        sources += sorted((ROOT / "Traces/Mutated").glob("*.ndjson"))
        self.assertEqual(len(sources), 6)
        for source in sources:
            with self.subTest(source=source.name):
                reduced = build_certificate(read_ndjson(source))
                normalized = normalize(reduced)
                with (
                    patch.object(
                        validate, "preprocess", wraps=validate.preprocess
                    ) as pre,
                    patch.object(validate, "reduce", wraps=validate.reduce) as red,
                    patch.object(validate, "normalize", wraps=normalize) as norm,
                    patch.object(
                        checked, "validate_checked", side_effect=fake_backend
                    ) as backend,
                    contextlib.redirect_stdout(io.StringIO()) as stdout,
                ):
                    self.assertEqual(
                        validate.validate(
                            source,
                            self.output,
                            bounds=BOUNDS,
                            cvc5=Path("/selected/cvc5"),
                            inspect_group=7,
                            core_reduction_budget_seconds=0.25,
                        ),
                        "sat",
                    )
                self.assertEqual(stdout.getvalue(), "sat\n")
                pre.assert_called_once()
                red.assert_called_once()
                norm.assert_called_once_with(reduced)
                backend.assert_called_once_with(
                    self.output / "certificate.json",
                    self.output,
                    cvc5=Path("/selected/cvc5"),
                    inspect_group=7,
                    core_reduction_budget_seconds=0.25,
                )
                self.assertEqual(self.read("reduced-certificate.json"), reduced)
                certificate = self.read("certificate.json")
                self.assertEqual(certificate, normalized.certificate(BOUNDS))
                self.assertEqual(
                    set(certificate),
                    {"schema_version", "entry", "bounds", "unknowns", "steps"},
                )
                self.assertEqual(
                    certificate["schema_version"], "ccfraft-symbolic-trace/v1"
                )
                self.assertEqual(certificate["entry"], "symbolic")
                mapping = self.read("normalization.json")
                self.assertEqual(
                    mapping["node_names"],
                    {str(slot): name for slot, name in normalized.node_names.items()},
                )
                self.assertEqual(
                    mapping["transaction_names"],
                    {name: {"unknown": name} for name in normalized.unknowns},
                )
                self.assertEqual(
                    self.read("evidence.json"),
                    {str(index): value for index, value in normalized.evidence.items()},
                )
                provenance = self.read("provenance.json")
                self.assertEqual(len(provenance), len(certificate["steps"]))
                for index, step in enumerate(certificate["steps"], 1):
                    self.assertEqual(
                        provenance[str(index)]["provenance"], step["provenance"]
                    )
                    self.assertEqual(provenance[str(index)]["rule"], step["rule"])
                    self.assertNotIn("evidence", step)
                result = self.read("result.json")
                self.assertEqual(result["assurance"], fake_result()["assurance"])
                self.assertEqual(result["checked_validation_wall_ms"], 8.0)
                for timing in result["phase_wall_ms"].values():
                    self.assertGreaterEqual(timing, 0)
                # No invented separate serialization or decision measurement.
                self.assertNotIn("smt_write", result["phase_wall_ms"])
                self.assertNotIn("decision_wall_ms", result)

    def seed_stale(self) -> None:
        self.output.mkdir(exist_ok=True)
        for name in (
            *validate.RAW_ARTIFACTS,
            "result.json",
            "constraint-map.json",
            "diagnosis.json",
            "formula.smt2",
            "unsat-core.txt",
            "cvc5-status.stdout",
        ):
            (self.output / name).write_text("stale success", encoding="utf-8")
        (self.output / "unrelated.txt").write_text("keep", encoding="utf-8")

    def assert_failed(self) -> None:
        self.assertFalse((self.output / "result.json").exists())
        self.assertFalse((self.output / "proof.txt").exists())
        self.assertEqual(self.read("error.json")["status"], "error")
        self.assertEqual((self.output / "unrelated.txt").read_text(), "keep")

    def test_missing_or_invalid_bounds_never_reach_backend_or_leave_success(
        self,
    ) -> None:
        invalid = [
            None,
            {},
            [],
            {**BOUNDS, "extra": 1},
            *(
                {**BOUNDS, field: value}
                for field in BOUNDS
                for value in (-1, True, 1.5, "1")
            ),
        ]
        for bounds in invalid:
            with self.subTest(bounds=bounds):
                self.seed_stale()
                with patch.object(checked, "validate_checked") as backend:
                    with self.assertRaises(ReductionError):
                        self.call(bounds=bounds)
                backend.assert_not_called()
                self.assert_failed()
                self.assertFalse((self.output / "certificate.json").exists())

    def test_zero_bounds_are_not_inferred_or_expanded(self) -> None:
        bounds = dict.fromkeys(BOUNDS, 0)
        with patch.object(checked, "validate_checked", side_effect=fake_backend):
            self.call(bounds=MappingProxyType(bounds))
        self.assertEqual(self.read("certificate.json")["bounds"], bounds)
        self.assertEqual(bounds, dict.fromkeys(BOUNDS, 0))

    def test_all_actions_keep_parameters_sparse_slots_and_aliasable_unknowns(
        self,
    ) -> None:
        parameters = {
            "transaction": "transaction-a",
            "configuration": ["2", "14"],
            "destination": "14",
            "source": "14",
            "batchEnd": 1,
        }
        steps = [
            {
                "kind": "action",
                "action": action,
                "node": "2",
                "provenance": [{"line": index}],
                "rule": "mock-reduction",
                **{field: parameters[field] for field in fields},
            }
            for index, (action, fields) in enumerate(ACTION_PARAMETERS.items(), 1)
        ]
        steps += [
            {**deepcopy(steps[0]), "transaction": name}
            for name in ("transaction-b", "transaction-a")
        ]
        reduced = {"schema_version": "ccfraft-reduction-certificate/v2", "steps": steps}
        before = deepcopy(reduced)
        with (
            patch.object(validate, "reduce", return_value=reduced),
            patch.object(checked, "validate_checked", side_effect=fake_backend),
        ):
            self.call(bounds=BOUNDS)
        certificate = self.read("certificate.json")
        self.assertEqual(certificate, normalize(reduced).certificate(BOUNDS))
        self.assertEqual(reduced, before)
        self.assertEqual(len({step["action"] for step in certificate["steps"]}), 17)
        self.assertEqual(certificate["unknowns"], ["transaction-a", "transaction-b"])
        self.assertEqual(
            self.read("normalization.json")["node_names"], {"2": "2", "14": "14"}
        )

    def test_unsupported_normalization_and_raw_parse_fail_without_fallback(
        self,
    ) -> None:
        for target, error in (
            ("read_ndjson", NDJSONError("line 2: malformed NDJSON")),
            ("preprocess", ReductionError("line 4: unaudited event")),
            ("normalize", ReductionError("unsupported raw action")),
        ):
            with self.subTest(target=target):
                self.seed_stale()
                with (
                    patch.object(validate, target, side_effect=error),
                    patch.object(checked, "validate_checked") as backend,
                    self.assertRaises(type(error)),
                ):
                    self.call(bounds=BOUNDS)
                backend.assert_not_called()
                self.assert_failed()

    def test_actual_raw_input_errors_are_recorded_with_no_backend_call(self) -> None:
        source = Path(self.temporary.name) / "invalid.ndjson"
        for payload, error in (
            (b'{"tag":"raft_trace","cmd":"test"}\n{bad\n', NDJSONError),
            (b"\xff\n", UnicodeError),
        ):
            with (
                self.subTest(payload=payload),
                patch.object(checked, "validate_checked") as backend,
                self.assertRaises(error),
            ):
                self.seed_stale()
                source.write_bytes(payload)
                validate.validate(source, self.output, bounds=BOUNDS)
            backend.assert_not_called()
            self.assert_failed()

    def test_unsupported_reduced_action_is_not_projected(self) -> None:
        reduced = {
            "schema_version": "ccfraft-reduction-certificate/v2",
            "steps": [
                {
                    "kind": "action",
                    "action": "futureAction",
                    "node": "0",
                    "rule": "test",
                    "provenance": [{"line": 1}],
                }
            ],
        }
        self.seed_stale()
        with (
            patch.object(validate, "reduce", return_value=reduced),
            patch.object(checked, "validate_checked") as backend,
            self.assertRaisesRegex(ReductionError, "unsupported raw action"),
        ):
            self.call(bounds=BOUNDS)
        backend.assert_not_called()
        self.assert_failed()
        self.assertEqual(self.read("reduced-certificate.json"), reduced)
        self.assertFalse((self.output / "certificate.json").exists())

    def test_backend_rejection_and_failure_never_fall_back(self) -> None:
        for error in (
            checked.CertificateRejected("symbolic dispatch not implemented"),
            ValidationError("proof gate failed"),
            OSError("encoder missing"),
        ):
            with self.subTest(error=error):
                self.seed_stale()
                with (
                    patch.object(
                        checked, "validate_checked", side_effect=error
                    ) as backend,
                    self.assertRaises(type(error)),
                ):
                    self.call(bounds=BOUNDS)
                backend.assert_called_once()
                self.assert_failed()
                self.assertEqual(
                    self.read("error.json")["certificate_rejected"],
                    isinstance(error, checked.CertificateRejected),
                )
                self.assertTrue((self.output / "certificate.json").is_file())

    def test_unknown_is_preserved_without_proof_or_core_queries(self) -> None:
        def backend(certificate: Path, output: Path, **kwargs: object) -> str:
            write_certificate(output / "result.json", fake_result("unknown"))
            print("unknown")
            return "unknown"

        with patch.object(checked, "validate_checked", side_effect=backend):
            self.assertEqual(self.call(bounds=BOUNDS), "unknown")
        self.assertEqual(self.read("result.json")["status"], "unknown")
        self.assertFalse((self.output / "proof.txt").exists())

    def test_actual_checked_runner_orders_gate_encoding_and_shared_solver(self) -> None:
        for expected_status in ("sat", "unknown"):
            events = []

            def gate(*args: object) -> dict:
                events.append("gate")
                return {"checked": True}

            def encoder(
                root: Path, certificate: Path, output: Path, **kwargs: object
            ) -> float:
                events.append("encoder")
                document = json.loads(certificate.read_text())
                write_certificate(
                    output / "constraint-map.json",
                    {
                        "schema_version": checked.CONSTRAINT_MAP_SCHEMA,
                        "certificate_schema": document["schema_version"],
                        "entry": document["entry"],
                        "bounds": document["bounds"],
                        "unknowns": document["unknowns"],
                        "theorem": checked.SYMBOLIC_THEOREM,
                        "supported_actions": list(ACTION_PARAMETERS),
                        "inspect_group": None,
                        "groups": [
                            {
                                "index": 0,
                                "name": "group_0",
                                "label": "mock bounds",
                                "kind": "bounds",
                                "clauses": [],
                            }
                        ],
                    },
                )
                (output / "formula.smt2").write_text(
                    "(set-logic QF_UF)\n(assert (! true :named group_0))\n(check-sat)\n"
                )
                return 2.0

            def solver(*args: object) -> SolverRun:
                events.append("solver")
                return SolverRun(expected_status, f"{expected_status}\n", "", 3.0)

            with (
                self.subTest(status=expected_status),
                patch.object(checked, "find_cvc5", return_value=Path("/mock/cvc5")),
                patch.object(checked, "build_proof_gate", side_effect=gate),
                patch.object(checked, "run_encoder", side_effect=encoder),
                patch.object(checked, "run_solver", side_effect=solver),
            ):
                self.assertEqual(self.call(bounds=BOUNDS), expected_status)
            self.assertEqual(events, ["gate", "encoder", "solver"])
            result = self.read("result.json")
            self.assertEqual(result["status"], expected_status)
            self.assertEqual(
                result["assurance"]["encoder_theorem"], checked.SYMBOLIC_THEOREM
            )
            self.assertEqual(result["check_sat_wall_ms"], 3.0)
            self.assertEqual(result["encoder_wall_ms"], 2.0)

    def test_actual_checked_gate_failure_stops_before_encoding_or_solver(self) -> None:
        self.seed_stale()
        with (
            patch.object(checked, "find_cvc5", return_value=Path("/mock/cvc5")),
            patch.object(
                checked, "build_proof_gate", side_effect=ValidationError("gate")
            ),
            patch.object(checked, "run_encoder") as encoder,
            patch.object(checked, "run_solver") as solver,
            self.assertRaises(ValidationError),
        ):
            self.call(bounds=BOUNDS)
        encoder.assert_not_called()
        solver.assert_not_called()
        self.assert_failed()

    def test_unsat_uses_checked_core_and_shared_proof_query(self) -> None:
        def backend(certificate: Path, output: Path, **kwargs: object) -> str:
            write_certificate(
                output / "result.json",
                {
                    **fake_result("unsat"),
                    "core_kind": "mock-core",
                    "core_fixed_context_names": ["group_0", "group_1"],
                },
            )
            (output / "formula-reduced.smt2").write_text(
                "(set-logic QF_UF)\n(assert false)\n(check-sat)\n",
                encoding="utf-8",
            )
            print("unsat")
            return "unsat"

        with (
            patch.object(checked, "validate_checked", side_effect=backend),
            patch.object(
                validate,
                "run_solver",
                return_value=SolverRun("unsat", "unsat\n(mock proof)\n", "", 4.0),
            ) as solver,
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            status = validate.validate(
                TRACE, self.output, bounds=BOUNDS, show_proof=True
            )
        self.assertEqual(status, "unsat")
        self.assertEqual(stdout.getvalue(), "unsat\n(mock proof)\n")
        solver.assert_called_once_with(
            Path("/mock/cvc5"),
            self.output / "formula-reduced-proof.smt2",
            self.output,
            "cvc5-proof",
        )
        result = self.read("result.json")
        self.assertEqual(result["core_fixed_context_names"], ["group_0", "group_1"])
        self.assertEqual(result["total_solver_wall_ms"], 5.0)
        self.assertEqual(result["proof_scope"], "mock-core")
        formula = (self.output / "formula-reduced-proof.smt2").read_text()
        self.assertIn("(set-option :check-proofs true)", formula)
        self.assertTrue(formula.endswith("(get-proof)\n"))

    def test_proof_failure_removes_backend_verdict(self) -> None:
        def backend(certificate: Path, output: Path, **kwargs: object) -> str:
            write_certificate(
                output / "result.json",
                {**fake_result("unsat"), "core_kind": "mock-core"},
            )
            (output / "formula-reduced.smt2").write_text(
                "(set-logic QF_UF)\n(assert false)\n(check-sat)\n"
            )
            return "unsat"

        for proof_run in (
            SolverRun("unknown", "unknown\n", "", 1.0),
            SolverRun("unsat", 'unsat\n(error "proof unavailable")\n', "", 1.0),
        ):
            with (
                self.subTest(proof_run=proof_run),
                patch.object(checked, "validate_checked", side_effect=backend),
                patch.object(validate, "run_solver", return_value=proof_run),
                self.assertRaises(ValidationError),
            ):
                self.seed_stale()
                self.call(bounds=BOUNDS)
            self.assert_failed()

    def test_encode_only_calls_gate_before_encoder_and_never_solver(self) -> None:
        events = []

        def gate(*args: object) -> dict:
            events.append("gate")
            return {"checked": True}

        def encode(*args: object, **kwargs: object) -> float:
            events.append("encode")
            (self.output / "formula.smt2").write_text("(check-sat)\n")
            return 1.0

        constraint_map = {
            "entry": "symbolic",
            "certificate_schema": "ccfraft-symbolic-trace/v1",
            "theorem": checked.SYMBOLIC_THEOREM,
            "bounds": BOUNDS,
            "unknowns": [],
            "supported_actions": list(ACTION_PARAMETERS),
        }
        with (
            patch.object(checked, "build_proof_gate", side_effect=gate),
            patch.object(checked, "run_encoder", side_effect=encode),
            patch.object(checked, "read_constraint_map", return_value=constraint_map),
            patch.object(checked, "validate_checked") as backend,
        ):
            self.assertEqual(self.call(bounds=BOUNDS, encode_only=True), "encoded")
        self.assertEqual(events, ["gate", "encode"])
        backend.assert_not_called()
        self.assertEqual(self.read("result.json")["status"], "encoded")
        self.assertNotIn("check_sat_wall_ms", self.read("result.json"))

    def test_encode_only_gate_failure_cannot_invoke_encoder(self) -> None:
        self.seed_stale()
        with (
            patch.object(
                checked, "build_proof_gate", side_effect=ValidationError("gate")
            ),
            patch.object(checked, "run_encoder") as encoder,
            self.assertRaises(ValidationError),
        ):
            self.call(bounds=BOUNDS, encode_only=True)
        encoder.assert_not_called()
        self.assert_failed()

    def test_cli_requires_bounds_and_forwards_loaded_profile(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            validate.parse_args([str(TRACE), str(self.output)])
        profile = Path(self.temporary.name) / "bounds.json"
        write_certificate(profile, BOUNDS)
        with (
            patch.object(checked, "validate_checked", side_effect=fake_backend),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                validate.main(
                    [
                        str(TRACE),
                        "--output-dir",
                        str(self.output),
                        "--bounds",
                        str(profile),
                    ]
                ),
                0,
            )
        self.assertEqual(self.read("certificate.json")["bounds"], BOUNDS)
        for text in ("[]", "{broken"):
            self.seed_stale()
            profile.write_text(text)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    validate.main(
                        [str(TRACE), str(self.output), "--bounds", str(profile)]
                    ),
                    2,
                )
            self.assert_failed()


class ArtifactCollisionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="artifact-collision-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "output"
        self.output.mkdir()
        self.raw = self.root / "raw.ndjson"
        self.raw.write_bytes(TRACE.read_bytes())
        self.profile = self.root / "bounds.json"
        write_certificate(self.profile, BOUNDS)
        (self.output / "unrelated.txt").write_text("keep")
        (self.output / "result.json").write_text("previous verdict, not a new run")
        self.enterContext(
            patch("subprocess.run", side_effect=AssertionError("unexpected subprocess"))
        )

    def snapshot(self) -> dict:
        return {
            str(path.relative_to(self.root)): (
                path.read_bytes(),
                path.lstat().st_ino,
                path.lstat().st_mtime_ns,
                str(path.readlink()) if path.is_symlink() else None,
            )
            for path in self.root.rglob("*")
            if path.is_file()
        }

    def test_raw_api_rejects_reserved_input_before_any_write(self) -> None:
        for name in (
            "certificate.json",
            "constraint-map.json",
            "error.json",
            "cvc5-other.stdout",
        ):
            with self.subTest(name=name):
                source = self.output / name
                source.write_bytes(self.raw.read_bytes())
                before = self.snapshot()
                with (
                    patch.object(checked, "validate_checked") as backend,
                    self.assertRaisesRegex(ValidationError, "collision"),
                ):
                    validate.validate(source, self.output, bounds=BOUNDS)
                backend.assert_not_called()
                self.assertEqual(self.snapshot(), before)
                source.unlink()

    def test_raw_cli_protects_source_and_profile_including_error_record(self) -> None:
        for protected in ("source", "profile"):
            for name in (
                "certificate.json",
                "constraint-map.json",
                "error.json",
                "cvc5-extra.stderr",
            ):
                with self.subTest(protected=protected, name=name):
                    path = self.output / name
                    path.write_bytes(
                        self.raw.read_bytes()
                        if protected == "source"
                        else self.profile.read_bytes()
                    )
                    before = self.snapshot()
                    with (
                        patch.object(checked, "validate_checked") as backend,
                        contextlib.redirect_stderr(io.StringIO()) as stderr,
                        contextlib.redirect_stdout(io.StringIO()) as stdout,
                    ):
                        result = validate.main(
                            [
                                str(path if protected == "source" else self.raw),
                                str(self.output),
                                "--bounds",
                                str(path if protected == "profile" else self.profile),
                            ]
                        )
                    self.assertEqual(result, 2)
                    self.assertIn("collision", stderr.getvalue())
                    self.assertEqual(stdout.getvalue(), "")
                    backend.assert_not_called()
                    self.assertEqual(self.snapshot(), before)
                    path.unlink()

    def test_checked_api_and_cli_protect_the_input_before_cleanup(self) -> None:
        for name in ("constraint-map.json", "error.json", "cvc5-extra.stdout"):
            with self.subTest(name=name):
                source = self.output / name
                source.write_text('{"input":"preserve"}')
                before = self.snapshot()
                with (
                    patch.object(checked, "_run_validation") as backend,
                    self.assertRaisesRegex(ValidationError, "collision"),
                ):
                    checked.validate_checked(source, self.output)
                backend.assert_not_called()
                self.assertEqual(self.snapshot(), before)
                with (
                    patch.object(checked, "_run_validation") as backend,
                    contextlib.redirect_stderr(io.StringIO()) as stderr,
                ):
                    self.assertEqual(checked.main([str(source), str(self.output)]), 2)
                self.assertIn("collision", stderr.getvalue())
                backend.assert_not_called()
                self.assertEqual(self.snapshot(), before)
                source.unlink()

    def test_alias_collisions_are_no_operations(self) -> None:
        for alias in (
            "input-symlink",
            "artifact-symlink",
            "hardlink",
            "output-symlink",
        ):
            with self.subTest(alias=alias):
                artifact = self.output / "error.json"
                source = self.raw
                output = self.output
                if alias == "input-symlink":
                    artifact.write_bytes(self.raw.read_bytes())
                    source = self.root / "alias.ndjson"
                    source.symlink_to(artifact)
                elif alias == "artifact-symlink":
                    artifact.symlink_to(source)
                elif alias == "hardlink":
                    artifact.hardlink_to(source)
                else:
                    artifact.write_bytes(self.raw.read_bytes())
                    source = artifact
                    output = self.root / "alias-output"
                    output.symlink_to(self.output, target_is_directory=True)
                before = self.snapshot()
                with (
                    patch.object(checked, "validate_checked") as backend,
                    self.assertRaisesRegex(ValidationError, "collision"),
                ):
                    validate.validate(source, output, bounds=BOUNDS)
                backend.assert_not_called()
                self.assertEqual(self.snapshot(), before)
                artifact.unlink()
                if alias == "input-symlink":
                    source.unlink()
                elif alias == "output-symlink":
                    output.unlink()

    def test_profile_aliases_are_preserved_by_cli(self) -> None:
        for alias in ("symlink", "hardlink"):
            with self.subTest(alias=alias):
                artifact = self.output / "error.json"
                if alias == "symlink":
                    artifact.symlink_to(self.profile)
                else:
                    artifact.hardlink_to(self.profile)
                before = self.snapshot()
                with (
                    contextlib.redirect_stderr(io.StringIO()) as stderr,
                    patch.object(checked, "validate_checked") as backend,
                ):
                    self.assertEqual(
                        validate.main(
                            [
                                str(self.raw),
                                str(self.output),
                                "--bounds",
                                str(self.profile),
                            ]
                        ),
                        2,
                    )
                self.assertIn("collision", stderr.getvalue())
                backend.assert_not_called()
                self.assertEqual(self.snapshot(), before)
                artifact.unlink()

    def test_nonreserved_colocated_inputs_remain_supported(self) -> None:
        source = self.output / "raw.ndjson"
        source.write_bytes(self.raw.read_bytes())
        profile = self.output / "bounds.json"
        profile.write_bytes(self.profile.read_bytes())
        with (
            patch.object(checked, "validate_checked", side_effect=fake_backend),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                validate.main(
                    [
                        str(source),
                        str(self.output),
                        "--bounds",
                        str(profile),
                    ]
                ),
                0,
            )
        self.assertEqual(source.read_bytes(), self.raw.read_bytes())
        self.assertEqual(profile.read_bytes(), self.profile.read_bytes())
        self.assertEqual((self.output / "unrelated.txt").read_text(), "keep")
        certificate = self.output / "certificate.json"
        before = certificate.read_bytes()
        with patch.object(checked, "_run_validation", return_value="sat"):
            self.assertEqual(checked.validate_checked(certificate, self.output), "sat")
        self.assertEqual(certificate.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
