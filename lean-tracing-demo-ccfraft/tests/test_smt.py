# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Shared core utilities and opt-in real checked raw-trace regressions."""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from Shared.smt import parse_unsat_core, reduce_unsat_core, restrict_to_assertions
from validate import read_bounds, validate
import validate_checked as checked

ROOT = Path(__file__).resolve().parents[1]
CAPTURED = ROOT / "Traces/Captured"
MUTATED = ROOT / "Traces/Mutated"


class SmtFormulaTests(unittest.TestCase):
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

        reduced = reduce_unsat_core(("first", "second"), check, budget_seconds=1)
        self.assertFalse(reduced.complete)
        self.assertEqual(reduced.names, ("first", "second"))


@unittest.skipUnless(
    os.environ.get("CCF_RAW_BACKEND_TESTS") == "1",
    "requires native slot approval; set CCF_RAW_BACKEND_TESTS=1, CVC5 and CCF_RAW_BOUNDS",
)
class Cvc5IntegrationTests(unittest.TestCase):
    """Real backend tests. No mocks, inferred bounds, or weakened SAT expectations."""

    @classmethod
    def setUpClass(cls) -> None:
        solver = os.environ.get("CVC5")
        profile = os.environ.get("CCF_RAW_BOUNDS")
        if not solver or not profile:
            raise RuntimeError(
                "declare CVC5 and a five-bound JSON path in CCF_RAW_BOUNDS"
            )
        cls.cvc5 = Path(solver)
        cls.bounds = read_bounds(Path(profile))
        cls.temporary = tempfile.TemporaryDirectory(prefix="raw-checked-integration-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.artifacts = Path(cls.temporary.name)

    def _validate(self, trace: Path) -> tuple[str, Path, dict]:
        output = self.artifacts / trace.stem
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            status = validate(trace, output, bounds=self.bounds, cvc5=self.cvc5)
        self.assertEqual(stdout.getvalue(), f"{status}\n")
        self.assertEqual(
            (output / "cvc5-status.stdout").read_text().splitlines()[0], status
        )
        self.assertTrue((output / "cvc5-status.stderr").is_file())
        result = json.loads((output / "result.json").read_text())
        certificate = json.loads((output / "certificate.json").read_text())
        self.assertEqual(certificate["schema_version"], "ccfraft-symbolic-trace/v1")
        self.assertEqual(certificate["entry"], "symbolic")
        self.assertEqual(certificate["bounds"], self.bounds)
        self.assertEqual(
            result["assurance"]["encoder_theorem"], checked.SYMBOLIC_THEOREM
        )
        self.assertEqual(result["assurance"]["entry"], "symbolic")
        self.assertEqual(result["assurance"]["bounds"], self.bounds)
        self.assertTrue(result["proof_gate"]["checked"])
        for artifact in (
            "reduced_certificate",
            "normalization",
            "evidence",
            "provenance",
        ):
            self.assertTrue((output / result[artifact]).is_file())
        for timing in result["phase_wall_ms"].values():
            self.assertGreaterEqual(timing, 0)
        for key in (
            "validation_wall_ms",
            "check_sat_wall_ms",
            "total_solver_wall_ms",
            "encoder_wall_ms",
            "checked_validation_wall_ms",
        ):
            self.assertGreaterEqual(result[key], 0)
        return status, output, result

    def test_captured_traces_are_sat(self) -> None:
        # Retain the old expectations until actual-model runs reconcile them.
        # Projection SAT or successful decoding is not evidence for these claims.
        traces = sorted(CAPTURED.glob("*.ndjson"))
        self.assertEqual(len(traces), 2)
        for trace in traces:
            with self.subTest(trace=trace.name):
                status, output, _ = self._validate(trace)
                self.assertEqual(
                    status,
                    "sat",
                    "Actual-model disagreement must be reconciled, not hidden by a fallback",
                )
                self.assertFalse((output / "proof.txt").exists())
                self.assertFalse((output / "unsat-core.txt").exists())

    def test_mutated_traces_are_unsat_with_checked_constraint_evidence(self) -> None:
        traces = sorted(MUTATED.glob("*.ndjson"))
        self.assertEqual(len(traces), 4)
        for trace in traces:
            with self.subTest(trace=trace.name):
                status, output, result = self._validate(trace)
                self.assertEqual(status, "unsat")
                self.assertTrue((output / "proof.txt").read_text().strip())
                self.assertTrue((output / "unsat-core.txt").read_text().strip())
                self.assertTrue(result["proof_checked_by_cvc5"])
                self.assertTrue(result["unsat_core_checked_by_cvc5"])
                self.assertLessEqual(
                    result["reduced_unsat_core_assertions"],
                    result["original_unsat_core_assertions"],
                )
                self.assertTrue((output / "formula-reduced.smt2").is_file())
                self.assertTrue((output / "formula-reduced-proof.smt2").is_file())
                diagnosis = json.loads((output / "diagnosis.json").read_text())
                self.assertEqual(result["proof_scope"], diagnosis["core_kind"])
                self.assertEqual(
                    len(diagnosis["items"]), result["reduced_unsat_core_assertions"]
                )
                provenance = json.loads((output / "provenance.json").read_text())
                for item in diagnosis["items"]:
                    if item["group_kind"] in {"action", "observation"}:
                        index = str(item["instruction_index"])
                        self.assertIn(index, provenance)
                        self.assertIn("provenance", provenance[index])
                self.assertGreaterEqual(
                    result["total_solver_wall_ms"], result["check_sat_wall_ms"]
                )


if __name__ == "__main__":
    unittest.main()
