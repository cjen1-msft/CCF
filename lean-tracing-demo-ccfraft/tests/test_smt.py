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
from Shared.smt import build_formula
from Shared.trace_io import read_ndjson
from validate import validate

CAPTURED = ROOT / "Traces" / "Captured"
MUTATED = ROOT / "Traces" / "Mutated"
ARTIFACTS = ROOT / "Artifacts" / "solver-tests"
CVC5 = os.environ.get("CVC5")


def _observations(certificate: dict[str, object]) -> int:
    reduced = certificate["reduced_trace"]
    assert isinstance(reduced, dict)
    entry = reduced["observations_at_entry"]
    steps = reduced["steps"]
    assert isinstance(entry, list)
    assert isinstance(steps, list)
    return len(entry) + sum(len(step["observations_after"]) for step in steps)


def _single_action_certificate(
    kind: str,
    parameters: dict[str, object],
) -> dict[str, object]:
    return {
        "artifact_kind": "ccfraft_reduction_certificate",
        "schema_version": "ccfraft-reduction-certificate/v1",
        "reduced_trace": {
            "observations_at_entry": [],
            "steps": [
                {
                    "action": {
                        "index": 1,
                        "kind": kind,
                        "parameters": parameters,
                        "provenance": [{"line": 1, "role": "raft_event"}],
                        "rule": "test",
                    },
                    "observations_after": [],
                }
            ],
        },
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
                first.text.count(":named transition_action_"),
                action_count,
            )
            self.assertEqual(
                first.text.count(":named observation_"),
                _observations(certificate),
            )
            self.assertEqual(
                first.text.count(":named valid_entry_node_"),
                len(first.nodes),
            )
            for position, step in enumerate(
                certificate["reduced_trace"]["steps"],
                1,
            ):
                action = step["action"]
                line = min(item["line"] for item in action["provenance"])
                expected = (
                    f":named transition_action_{position:04d}_"
                    f"line_{line:04d}_{action['kind']}"
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
                {"source": "0", "newConfiguration": ["0", "1"]},
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
        formula = build_formula(
            _single_action_certificate("becomeLeader", {"node": "0"})
        )
        self.assertIn(
            "(<= (select state_0001_log_length 0) " "(select state_0000_log_length 0))",
            formula.text,
        )
        self.assertNotIn(
            "(>= (select state_0001_log_length 0) "
            "(select state_0000_commit_index 0))",
            formula.text,
        )


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
        self.assertGreaterEqual(result["check_sat_wall_ms"], 0)
        self.assertGreaterEqual(result["total_solver_wall_ms"], 0)
        return status, output_directory, emitted

    def test_captured_traces_are_sat(self) -> None:
        for trace_path in sorted(CAPTURED.glob("*.ndjson")):
            with self.subTest(trace=trace_path.name):
                status, output_directory, emitted = self._validate(trace_path)
                self.assertEqual(status, "sat")
                self.assertEqual(emitted, "sat\n")
                self.assertFalse((output_directory / "proof.txt").exists())
                self.assertFalse((output_directory / "unsat-core.txt").exists())

    def test_mutated_traces_are_unsat_with_solver_evidence(self) -> None:
        for trace_path in sorted(MUTATED.glob("*.ndjson")):
            with self.subTest(trace=trace_path.name):
                status, output_directory, emitted = self._validate(trace_path)
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
                self.assertGreaterEqual(parsed["unsat_core_wall_ms"], 0)
                self.assertGreaterEqual(parsed["proof_wall_ms"], 0)
                self.assertGreaterEqual(
                    parsed["total_solver_wall_ms"],
                    parsed["check_sat_wall_ms"],
                )


if __name__ == "__main__":
    unittest.main()
