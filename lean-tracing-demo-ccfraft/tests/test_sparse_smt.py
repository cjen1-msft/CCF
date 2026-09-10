# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Opt-in scalar SMT rendering and token-decoding checks."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


def load_fixtures(*args: str) -> list[dict]:
    generated = subprocess.run(
        [
            "nice", "-n", "10", "lake", "env", "lean", "--run",
            "Sparse/SmtFixtureMain.lean", *args,
        ],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return json.loads(generated.stdout)


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseSmtIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        requested = os.environ.get("CVC5")
        cls.cvc5 = find_cvc5(Path(requested) if requested else None)
        cls.temporary = tempfile.TemporaryDirectory(prefix="sparse-smt-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.artifacts = Path(cls.temporary.name)
        subprocess.run(
            [
                "nice", "-n", "10", "lake", "build",
                "Sparse.SmtScript", "Sparse.SmtText", "Sparse.SmtNumerals",
                "Sparse.SmtExpressionText",
                "Sparse.SmtScriptText",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cls.fixtures = load_fixtures()
        cls.symbol_fixtures = load_fixtures("--symbols")
        cls.numeral_fixtures = load_fixtures("--numerals")
        cls.expression_fixtures = load_fixtures("--expressions")
        cls.script_fixtures = load_fixtures("--scripts")

    def test_rendered_terms_match_solver_semantics(self) -> None:
        self.assertEqual(len(self.fixtures), 11)
        self.assertEqual(len({case["name"] for case in self.fixtures}), len(self.fixtures))
        for case in self.fixtures:
            for renderer in ("script", "generated_script"):
                with self.subTest(case=case["name"], renderer=renderer):
                    script = case[renderer]
                    self.assertTrue(script.isascii())
                    stem = case["name"] + "-" + renderer
                    path = self.artifacts / (stem + ".smt2")
                    path.write_text(script, encoding="ascii")
                    result = run_solver(self.cvc5, path, self.artifacts, stem)
                    self.assertEqual(result.status, case["expected"])

    def test_generated_declarations_are_unique(self) -> None:
        for case in self.fixtures:
            declarations = [
                line.split()[1]
                for line in case["generated_script"].splitlines()
                if line.startswith("(declare-fun ")
            ]
            with self.subTest(case=case["name"]):
                self.assertEqual(len(declarations), len(set(declarations)))

    def test_symbol_tokens_roundtrip_and_reject_malformed_names(self) -> None:
        self.assertEqual(len(self.symbol_fixtures), 77)
        self.assertEqual(
            sum(case["expected"] is None for case in self.symbol_fixtures), 11
        )
        for case in self.symbol_fixtures:
            with self.subTest(text=case["text"]):
                self.assertEqual(case["actual"], case["expected"])

    def test_numeral_tokens_roundtrip_and_reject_malformed_text(self) -> None:
        self.assertEqual(len(self.numeral_fixtures), 24)
        self.assertEqual(
            sum(case["expected"] is None for case in self.numeral_fixtures), 14
        )
        for case in self.numeral_fixtures:
            with self.subTest(text=case["text"]):
                self.assertEqual(case["actual"], case["expected"])

    def test_expression_text_preserves_structure_and_evaluation(self) -> None:
        self.assertEqual(len(self.expression_fixtures), 17)
        expressions = list(self.expression_fixtures)
        for fixture in self.fixtures:
            expressions.extend(fixture["expressions"])
        for case in expressions:
            with self.subTest(name=case["name"], text=case["text"]):
                self.assertEqual(case["actual_render"], case["expected_render"])
                self.assertEqual(case["actual_value"], case["expected_value"])

    def test_script_text_preserves_commands_and_fixed_assignment_truth(self) -> None:
        for case in self.fixtures:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["parsed_script"], case["generated_script"])
                self.assertEqual(case["parsed_value"], case["command_value"])
        self.assertEqual(len(self.script_fixtures), 18)
        for case in self.script_fixtures:
            with self.subTest(case=case["name"], text=case["text"]):
                self.assertEqual(case["actual_render"], case["expected_render"])
                self.assertEqual(case["actual_value"], case["expected_value"])


if __name__ == "__main__":
    unittest.main()
