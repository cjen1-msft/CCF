# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Opt-in scalar SMT rendering and generated-symbol decoding checks."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


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
            ["nice", "-n", "10", "lake", "build", "Sparse.SmtScript", "Sparse.SmtText"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run", "Sparse/SmtFixtureMain.lean"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cls.fixtures = json.loads(generated.stdout)
        symbols = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/SmtFixtureMain.lean", "--symbols",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cls.symbol_fixtures = json.loads(symbols.stdout)

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


if __name__ == "__main__":
    unittest.main()
