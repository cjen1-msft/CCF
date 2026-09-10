# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Opt-in checks of Lean-rendered scalar terms against cvc5."""

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
            ["nice", "-n", "10", "lake", "build", "Sparse.Smt"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run", "Sparse/SmtFixtureMain.lean"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cls.fixtures = json.loads(generated.stdout)

    def test_rendered_terms_match_solver_semantics(self) -> None:
        self.assertEqual(len(self.fixtures), 9)
        self.assertEqual(len({case["name"] for case in self.fixtures}), len(self.fixtures))
        for case in self.fixtures:
            with self.subTest(case=case["name"]):
                script = case["script"]
                self.assertTrue(script.isascii())
                path = self.artifacts / (case["name"] + ".smt2")
                path.write_text(script, encoding="ascii")
                result = run_solver(self.cvc5, path, self.artifacts, case["name"])
                self.assertEqual(result.status, case["expected"])


if __name__ == "__main__":
    unittest.main()
