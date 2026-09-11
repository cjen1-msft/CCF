"""Opt-in native-sort scripts, including every unary signature."""

from collections import Counter
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
class SparseNativeSortTests(unittest.TestCase):
    def assert_cases(self, cases: list[dict]) -> None:
        self.assertEqual(len(cases), 73)
        by_name = {case["name"]: case for case in cases}
        self.assertEqual(len(by_name), len(cases))
        self.assertEqual(Counter(case["expected"] for case in cases), {"sat": 37, "unsat": 36})
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-native-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, case["expected"])
        self.assertEqual(by_name["all-signatures"]["declarations"], 30)
        for index in (0, 1):
            self.assertEqual(by_name[f"self-{index}-sat"]["prelude"], ["(set-logic QF_UFLIA)"])
        self.assertEqual(by_name["self-2-sat"]["prelude"], ["(set-logic ALL)"])
        self.assertEqual(len(by_name["self-3-sat"]["prelude"]), 2)
        entry_prelude = by_name["self-4-sat"]["prelude"]
        self.assertEqual(len(entry_prelude), 3)
        self.assertEqual(by_name["inactive-native"]["prelude"], entry_prelude)
        self.assertEqual(by_name["false-before-native"]["prelude"], entry_prelude)

    def test_native_sort_scripts(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.NativeSortFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/NativeSortFixtureMain.lean",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        self.assert_cases(json.loads(generated.stdout))


if __name__ == "__main__":
    unittest.main()
