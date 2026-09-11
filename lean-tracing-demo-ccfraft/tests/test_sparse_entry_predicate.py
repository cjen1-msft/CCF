"""Opt-in Entry predicate lowering against independent value comparisons."""

import json
import operator
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]
OPERATORS = {"eq": operator.eq, "ne": operator.ne, "le": operator.le, "lt": operator.lt}


def decode(value: int) -> int:
    return value * 2 if value >= 0 else -value * 2 - 1


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseEntryPredicateTests(unittest.TestCase):
    def test_entry_comparisons(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.EntryPredicateFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run", "Sparse/EntryPredicateFixtureMain.lean"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 620)
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-entry-predicate-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    left, right = case["left"], case["right"]
                    if case["kind"] == "comparison" and case["view"] != "raw":
                        left, right = decode(left), decode(right)
                    expected = "sat" if OPERATORS[case["operator"]](left, right) else "unsat"
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    if case.get("view") == "decoded-input":
                        self.assertEqual(case["references"], [])
                        self.assertEqual(case["external_max"], 11)
                    else:
                        self.assertEqual(set(case["references"]), {0, 1})
                        self.assertEqual(case["external_max"], 0)
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, expected)


if __name__ == "__main__":
    unittest.main()
