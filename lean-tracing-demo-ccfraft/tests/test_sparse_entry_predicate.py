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
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.EntryPredicateFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
    def load(self, *arguments: str) -> list[dict]:
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run", "Sparse/EntryPredicateFixtureMain.lean", *arguments],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        return json.loads(generated.stdout)

    def test_entry_comparisons(self) -> None:
        cases = self.load()
        self.assertEqual(len(cases), 620)
        self.assert_cases(cases)

    def assert_cases(self, cases: list[dict], native: bool = False) -> None:
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-entry-predicate-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    if native:
                        expected = "sat" if self.native_value(case) == case["answer"] else "unsat"
                    else:
                        left, right = case["left"], case["right"]
                        if case["kind"] == "comparison" and case["view"] != "raw":
                            left, right = decode(left), decode(right)
                        expected = "sat" if OPERATORS[case["operator"]](left, right) else "unsat"
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    if native:
                        self.assertTrue(case["references"])
                        if case["operation"] == "filter":
                            self.assertEqual(case["external_max"], 1014)
                    elif case.get("view") == "decoded-input":
                        self.assertEqual(case["references"], [])
                        self.assertEqual(case["external_max"], 11)
                    else:
                        self.assertEqual(set(case["references"]), {0, 1})
                        self.assertEqual(case["external_max"], 0)
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, expected)

    def native_value(self, case: dict):
        operation = case["operation"]
        if operation == "selector":
            return case["value"]
        left, right = case["left"], case["right"]
        if operation in ("and", "filter"):
            return left & right
        if operation == "or":
            return left | right
        if operation == "difference":
            return left & ~right
        if operation == "not":
            return left ^ 32767
        if operation == "cardinality":
            return left.bit_count()
        if operation == "member":
            return bool(left & (1 << right))
        if operation == "tag":
            return left == right
        if operation == "majority":
            return 2 * (left & right).bit_count() > right.bit_count()
        if operation == "guarded":
            return case["tag"] != 2 or 2 * (left & right).bit_count() > right.bit_count()
        self.fail(f"Unknown native predicate operation: {operation}")

    def test_cell_local_native_operations(self) -> None:
        cases = self.load("--native")
        self.assertEqual(len(cases), 550)
        self.assert_cases(cases, native=True)


if __name__ == "__main__":
    unittest.main()
