"""Opt-in fixed-size frame metadata and native domain constraints."""

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
class SparseStateFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.StateFrameFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
    def load(self, *arguments: str) -> list[dict]:
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run", "Sparse/StateFrameFixtureMain.lean", *arguments],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        return json.loads(generated.stdout)

    def test_canonical_metadata_stays_fixed_size(self) -> None:
        cases = self.load()
        self.assertEqual(
            [(case["base"], case["prior"], case["versions"]) for case in cases],
            [(0, 0, 0), (1000, 7, 400), (10**6, 10**6, 10**6), (10**12, 10**12, 10**12)],
        )
        for case in cases:
            with self.subTest(base=case["base"], prior=case["prior"]):
                base = case["base"]
                symbols = case["symbols"]
                self.assertEqual(len(symbols), 662)
                self.assertTrue(all(symbol["constant"] for symbol in symbols))
                self.assertEqual(Counter(symbol["sort"] for symbol in symbols), {"int": 585, "bool": 30, "nodes": 47})
                self.assertEqual(sorted(symbol["id"] for symbol in symbols), list(range(base, base + 662)))
                self.assertEqual(case["high_water"], base + 662)
                for sort, lower, upper in (("int", 0, 585), ("bool", 585, 615), ("nodes", 615, 662)):
                    self.assertEqual(
                        sorted(symbol["id"] for symbol in symbols if symbol["sort"] == sort),
                        list(range(base + lower, base + upper)),
                    )
                self.assertEqual(
                    case["roots"],
                    [{"kind": "root", "id": case["prior"] + node} for node in range(15)],
                )

    def test_allocation_guarded_native_domains(self) -> None:
        cases = self.load("--domains")
        self.assertEqual(len(cases), 634)
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-state-domains-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    if "expected" in case:
                        expected = case["expected"]
                    else:
                        self.assertEqual(bool(case["allocation"] & (1 << case["node"])), case["active"])
                        column, value = case["column"], case["value"]
                        valid = value >= 0
                        if column in (0, 5):
                            valid = valid and value < 5
                        elif column == 4:
                            valid = valid and value <= 15
                        expected = "sat" if not case["active"] or valid else "unsat"
                    self.assertEqual(case["clauses"], 15)
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    self.assertEqual(run_solver(cvc5, path, artifacts, case["name"]).status, expected)


if __name__ == "__main__":
    unittest.main()
