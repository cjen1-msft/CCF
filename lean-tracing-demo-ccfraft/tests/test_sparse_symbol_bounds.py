"""Opt-in exact allocation-bound checks for the compiler's proved summary."""

import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean available",
)
class SparseSymbolBoundsTests(unittest.TestCase):
    def test_reference_and_compiled_allocation_agree(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.SymbolBoundsFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/SymbolBoundsFixtureMain.lean",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = [json.loads(line) for line in generated.stdout.splitlines()]
        self.assertEqual(
            {case["name"]: case["bound"] for case in cases},
            {
                "empty": 1, "large-literals": 1, "symbol-zero": 1,
                "constant-bool": 5, "unary-bool-bool": 6, "unary-int-bool": 7,
                "unary-bool-int": 8, "unary-int-int": 9, "nested-arithmetic": 13,
                "inactive-branch": 101, "inactive-implication": 102,
                "same-id-different-signatures": 21, "large-id": 2**129 + 4,
                "many-symbols": 1200,
            },
        )
        self.assertEqual(len(cases), 14)


if __name__ == "__main__":
    unittest.main()
