"""Opt-in scalar predicate lowering and pre-product demand deduplication."""

import json
import operator
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]
OPERATORS = {
    "eq": operator.eq,
    "ne": operator.ne,
    "le": operator.le,
    "lt": operator.lt,
}


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseIntervalPredicateTests(unittest.TestCase):
    def test_comparisons_aliases_and_deduplication(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.IntervalPredicate"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/IntervalPredicateFixtureMain.lean",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        data = json.loads(generated.stdout)
        self.assertEqual(len(data["comparisons"]), 144)
        self.assertEqual(len(data["aliases"]), 2)
        for case in data["comparisons"]:
            holds = OPERATORS[case["operator"]](case["left"], case["right"])
            case["expected"] = "sat" if holds else "unsat"
        cases = data["comparisons"] + data["aliases"]
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-predicates-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, case["expected"])
        self.assertEqual(
            {case["name"]: (case["requests"], case["planned"]) for case in data["plans"]},
            {"repeated-400": (1, 2), "mixed-duplicates": (6, 9), "empty-references": (0, 0)},
        )
        self.assertEqual(len(data["plans"]), 3)


if __name__ == "__main__":
    unittest.main()
