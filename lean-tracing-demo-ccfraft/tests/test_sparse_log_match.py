"""Opt-in exact log-match reader constraints against a concrete finite oracle."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


def expected(case: dict) -> str:
    if "expected" in case:
        return case["expected"]
    candidates = [
        index + 1
        for index, term in enumerate(case["terms"][:case["index"]])
        if term <= case["threshold"]
    ]
    return "sat" if case["best"] == max(candidates, default=0) else "unsat"


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseLogMatchTests(unittest.TestCase):
    def test_shared_reader_constraints(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.LogMatchFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run",
             "Sparse/LogMatchFixtureMain.lean"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 446)
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-log-match-") as directory:
            artifacts = Path(directory)
            for number, case in enumerate(cases):
                with self.subTest(case=case["name"]):
                    self.assertEqual(case["queries"], 2 * case["readers"])
                    self.assertTrue(case["matches_assembly"])
                    self.assertEqual(len(case["derived_slots"]), case["readers"])
                    for first in case["derived_slots"]:
                        self.assertGreaterEqual(case["outer_zero"], first + 2)
                    self.assertEqual(
                        case["witnesses"],
                        int(case["name"] in {"shared-caller-witness", "disabled-caller-witness"}),
                    )
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    if case["name"].startswith("sparse-"):
                        self.assertEqual(case["points"], 1)
                        self.assertLess(len(case["script"]), 15000)
                    if case["name"] == "unused-graph-symbol":
                        self.assertGreater(case["derived_slots"][0], 1000000)
                    path = artifacts / f"case-{number}.smt2"
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, f"case-{number}")
                    self.assertEqual(result.status, expected(case))


if __name__ == "__main__":
    unittest.main()
