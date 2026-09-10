"""Opt-in symbolic interval point-read checks with actual generated SMT text."""

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
class SparseIntervalEncodingTests(unittest.TestCase):
    def test_point_reads_and_symbolic_bounds(self) -> None:
        subprocess.run(
            [
                "nice", "-n", "10", "lake", "build",
                "Sparse.IntervalEncoding", "Sparse.SmtScriptText",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/IntervalEncodingFixtureMain.lean",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 92)
        by_name = {case["name"]: case for case in cases}
        self.assertEqual(len(by_name), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-intervals-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    if case["name"].startswith("boundary-"):
                        lower, upper, position, value = map(
                            int, case["name"].split("-")[1:]
                        )
                        actual = 7 if lower <= position < upper else 9
                        self.assertEqual(
                            case["expected"], "sat" if actual == value else "unsat"
                        )
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, case["expected"])
        for name in ("shared-400-sat", "shared-400-unsat"):
            self.assertEqual(by_name[name]["versions"], 400)
            self.assertEqual(by_name[name]["demands"], 401)
        self.assertEqual(by_name["million-root-domain"]["roots"], 1000000)
        self.assertEqual(by_name["million-root-domain"]["demands"], 2)
        self.assertEqual(by_name["trillion-position"]["demands"], 2)


if __name__ == "__main__":
    unittest.main()
