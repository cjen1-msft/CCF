"""Opt-in universal interval constraints with one shared array-family witness."""

from itertools import product
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


def concrete_bounds_case(name: str) -> bool:
    _, aliases, lower_a, upper_a, lower_b, upper_b = name.split("-")
    lower_a, upper_a, lower_b, upper_b = map(
        int, (lower_a, upper_a, lower_b, upper_b)
    )
    same = aliases == "true"
    # Only equality with zero is observed, so one nonzero representative suffices.
    return all(
        any(
            (not (lower_a <= position < upper_a) or values[0] == 0)
            and (not (lower_b <= position < upper_b) or values[0 if same else 1] != 0)
            for values in product((0, 1), repeat=1 if same else 2)
        )
        for position in range(max(upper_a, upper_b))
    )


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseIntervalQueryTests(unittest.TestCase):
    def test_universal_queries_share_one_family(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.IntervalQueryEncoding"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/IntervalQueryFixtureMain.lean",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 187)
        by_name = {case["name"]: case for case in cases}
        self.assertEqual(len(by_name), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-queries-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    if case["name"].startswith("bounds-"):
                        self.assertEqual(
                            case["expected"],
                            "sat" if concrete_bounds_case(case["name"]) else "unsat",
                        )
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, case["expected"])
        self.assertGreater(by_name["metadata-only-operand"]["zero_id"], 100)
        self.assertGreater(by_name["preserved-input-function"]["zero_id"], 500)
        for name in ("trillion-interval", "million-root-domain", "repeated-400-queries"):
            self.assertEqual(by_name[name]["demands"], 6)
        self.assertEqual(by_name["million-root-domain"]["roots"], 1000000)
        for name in ("shared-400-versions-sat", "shared-400-versions-unsat"):
            self.assertEqual(by_name[name]["versions"], 400)
            self.assertEqual(by_name[name]["demands"], 1203)


if __name__ == "__main__":
    unittest.main()
