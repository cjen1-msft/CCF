"""Opt-in shared Entry points/universals with a finite two-value oracle."""

from itertools import product
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


def concrete_exists(case: dict) -> bool:
    def accepts(left: int, right: int) -> bool:
        return {
            "eq": left == right,
            "ne": left != right,
            "raw-le": left <= right,
            "decoded-le": (2 * left if left >= 0 else -2 * left - 1)
            <= (2 * right if right >= 0 else -2 * right - 1),
        }[case["kind"]]

    for cells in product((-1, 0), repeat=8):
        left, right = cells[:4], cells[4:]
        if left[case["position"]] != -1 or right[case["position"]] != (0 if case["different"] else -1):
            continue
        if not case["enabled"] or all(
            accepts(left[index], right[index])
            for index in range(case["lower"], case["upper"])
        ):
            return True
    return False


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseTypedJointTests(unittest.TestCase):
    def test_shared_entry_points_and_universals(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.TypedJointPredicateFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run", "Sparse/TypedJointPredicateFixtureMain.lean"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 590)
        by_name = {case["name"]: case for case in cases}
        self.assertEqual(len(by_name), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-typed-joint-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    expected = case["expected"] if "expected" in case else (
                        "sat" if concrete_exists(case) else "unsat"
                    )
                    self.assertEqual(case["first"], case["zero"] + 1)
                    self.assertEqual(case["next"], case["first"] + case["roots"] + case["versions"])
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, expected)
        self.assertGreater(by_name["unused-constant"]["zero"], 8000)
        self.assertGreater(by_name["disabled-function"]["zero"], 9000)
        for verdict in ("sat", "unsat"):
            self.assertEqual(by_name[f"points-400-{verdict}"]["demands"], 806)
            self.assertEqual(by_name[f"versions-400-{verdict}"]["demands"], 1604)
        self.assertEqual(by_name["points-400-sat"]["points"], 400)
        self.assertEqual(by_name["points-400-unsat"]["points"], 401)


if __name__ == "__main__":
    unittest.main()
