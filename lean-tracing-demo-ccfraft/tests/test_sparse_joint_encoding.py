"""Opt-in joint point/universal constraints on one shared root family."""

from itertools import product
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


def concrete_case(name: str) -> bool:
    _, aliases, _, lower, upper, point, value = name.split("-")
    lower, upper, point, value = map(int, (lower, upper, point, value))
    same = aliases == "true"
    return all(
        any(
            (not (lower <= position < upper) or values[0] == 0)
            and (position != point or values[0 if same else 1] == value)
            for values in product((0, 1), repeat=1 if same else 2)
        )
        for position in range(max(upper, point + 1))
    )


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseJointEncodingTests(unittest.TestCase):
    def test_points_and_ranges_share_one_family(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.JointEncodingFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/JointEncodingFixtureMain.lean",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 311)
        by_name = {case["name"]: case for case in cases}
        self.assertEqual(len(by_name), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-joint-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    if case["name"].startswith("joint-"):
                        self.assertEqual(
                            case["expected"], "sat" if concrete_case(case["name"]) else "unsat"
                        )
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, case["expected"])
        self.assertGreater(by_name["expected-symbol-reservation"]["zero_id"], 1000)
        self.assertGreater(by_name["position-symbol-reservation"]["zero_id"], 1999)
        self.assertEqual(by_name["trillion-point-million-roots"]["demands"], 1)
        self.assertEqual(by_name["repeated-400-points"]["demands"], 8)
        self.assertEqual(by_name["point-only-400-positions"]["demands"], 800)


if __name__ == "__main__":
    unittest.main()
