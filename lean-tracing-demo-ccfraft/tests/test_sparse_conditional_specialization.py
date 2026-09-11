"""Opt-in known-guard queue normalization and unchanged fallback controls."""

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
    for initial in product((0, 1, 2), repeat=case["initial_length"]):
        queue = list(initial)
        if case["mask"] & 1 and 0 not in queue:
            queue.append(0)
        if case["mask"] & 2:
            key = 0 if case["aliases"] else 1
            if not queue or queue[0] != key:
                continue
            queue.pop(0)
        if len(queue) == case["final_length"]:
            return True
    return False


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseConditionalSpecializationTests(unittest.TestCase):
    def test_known_guards_and_fallback(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build",
             "Sparse.ConditionalQueueSpecializationFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run",
             "Sparse/ConditionalQueueSpecializationFixtureMain.lean"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 395)
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-conditional-specialization-") as directory:
            artifacts = Path(directory)
            for number, case in enumerate(cases):
                with self.subTest(case=case["name"]):
                    expected = case.get("expected")
                    if expected is None:
                        expected = "sat" if concrete_exists(case) else "unsat"
                    self.assertEqual(case["known"], case.get("expected_known", True))
                    self.assertTrue(case["same_selected_backend"])
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertTrue(case["script"].isascii())
                    if case["known"]:
                        self.assertLessEqual(case["encoded_events"], case["selected_events"])
                    else:
                        self.assertIsNone(case["selected_events"])
                    if case["name"] == "million-symbolic-length":
                        self.assertLess(len(case["script"]), 10000)
                    if case["name"] == "redundant-sends":
                        self.assertEqual(case["selected_events"], 4)
                        self.assertEqual(case["encoded_events"], 2)
                    path = artifacts / f"case-{number}.smt2"
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, f"case-{number}")
                    self.assertEqual(result.status, expected)


if __name__ == "__main__":
    unittest.main()
