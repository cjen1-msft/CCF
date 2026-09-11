"""Opt-in observation-only Model encoding and explicit unsupported-input errors."""

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
class SparseFrameObservationTests(unittest.TestCase):
    def test_observation_only_model_encoding(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.FrameObservationFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run",
             "Sparse/FrameObservationFixtureMain.lean"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 148)
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-frame-observations-") as directory:
            artifacts = Path(directory)
            for number, case in enumerate(cases):
                with self.subTest(case=case["name"]):
                    if "rejection" in case:
                        self.assertEqual(case["rejection"], case["expected"])
                        self.assertNotIn("script", case)
                        continue
                    self.assertEqual(
                        case["clauses"], case["source_count"] + 15 + case["instructions"]
                    )
                    self.assertTrue(case["checked_matches"])
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    self.assertTrue(case["script"].isascii())
                    self.assertLess(len(case["script"]), 100000)
                    path = artifacts / f"case-{number}.smt2"
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, f"case-{number}")
                    self.assertEqual(result.status, case["expected"])


if __name__ == "__main__":
    unittest.main()
