"""Opt-in configuration reader constraints against an independent finite oracle."""

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
    index, nodes = 0, case["bootstrap"]
    for position, content in enumerate(case["contents"][:case["frontier"]], 1):
        if content is not None:
            index, nodes = position, content
    return "sat" if (case["index"], case["nodes"]) == (index, nodes) else "unsat"


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseConfigurationReaderTests(unittest.TestCase):
    def test_shared_configuration_constraints(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.ConfigurationReaderFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run",
             "Sparse/ConfigurationReaderFixtureMain.lean"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 460)
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-configuration-reader-") as directory:
            artifacts = Path(directory)
            for number, case in enumerate(cases):
                with self.subTest(case=case["name"]):
                    self.assertEqual(case["queries"], 2 * case["readers"])
                    self.assertEqual(len(case["derived_slots"]), case["readers"])
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    if case["name"].startswith("sparse-"):
                        self.assertEqual(case["points"], 1)
                        self.assertLess(len(case["script"]), 20000)
                    if case["name"] in {"unused-graph-symbol", "inactive-mask-selector"}:
                        self.assertGreater(case["derived_slots"][0], 1000000)
                    path = artifacts / f"case-{number}.smt2"
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, f"case-{number}")
                    self.assertEqual(result.status, expected(case))


if __name__ == "__main__":
    unittest.main()
