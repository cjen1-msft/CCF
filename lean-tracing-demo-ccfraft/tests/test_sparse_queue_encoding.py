"""Opt-in count/scalar encoding checks, not full FIFO validation."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


def load_fixtures(*args: str) -> list[dict]:
    generated = subprocess.run(
        [
            "nice", "-n", "10", "lake", "env", "lean", "--run",
            "Sparse/QueueCountFixtureMain.lean", *args,
        ],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return json.loads(generated.stdout)


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseQueueEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        requested = os.environ.get("CVC5")
        cls.cvc5 = find_cvc5(Path(requested) if requested else None)
        cls.temporary = tempfile.TemporaryDirectory(prefix="sparse-counts-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.artifacts = Path(cls.temporary.name)
        subprocess.run(
            [
                "nice", "-n", "10", "lake", "build", "Sparse.QueueEncoding",
                "Sparse.QueueScalarEncoding", "Sparse.SmtScriptText",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cls.fixtures = load_fixtures()
        cls.scalar_fixtures = load_fixtures("--scalar")

    def assert_scripts(self, fixtures: list[dict], scope: str) -> None:
        self.assertEqual(len({case["name"] for case in fixtures}), len(fixtures))
        for case in fixtures:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["scope"], scope)
                self.assertTrue(case["script"].isascii())
                self.assertEqual(case["parsed_script"], case["script"])
                self.assertEqual(case["parsed_value"], case["command_value"])
                name = scope + "-" + case["name"]
                path = self.artifacts / (name + ".smt2")
                path.write_text(case["script"], encoding="ascii")
                result = run_solver(self.cvc5, path, self.artifacts, name)
                self.assertEqual(result.status, case["expected"])

    def test_count_read_scripts(self) -> None:
        self.assertEqual(len(self.fixtures), 13)
        self.assert_scripts(self.fixtures, "count-read")

    def test_scalar_scripts(self) -> None:
        self.assertEqual(len(self.scalar_fixtures), 14)
        self.assert_scripts(self.scalar_fixtures, "count-and-scalar")
        for case in self.scalar_fixtures:
            with self.subTest(case=case["name"]):
                self.assertLessEqual(case["count_range_end"], case["scalar_base"])


if __name__ == "__main__":
    unittest.main()
