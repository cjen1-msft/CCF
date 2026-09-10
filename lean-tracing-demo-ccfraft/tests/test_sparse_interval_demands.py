"""Opt-in runtime checks for memoized interval-demand planning."""

import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean available",
)
class SparseIntervalDemandTests(unittest.TestCase):
    def test_shared_ancestors_and_sparse_domains(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.IntervalDemandPlan"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        result = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/IntervalDemandFixtureMain.lean",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), 15)
        cases = {row["case"]: row for row in rows}
        self.assertEqual(len(cases), len(rows))
        for depth in (4, 6, 8, 10, 12, 16, 64, 128, 399):
            self.assertEqual(
                cases[f"repeated-child-{depth}"]["distinct_demands"], depth + 2
            )
            self.assertEqual(cases[f"repeated-child-{depth}"]["versions"], depth + 1)
        expected = {
            "duplicate-and-aliased-positions": 28,
            "empty-interval-both-children": 5,
            "reversed-interval-both-children": 5,
            "constant-no-roots": 1,
            "empty-requests": 0,
            "unreferenced-root-domain": 2,
        }
        for name, count in expected.items():
            self.assertEqual(cases[name]["distinct_demands"], count)


if __name__ == "__main__":
    unittest.main()
