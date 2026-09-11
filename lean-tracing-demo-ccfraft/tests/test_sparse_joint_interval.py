"""Opt-in joint demand planning without a point-reference cross product."""

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
class SparseJointIntervalTests(unittest.TestCase):
    def test_point_only_references_remain_local(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.JointIntervalFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/JointIntervalFixtureMain.lean",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 8)
        self.assertEqual(
            {
                case["case"]: (case["cuts"], case["requests"], case["planned"])
                for case in cases
            },
            {
                "empty": (1, 0, 0),
                "root-version-alias": (2, 2, 2),
                "repeated-points": (2, 1, 2),
                "point-only-many-cuts": (401, 400, 800),
                "query-plus-point-only-reference": (402, 802, 1604),
                "million-root-domain": (401, 400, 400),
                "non-equality-cell-type": (2, 1, 1),
                "query-only": (2, 2, 4),
            },
        )
        self.assertEqual(
            next(case["roots"] for case in cases if case["case"] == "million-root-domain"),
            1000000,
        )


if __name__ == "__main__":
    unittest.main()
