# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Count bounds construction, not elapsed time, across unchanged trace states."""

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("lake"), "needs Lean")
class SymbolicTraceScalingTests(unittest.TestCase):
    def test_bounds_once_per_state(self) -> None:
        for observations in (0, 1, 64, 1000):
            with self.subTest(observations_per_block=observations):
                result = subprocess.run(
                    [
                        "nice",
                        "-n",
                        "10",
                        "lake",
                        "env",
                        "lean",
                        "--run",
                        "Shared/SymbolicTraceScalingMain.lean",
                        str(observations),
                    ],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                lines = (result.stdout + result.stderr).splitlines()
                self.assertEqual(lines.count("TRACE_BOUNDS_CALL"), 3)
                self.assertCountEqual(
                    [line for line in lines if line.startswith("TRACE_NAME_CALL:")],
                    [
                        f"TRACE_NAME_CALL:{observations + 1}",
                        f"TRACE_NAME_CALL:{2 * observations + 2}",
                    ],
                )
                self.assertIn(
                    f"SCALING_OK:{observations}:{3 * observations + 3}", lines
                )


if __name__ == "__main__":
    unittest.main()
