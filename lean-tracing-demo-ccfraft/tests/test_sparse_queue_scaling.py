"""Explicitly opt-in queue emission/solver scaling, not a full-Raft benchmark."""

import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_QUEUE_SCALING") == "1",
    "set CCF_SPARSE_QUEUE_SCALING=1 with Lean and cvc5 available",
)
class SparseQueueScalingTests(unittest.TestCase):
    def test_emission_and_solver_scaling(self) -> None:
        size = int(os.environ.get("CCF_SPARSE_QUEUE_EVENTS", "400"))
        self.assertGreaterEqual(size, 3)
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.QueueEncodingScaleMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/QueueEncodingScaleMain.lean", "--fixtures", str(size),
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = [json.loads(line) for line in generated.stdout.splitlines()]
        self.assertEqual(len(cases), 6)
        self.assertEqual(len({case["case"] for case in cases}), 6)
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-queue-scale-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["case"]):
                    self.assertEqual(case["events"], size)
                    self.assertEqual(case["tracked_keys"], 1)
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["bytes"], len(case["script"].encode("ascii")))
                    path = artifacts / (case["case"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    times = []
                    for repetition in range(3):
                        result = run_solver(
                            cvc5, path, artifacts, f"{case['case']}-{repetition}"
                        )
                        self.assertEqual(result.status, case["expected"])
                        times.append(result.wall_time_ms)
                    summary = {key: value for key, value in case.items() if key != "script"}
                    summary["solver_median_ms"] = statistics.median(times)
                    summary["emission_plus_solver_ms"] = (
                        case["encoding_ns"] / 1_000_000 + summary["solver_median_ms"]
                    )
                    print(json.dumps(summary, sort_keys=True), flush=True)


if __name__ == "__main__":
    unittest.main()
