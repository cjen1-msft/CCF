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
        keys = os.environ.get("CCF_SPARSE_QUEUE_KEYS")
        arguments = ["--fixtures", str(size)]
        if keys is not None:
            keys = int(keys)
            self.assertGreater(keys, 0)
            self.assertLess(keys, size)
            arguments = ["--mixed-fixtures", str(size), str(keys)]
        summarized = os.environ.get("CCF_SPARSE_QUEUE_SUMMARIES") == "1"
        if summarized:
            arguments.insert(0, "--summarize")
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.QueueEncodingScaleMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/QueueEncodingScaleMain.lean", *arguments,
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
                    if keys is None:
                        self.assertEqual(case["tracked_keys"], 1)
                        cycle = case["case"].startswith("cycle-")
                        unknown = case["case"].startswith("unknown-million-")
                        self.assertEqual(
                            case["encoded_events"],
                            (3 if unknown else 2) if summarized and not cycle else size,
                        )
                        self.assertEqual(
                            case["query_pairs"],
                            1 if summarized and not cycle else size - (2 if unknown else 1),
                        )
                    else:
                        cycle = case["case"].startswith("mixed-symbolic-cycle-")
                        last_write = {
                            (index // 2 if cycle else index) % keys: index
                            for index in range(size - 1)
                        }
                        if summarized and not cycle:
                            last_write = {index: index for index in range(keys)}
                        self.assertEqual(
                            case["encoded_events"],
                            keys + 1 if summarized and not cycle else size,
                        )
                        self.assertEqual(case["tracked_keys"], len(last_write))
                        self.assertEqual(
                            case["query_pairs"], sum(index + 1 for index in last_write.values())
                        )
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
