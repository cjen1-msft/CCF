# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Summary, censoring, and polarity tests for the sequential ledger study."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from encoding_study import save
from ledger_microbench import summary


class LedgerMicroSummaryTests(unittest.TestCase):
    def row(self, count=8, negative=False, sample=0, status="sat", seconds=0.1):
        return {
            "count": count, "negative": negative, "sample": sample,
            "metadata": {"operation": "append", "variant": "native"},
            "smt_bytes": 100, "clauses": 20,
            "result": {"status": status, "solver_seconds": seconds,
                       "stats": {"rlimit-count": 100}},
        }

    def prepare(self, directory, rows, samples=3, negative_samples=1):
        save(directory / "environment.json",
             {"arguments": {"samples": samples, "negative_samples": negative_samples}})
        save(directory / "samples.json", rows)

    def test_partial_positive_group_has_no_median(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self.prepare(path, [self.row()])
            row = summary(path)[0]
            self.assertFalse(row["complete"])
            self.assertIsNone(row["median_seconds"])
            self.assertEqual(row["completed_samples"], 1)
            self.assertEqual(row["requested_samples"], 3)

    def test_cutoff_is_not_a_runtime_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self.prepare(path, [self.row(status="external_cutoff", seconds=None)], samples=1)
            row = summary(path)[0]
            self.assertIsNone(row["median_seconds"])
            self.assertEqual(row["completed_samples"], 0)
            self.assertEqual(json.loads((path / "growth.json").read_text()), [])

    def test_both_polarities_have_separate_curves(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            rows = [self.row(count=n, negative=neg, status="unsat" if neg else "sat", seconds=n / 100)
                    for n in (8, 16) for neg in (False, True)]
            self.prepare(path, rows, samples=1)
            report = summary(path)
            self.assertEqual(len(report), 4)
            ratios = json.loads((path / "growth.json").read_text())
            self.assertEqual({row["negative"] for row in ratios}, {False, True})
            self.assertTrue(all(row["time_ratio"] == 2 for row in ratios))
            ET.parse(path / "curve.svg")
            ET.parse(path / "negative-curve.svg")

    def test_negative_only_result_can_be_summarized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self.prepare(path, [self.row(negative=True, status="unsat")])
            row = summary(path)[0]
            self.assertTrue(row["complete"])
            self.assertFalse((path / "curve.svg").exists())
            self.assertTrue((path / "negative-curve.svg").exists())


if __name__ == "__main__":
    unittest.main()
