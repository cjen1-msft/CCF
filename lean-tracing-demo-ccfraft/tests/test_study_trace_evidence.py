# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Source-evidence selection controls for the C prototype."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from study_trace_evidence import plans_for
from native_origin import reduce_raw
from native_reduction import native_document


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = b"".join((ROOT / "Traces/Captured/bad_network.ndjson").read_bytes().splitlines(keepends=True)[:34])
        origin = reduce_raw(raw)
        cls.document = native_document(origin.trace, ["0"])
        cls.certificate = origin.certificate
        cls.rows = [json.loads(line) for line in raw.splitlines()]
        cls.case = {
            "selected_provenance": cls.certificate["steps"],
            "action_kinds": [i["kind"] if s["kind"] == "action" else None
                             for s, i in zip(origin.trace.steps, cls.document["instructions"], strict=True)],
        }

    def select(self, rows):
        return plans_for(self.case, self.document, rows, self.certificate)[0]

    def test_local_execution_snapshots(self):
        plans = self.select(self.rows)
        self.assertEqual([p["oldLength"] for p in plans], [0, 1, 2])
        self.assertEqual([p["oldCommit"] for p in plans], [0, 0, 2])
        self.assertEqual([p["executionLine"] for p in plans], [28, 30, 32])
        self.assertEqual([p["previousTerm"] for p in plans], [0, None, None])

    def test_inconsistent_response_does_not_select(self):
        for key, value in (("term", 99), ("last_log_idx", 99), ("success", "FAIL")):
            with self.subTest(key=key):
                rows = deepcopy(self.rows)
                rows[33]["msg"]["packet"][key] = value
                self.assertEqual(self.select(rows), [])

    def test_inconsistent_local_snapshot_does_not_select(self):
        for key, value in (("last_idx", 99), ("commit_idx", 99), ("current_view", 99)):
            with self.subTest(key=key):
                rows = deepcopy(self.rows)
                rows[29]["msg"]["state"][key] = value
                self.assertEqual(self.select(rows), [])

    def test_cross_thread_group_does_not_select(self):
        rows = deepcopy(self.rows)
        rows[33]["thread_id"] = "different"
        self.assertEqual(self.select(rows), [])

    def test_bad_source_line_rejected(self):
        case = deepcopy(self.case)
        case["selected_provenance"][134]["provenance"][0]["line"] = 0
        with self.assertRaises(ValueError):
            plans_for(case, self.document, self.rows, self.certificate)


if __name__ == "__main__":
    unittest.main()
