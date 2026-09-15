# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Structural checks for the isolated encoding-study runner."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "encoding_study", Path(__file__).resolve().parents[1] / "scripts/encoding_study.py"
)
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


class StudyTests(unittest.TestCase):
    def details(self):
        clauses = [{"name": f"a{i}", "expression": "true"} for i in range(6)]
        return {
            "clauses": clauses,
            "groups": [
                {"instruction": None, "start": 0, "stop": 1},
                *[{"instruction": i, "start": i + 1, "stop": i + 2} for i in range(5)],
            ],
            "script": "(set-logic ALL)\n" + "".join(
                f'(assert (! {c["expression"]} :named {c["name"]}))\n' for c in clauses
            ) + "(check-sat)\n",
        }

    def test_chunks_keep_post_observations(self):
        details = self.details()
        chunks = study.assertion_chunks(details, [None, "receive", None, "send", None], True)
        self.assertEqual(len(chunks), 2)
        self.assertIn(":named a3", chunks[0])
        self.assertNotIn(":named a4", chunks[0])
        self.assertEqual("".join(chunks) + "(check-sat)\n", details["script"])

    def test_single_action_is_one_check(self):
        self.assertEqual(len(study.assertion_chunks(
            self.details(), [None, None, "receive", None, None], True
        )), 1)

    def test_metadata_mismatch_rejected(self):
        details = self.details()
        details["clauses"][0]["expression"] = "false"
        with self.assertRaises(ValueError):
            study.assertion_chunks(details, [None] * 5, True)

    def test_extra_query_rejected(self):
        details = self.details()
        details["script"] += "(check-sat)\n"
        with self.assertRaises(ValueError):
            study.assertion_chunks(details, [None] * 5, False)

    def test_empty_plot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plot.svg"
            study.plot([], path)
            self.assertTrue(path.read_text().endswith("</svg>"))

    def fake_solver(self, directory, behavior):
        path = Path(directory) / "solver"
        path.write_text(f"#!{sys.executable}\n" + behavior)
        path.chmod(0o700)
        return str(path)

    def test_intermediate_unknown_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            solver = self.fake_solver(directory, """import sys
count = 0
for line in sys.stdin:
    if line.startswith('(check-sat)'):
        count += 1
        print('unknown' if count == 1 else 'sat', flush=True)
    elif line.startswith('(get-info'):
        print('(:reason-unknown "incomplete")', flush=True)
    elif line.startswith('(echo'):
        print('STUDY_REASON_END', flush=True)
""")
            result = study.solve(Path(directory) / "run", ["", ""], "(check-sat)\n", solver, 10, False)
            self.assertEqual(result["status"], "sat")
            self.assertTrue(result["all_queries_completed"])
            self.assertEqual(result["queries"][0]["verdict"], "unknown")
            self.assertIn("incomplete", result["queries"][0]["reason_unknown"])

    def test_cutoff_preserves_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            solver = self.fake_solver(directory, """import sys, time
count = 0
for line in sys.stdin:
    if line.startswith('(check-sat)'):
        count += 1
        if count == 1:
            print('sat', flush=True)
        else:
            time.sleep(20)
""")
            result = study.solve(Path(directory) / "run", ["", ""], "(check-sat)\n", solver, 2, False)
            self.assertEqual(result["status"], "external_cutoff")
            self.assertFalse(result["all_queries_completed"])
            self.assertEqual(result["queries"][0]["verdict"], "sat")

    def test_core_is_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            solver = self.fake_solver(directory, """import sys
for line in sys.stdin:
    if line.startswith('(check-sat)'):
        print('unsat', flush=True)
    elif line.startswith('(get-unsat-core)'):
        print('(a0 a1)', flush=True)
""")
            result = study.solve(Path(directory) / "run", [""], "(check-sat)\n", solver, 10, False)
            self.assertEqual(result["core"], ["a0", "a1"])


if __name__ == "__main__":
    unittest.main()
