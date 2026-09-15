# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Representation-independent operation-stream and encoding invariants."""

from pathlib import Path
import json
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from ledger_suite import closure, encode, oracle, plan


class LedgerSuiteTests(unittest.TestCase):
    def test_expected_polarities(self):
        for workload in ("append", "rollback", "equality", "mixed"):
            for negative in (False, True):
                with self.subTest(workload=workload, negative=negative):
                    self.assertEqual(oracle(plan(workload, 2, 4, negative=negative))["all_match"], not negative)

    def test_mixed_fixed_cycle_counts(self):
        stream = plan("mixed", 3, 4)
        self.assertEqual(stream["operation_counts"], {"append": 9, "rollback": 9, "equality": 9})
        self.assertEqual(stream["capacity"], 5)
        reference = oracle(stream)
        self.assertEqual(list(reference["booleans"].values()), [False, True, True] * 3)
        self.assertEqual(len(reference["states"]["state_19"]), 4)

    def test_growing_mixed_counts(self):
        stream = plan("mixed", 3, 4, growing=True)
        self.assertEqual(stream["operation_counts"], {"append": 9, "rollback": 3, "equality": 6})
        self.assertEqual(stream["capacity"], 7)
        self.assertTrue(oracle(stream)["all_match"])

    def test_mixed_negative_phases(self):
        for growing in (False, True):
            for target in ("final", "unequal", "regrowth", "retained"):
                stream = plan("mixed", 2, 4, growing=growing, negative=True, mixed_negative=target)
                self.assertFalse(oracle(stream)["all_match"])

    def test_negative_witness_seed_rejected(self):
        with self.assertRaises(ValueError):
            plan("mixed", 1, 4, seed=-1)

    def test_independent_equality_states(self):
        stream = plan("equality", 4, 3, "symbolic")
        self.assertEqual(len(stream["initial_states"]), 8)
        self.assertEqual(list(oracle(stream)["booleans"].values()), [True, False, True, False])
        self.assertEqual(stream["operation_counts"], {"equality": 4})

    def test_single_comparison_length_axis(self):
        for kind, expected in (("equal", True), ("unequal", False)):
            stream = plan("equality", 8, 16, axis="length", equality_kind=kind)
            self.assertEqual(len(stream["initial_states"]), 2)
            self.assertEqual(len(stream["events"]), 1)
            self.assertEqual(stream["capacity"], 8)
            self.assertEqual(list(oracle(stream)["booleans"].values()), [expected])

    def test_equality_array_scripts_are_identical(self):
        for regime in ("concrete", "symbolic"):
            for negative in (False, True):
                for kind in ("equal", "unequal"):
                    stream = plan("equality", 4, 16, regime, axis="length",
                                  negative=negative, equality_kind=kind)
                    self.assertEqual(encode(stream, "R", "")["script"], encode(stream, "A", "")["script"])

    def test_batch_append_count(self):
        stream = plan("append", 2, 1, batch_size=4)
        self.assertEqual(stream["capacity"], 9)
        self.assertEqual(len(oracle(stream)["states"]["state_2"]), 9)
        self.assertEqual(stream["operation_counts"], {"append": 2})

    def test_source_names_do_not_shadow_values(self):
        stream = plan("append", 2, 1)
        for rep in ("R", "C", "A"):
            result = encode(stream, rep, "")
            symbols = set(re.findall(r"\(declare-const (\w+) ", result["script"]))
            self.assertFalse(symbols & result["groups"].keys())

    def test_stream_json_roundtrip_preserves_encoding(self):
        for workload in ("append", "rollback", "equality", "mixed"):
            stream = plan(workload, 2, 16)
            restored = json.loads(json.dumps(stream, sort_keys=True))
            for rep in ("R", "C", "A"):
                self.assertEqual(encode(stream, rep, "")["script"], encode(restored, rep, "")["script"])

    def test_cells_are_fresh_and_have_no_array_declarations(self):
        result = encode(plan("append", 2, 1), "C", "")
        self.assertNotIn(" Ledger)", result["script"])
        all_cells = [cell for cells in result["cell_symbols"].values() for cell in cells]
        self.assertEqual(len(all_cells), len(set(all_cells)))
        self.assertEqual(result["live_cells_across_states"], 6)

    def test_every_live_cell_has_a_type_predicate(self):
        for workload in ("append", "rollback", "mixed"):
            result = encode(plan(workload, 2, 4), "C", "")
            all_cells = {cell for cells in result["cell_symbols"].values() for cell in cells}
            typed = set(re.findall(r"\(entry_valid (cell_[A-Za-z0-9_]+)\)", result["script"]))
            self.assertEqual(all_cells, typed, workload)

    def test_core_closure_retains_ancestors(self):
        result = encode(plan("append", 3, 1, negative=True), "A", "")
        selected = closure(result, ["observe_2"])
        self.assertIn("initial_state_0", selected)
        for index in range(3):
            self.assertIn(f"step_{index}", selected)

    def test_rollback_zero(self):
        stream = plan("rollback", 4, 4)
        self.assertEqual(oracle(stream)["states"]["state_4"], [])
        self.assertTrue(oracle(stream)["all_match"])

    def test_rollback_arrays_are_identical(self):
        for regime in ("concrete", "symbolic"):
            for negative in (False, True):
                for count in (1, 4):
                    stream = plan("rollback", count, 4, regime, negative=negative)
                    self.assertEqual(encode(stream, "R", "")["script"], encode(stream, "A", "")["script"])
            for target in (0, 1, 4, 7):
                stream = plan("rollback", 1, 4, regime)
                stream["events"][0]["target"] = target
                stream["observations"] = [{"kind": "length", "state": "state_1", "expected": min(4, target)}]
                self.assertEqual(encode(stream, "R", "")["script"], encode(stream, "A", "")["script"])

    def test_retained_control_needs_live_prefix(self):
        with self.assertRaises(ValueError):
            plan("append", 1, 0, negative=True, negative_position="retained")


if __name__ == "__main__":
    unittest.main()
