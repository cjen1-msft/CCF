# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Boundary and fragment checks for the deliberately small bit-vector trial."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from study_bitvectors import formula, render


class BitvectorStudyTests(unittest.TestCase):
    def test_insufficient_width_rejected(self):
        with self.assertRaises(ValueError):
            formula(5, bitvectors=True, width=3)

    def test_uint4_has_no_other_theories(self):
        script = render(formula(5, bitvectors=True))
        for forbidden in (" Int", "Array", "forall", "exists", "NativePair", "NativeSum", "bvsle", "bvsub"):
            self.assertNotIn(forbidden, script)
        self.assertIn("(set-logic QF_BV)", script)
        self.assertIn("bvule", script)
        self.assertIn("bvadd", script)

    def test_negative_goal_is_not_a_literal_contradiction(self):
        data = formula(5, negative=True)
        self.assertEqual(data["constraints"]["observed_length"], "(= length_5 (+ length_0 6))")
        self.assertNotIn("contradictory_length", data["constraints"])
        self.assertNotIn("(not (= length_5 (+ length_0 6)))", render(data))

    def test_count_boundaries(self):
        for count in (0, 6):
            with self.assertRaises(ValueError):
                formula(count)
        self.assertEqual(formula(5)["bound"], 8)


if __name__ == "__main__":
    unittest.main()
