# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Focused semantic checks for the opt-in finite-cell compiler."""

import json
from pathlib import Path
import subprocess
import unittest

try:
    import z3
except ModuleNotFoundError:
    z3 = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(z3 is None, "optional canonical-cell backend requires z3-solver")
class CellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from native_cells import CellLowering
        cls.lowering = CellLowering(2, 4, 7)
        cls.entry = cls.lowering.normalization_variable.sort()

    def unsat(self, *conditions):
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(*conditions)
        self.assertEqual(solver.check(), z3.unsat)

    def test_native_normalizer_recognition_is_exact(self):
        c = self.lowering
        self.assertIsNotNone(c.normalized_source(c.normalization_pattern))
        altered = z3.substitute(c.normalization_pattern, (z3.IntVal(0), z3.IntVal(1)))
        self.assertIsNone(c.normalized_source(altered))

    def test_cell_store_select_at_every_live_index(self):
        c = self.lowering
        array = z3.Array("cells_test_array", z3.IntSort(), self.entry)
        value = z3.Const("cells_test_value", self.entry)
        old = c.visit(array)
        for position in range(4):
            updated = c.visit(z3.Store(array, position, value))
            for index in range(4):
                read = c.select(array.sort(), updated, z3.IntVal(index))
                expected = c.visit(value) if index == position else c.select(array.sort(), old, z3.IntVal(index))
                self.unsat(read != expected)

    def test_outside_cell_range_is_default(self):
        c = self.lowering
        array = z3.Array("cells_outside", z3.IntSort(), self.entry)
        for index in (-1, 4, 100):
            actual = c.visit(z3.Select(array, index))
            self.unsat(actual != c.default(self.entry))

    def test_canonical_cells_reject_negative_term(self):
        c = self.lowering
        array = z3.Array("cells_invalid", z3.IntSort(), self.entry)
        value = c.visit(z3.Select(array, 0))
        term = value.sort().accessor(0, 0)(value)
        self.unsat(*c.type_constraints.values(), term < 0)

    def test_guarded_grounding_keeps_large_range_fallback(self):
        c = self.lowering
        i = z3.Int("range_index")
        array = z3.Array("range_values", z3.IntSort(), z3.IntSort())
        length = z3.Int("range_length")
        for inclusive in (False, True):
            upper = i <= length if inclusive else z3.Not(length <= i)
            quantified = z3.ForAll([i], z3.Or(z3.Not(z3.And(0 <= i, upper)), z3.Select(array, i) == i))
            result = c.visit(quantified)
            for n in (-1, 0, 3, 9):
                self.unsat(length == n, z3.Xor(result, quantified))

    def test_dag_render_keeps_nested_bound_variables(self):
        from native_cells import render_dag
        x, y, outer = z3.Ints("dag_x dag_y dag_outer")
        formula = z3.ForAll([x], z3.And(x + outer >= x, z3.ForAll([y], x + y + outer >= x + y)))
        script = render_dag([("original", formula)])
        parsed = z3.parse_smt2_string(script)
        self.unsat(z3.Xor(parsed[0], formula))

    def test_dag_render_declares_constructor_only_sorts(self):
        from native_cells import render_dag
        array = z3.Array("dag_cells", z3.IntSort(), self.entry)
        expr = self.lowering.visit(z3.Select(z3.Store(array, 1, z3.Select(array, 0)), 1))
        formula = expr == self.lowering.visit(z3.Select(array, 0))
        parsed = z3.parse_smt2_string(render_dag([("identity", formula)]))
        self.unsat(z3.Not(parsed[0]))

    def test_known_initial_bounds_and_head_observation(self):
        from native_cells import trace_capacities
        doc = {
            "nodes": ["0", "1"], "bootstrap": ["0"], "instructions": [
                {"kind": "logLength", "node": "0", "value": 2},
                {"kind": "queuePattern", "source": "0", "destination": "1", "index": 0,
                 "value": {"kind": "appendEntriesRequest", "entriesLength": 3}},
                {"kind": "queuePattern", "source": "0", "destination": "1", "index": 1,
                 "value": {"kind": "appendEntriesRequest", "entriesLength": 0}},
                {"kind": "receiveAppendEntries", "source": "0", "destination": "1"},
            ],
        }
        bounds = trace_capacities(doc)
        self.assertEqual(bounds["ledger"], 3)
        self.assertEqual(bounds["queue"], 1)

    def test_initial_bounds_reject_missing_or_nonempty_queues(self):
        from native_cells import trace_capacities
        from Shared.solver import ValidationError
        document = {"nodes": ["0"], "bootstrap": ["0"], "instructions": [
            {"kind": "logLength", "node": "0", "value": 2},
        ]}
        with self.assertRaises(ValidationError):
            trace_capacities(document, {"allocated": ["0"], "ledger_lengths": {}, "queues": []})
        with self.assertRaises(ValidationError):
            trace_capacities(document, {"allocated": ["0"], "ledger_lengths": {"0": 2},
                "queues": [{"source": "0", "destination": "0", "length": 1}]})


if __name__ == "__main__":
    unittest.main()
