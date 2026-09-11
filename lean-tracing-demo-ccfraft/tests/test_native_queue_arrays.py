# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Native FIFO commands against a finite oracle and symbolic initial queues."""

import itertools
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from native_arrays import SOLVER_ARGUMENTS
from native_queue_arrays import QueueArray
from Shared.solver import find_cvc5, query_payload, run_solver


def numeral(value):
    return str(value) if value >= 0 else f"(- {-value})"


def render(*queues, extra=()):
    return "\n".join(
        ["(set-logic ALL)", "(set-option :produce-models true)"]
        + [command for queue in queues for command in queue.commands]
        + list(extra)
        + ["(check-sat)", ""]
    )


def apply(queue, operation):
    kind, value = operation
    if kind == "send":
        queue.send(numeral(value))
    elif kind == "receive":
        queue.receive(numeral(value))
    elif kind == "length":
        queue.observe_length(numeral(value))
    elif kind == "point":
        queue.point("0", numeral(value))
    else:
        raise AssertionError(f"unknown test operation {operation}")


def oracle(initial, operations):
    values = list(initial)
    for kind, value in operations:
        if kind == "send":
            values.append(value)
        elif kind == "receive":
            if not values or values.pop(0) != value:
                return "unsat"
        elif kind == "length":
            if len(values) != value:
                return "unsat"
        elif kind == "point":
            if not values or values[0] != value:
                return "unsat"
        else:
            raise AssertionError(f"unknown test operation {(kind, value)}")
    return "sat"


class NativeQueueShapeTests(unittest.TestCase):
    def test_flat_updates_and_no_equality_scan(self):
        queue = QueueArray("q", "Int")
        queue.send("value")
        queue.send("value")
        queue.receive("value")
        self.assertEqual(queue.head, "q_head_3")
        self.assertEqual(queue.cells, "q_cells_2")
        script = render(queue)
        self.assertIn("(store q_cells_1 (+ q_head_0 q_length_1) value)", script)
        self.assertNotIn("(store (store", script)
        self.assertNotIn("forall", script)
        self.assertNotIn("ite", script)
        self.assertEqual(script.count("(select "), 1)


@unittest.skipUnless(
    os.environ.get("CCF_NATIVE_ARRAY_TESTS") == "1",
    "set CCF_NATIVE_ARRAY_TESTS=1 with cvc5 available",
)
class NativeQueueSolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        requested = os.environ.get("CVC5")
        cls.cvc5 = find_cvc5(Path(requested) if requested else None)
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-queue-arrays-")
        cls.artifacts = Path(
            os.environ.get("CCF_NATIVE_ARRAY_ARTIFACTS", cls.temporary.name)
        )
        cls.artifacts.mkdir(parents=True, exist_ok=True)
        cls.measurements = []

    @classmethod
    def tearDownClass(cls):
        (cls.artifacts / "queue-measurements.json").write_text(
            json.dumps(cls.measurements, indent=2) + "\n", encoding="utf-8"
        )
        cls.temporary.cleanup()

    def solve(self, name, script, expected):
        path = self.artifacts / f"queue-{name}.smt2"
        path.write_text(script, encoding="ascii")
        run = run_solver(
            self.cvc5,
            path,
            self.artifacts,
            f"queue-{name}",
            extra_arguments=SOLVER_ARGUMENTS,
        )
        self.assertEqual(run.status, expected, name)
        self.measurements.append(
            {
                "name": name,
                "bytes": len(script),
                "status": run.status,
                "solver_ms": run.wall_time_ms,
            }
        )
        return run

    def test_finite_oracle(self):
        alphabet = [
            ("send", 1),
            ("send", 2),
            ("receive", 1),
            ("receive", 2),
            ("length", 0),
            ("length", 2),
            ("point", 1),
        ]
        number = 0
        for initial in ([], [1], [2, 1], [1, 1]):
            for operations in itertools.product(alphabet, repeat=2):
                queue = QueueArray("q", "Int")
                queue.observe_length(str(len(initial)))
                for index, value in enumerate(initial):
                    queue.point(str(index), numeral(value))
                for operation in operations:
                    apply(queue, operation)
                self.solve(
                    f"finite-{number}", render(queue), oracle(initial, operations)
                )
                number += 1
        self.assertEqual(number, 196)

    def test_symbolic_aliases_keep_duplicates(self):
        queue = QueueArray("q", "Int")
        queue.commands[0:0] = ["(declare-const x Int)", "(declare-const y Int)"]
        queue.observe_length("0")
        queue.send("x")
        queue.send("y")
        queue.observe_length("2")
        queue.receive("x")
        queue.receive("x")
        queue.observe_length("0")
        self.solve("alias", render(queue, extra=["(assert (= x y))"]), "sat")
        self.solve(
            "distinct", render(queue, extra=["(assert (distinct x y))"]), "unsat"
        )

    def test_late_observations_materialize_initial_values(self):
        queue = QueueArray("q", "Int")
        queue.observe_length("2")
        queue.receive("7")
        queue.point("0", "13")
        queue.send("99")
        # Query the original array, after observations at two later boundaries.
        script = render(queue) + (
            "(get-value ((select q_cells_0 q_head_0) "
            "(select q_cells_0 (+ q_head_0 1))))\n"
        )
        result = self.solve("initial-readback", script, "sat")
        payload = query_payload(result, "get-value")
        self.assertIn(" 7)", payload)
        self.assertIn(" 13)", payload)
        self.solve(
            "initial-conflict",
            render(queue, extra=["(assert (= (select q_cells_0 (+ q_head_0 1)) 14))"]),
            "unsat",
        )

    def test_prefix_and_tail_are_irrelevant(self):
        queue = QueueArray("q", "Int")
        queue.observe_length("1")
        queue.point("0", "7")
        outside = [
            "(assert (= q_head_0 1000000))",
            "(assert (= (select q_cells_0 999999) 19))",
            "(assert (= (select q_cells_0 1000001) 23))",
        ]
        self.solve("irrelevant-cells", render(queue, extra=outside), "sat")
        queue.receive("7")
        queue.send("(- 4)")
        queue.point("0", "(- 4)")
        self.solve("overwrite-tail", render(queue, extra=outside), "sat")
        queue.point("1", "23")
        self.solve("out-of-bounds", render(queue, extra=outside), "unsat")

    def test_independent_source_queues(self):
        left, right = QueueArray("d_s1", "Int"), QueueArray("d_s2", "Int")
        right.observe_length("1")
        right.point("0", "42")
        left.send("9")
        left.receive("9")
        right.point("0", "42")
        self.solve("source-frame", render(left, right), "sat")
        right.point("0", "43")
        self.solve("source-frame-conflict", render(left, right), "unsat")

    def test_symbolic_and_event_scale(self):
        queue = QueueArray("q", "Int")
        queue.observe_length(str(10**12))
        queue.send("17")
        queue.point(str(10**12), "17")
        script = render(queue)
        self.assertLess(len(script), 1500)
        self.solve("trillion", script, "sat")
        queue.point(str(10**12), "18")
        self.solve("trillion-conflict", render(queue), "unsat")
        started = time.perf_counter_ns()
        queue = QueueArray("q", "Int")
        queue.observe_length("0")
        for _ in range(200):
            queue.send("7")
        for _ in range(200):
            queue.receive("7")
        queue.observe_length("0")
        script = render(queue)
        encoder_ms = (time.perf_counter_ns() - started) / 1_000_000
        self.solve("400-operations", script, "sat")
        self.measurements[-1]["encoder_ms"] = encoder_ms


if __name__ == "__main__":
    unittest.main()
