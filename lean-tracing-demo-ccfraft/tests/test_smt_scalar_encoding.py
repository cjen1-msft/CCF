# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Solver interpretation of the subtraction rendering pinned by Shared.SmtTests."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tests.test_client_request_encoding import CVC5, ROOT
from Shared.solver import run_solver


@unittest.skipUnless(CVC5 is not None, "needs cvc5")
class ScalarEncodingTests(unittest.TestCase):
    def test_truncated_subtraction_matches_natural_arithmetic(self) -> None:
        expression = "(ite (< unknown_0 unknown_1) 0 (- unknown_0 unknown_1))"
        counterexamples = [
            f"(and (= unknown_0 {left}) (= unknown_1 {right}) "
            f"(not (= {expression} {max(0, left - right)})))"
            for left in range(4)
            for right in range(4)
        ]
        formula = (
            "(set-logic QF_LIA)\n"
            "(declare-const unknown_0 Int)\n"
            "(declare-const unknown_1 Int)\n"
            "(assert (>= unknown_0 0))\n"
            "(assert (>= unknown_1 0))\n"
            "(assert (or " + " ".join(counterexamples) + "))\n(check-sat)\n"
        )
        with tempfile.TemporaryDirectory(
            prefix="smt-scalars-", dir=ROOT / "Artifacts"
        ) as directory:
            output = Path(directory)
            path = output / "subtraction.smt2"
            path.write_text(formula, encoding="utf-8")
            assert CVC5 is not None
            result = run_solver(CVC5, path, output, "subtraction")
            self.assertEqual(result.status, "unsat")


if __name__ == "__main__":
    unittest.main()
