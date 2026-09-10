# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Keep raw and checked runners on the shared solver implementation."""

from pathlib import Path
import unittest
from unittest.mock import patch

from Shared import solver
import validate
import validate_checked


class SharedSolverTests(unittest.TestCase):
    def test_runners_use_the_shared_solver_helpers(self) -> None:
        for name in ("find_cvc5", "solver_status", "run_solver", "query_payload"):
            with self.subTest(helper=name):
                self.assertIs(getattr(validate, f"_{name}"), getattr(solver, name))
                self.assertIs(getattr(validate_checked, name), getattr(solver, name))

    def test_raw_runner_discovers_cvc5_on_path(self) -> None:
        with patch("Shared.solver.shutil.which", return_value="/tools/cvc5"):
            self.assertEqual(validate._find_cvc5(None), Path("/tools/cvc5"))

    def test_raw_runner_reports_a_missing_solver(self) -> None:
        with patch("Shared.solver.shutil.which", return_value=None):
            with self.assertRaisesRegex(solver.ValidationError, "not found on PATH"):
                validate._find_cvc5(None)


if __name__ == "__main__":
    unittest.main()
