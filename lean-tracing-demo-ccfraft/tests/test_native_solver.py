# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Exercise the solver protocol independently of Lean compilation."""

import sys
import tempfile
import unittest
from pathlib import Path

from native_solver import find_z3, run_z3
from Shared.solver import ValidationError


class NativeSolverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-solver-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.executable = self.root / "fake-z3"
        self.query = "(get-unsat-core)\n"

    def solver(self, verdict, *, code=0, output=""):
        self.executable.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "for line in sys.stdin:\n"
            "    if line.strip() == '(check-sat)':\n"
            "        break\n"
            f"print({verdict!r}, flush=True)\n"
            "query = sys.stdin.read()\n"
            f"pathlib.Path({str(self.root / 'received-query')!r}).write_text(query)\n"
            f"print({output!r}, end='', flush=True)\n"
            "print('solver diagnostic', file=sys.stderr)\n"
            f"sys.exit({code})\n",
            encoding="ascii",
        )
        self.executable.chmod(0o755)
        return self.executable

    def run_solver(self, verdict, **options):
        return run_z3(
            self.solver(verdict, **options),
            "(check-sat)\n",
            self.query,
            self.root,
            "trace",
        )

    def test_only_unsat_requests_core(self):
        for verdict in ("sat", "unsat", "unknown"):
            with self.subTest(verdict=verdict):
                core = "(assertion_1)\n" if verdict == "unsat" else ""
                result = self.run_solver(verdict, output=core)
                self.assertEqual(result.status, verdict)
                self.assertEqual(
                    (self.root / "received-query").read_text(),
                    self.query if verdict == "unsat" else "",
                )
                self.assertEqual(result.stdout, verdict + "\n" + core)
                self.assertEqual(result.stderr, "solver diagnostic\n")
                self.assertEqual(
                    (self.root / "trace.stdout").read_text(), result.stdout
                )
                self.assertGreaterEqual(result.wall_time_ms, 0)

    def test_script_or_query_error_is_not_a_verdict(self):
        for verdict, output in (
            ('(error "bad script")', ""),
            ("unsat", '(error "bad query")\n'),
        ):
            with self.subTest(verdict=verdict), self.assertRaisesRegex(
                ValidationError, "Z3 rejected"
            ):
                self.run_solver(verdict, output=output)

    def test_nonzero_exit_preserves_diagnostics(self):
        with self.assertRaisesRegex(ValidationError, "exit code 7"):
            self.run_solver("unknown", code=7)
        self.assertEqual(
            (self.root / "trace.stderr").read_text(), "solver diagnostic\n"
        )

    def test_missing_verdict_fails(self):
        with self.assertRaisesRegex(ValidationError, "did not contain"):
            self.run_solver("")

    def test_explicit_solver_path(self):
        self.assertEqual(find_z3(self.solver("unknown")), self.executable)
        with self.assertRaisesRegex(ValidationError, "does not exist"):
            find_z3(self.root / "missing-z3")


if __name__ == "__main__":
    unittest.main()
