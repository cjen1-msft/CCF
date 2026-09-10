# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Exercise the typed symbolic serializer against cvc5."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.test_client_request_encoding import CVC5, ROOT
from Shared.solver import run_solver


@unittest.skipUnless(CVC5 is not None and shutil.which("lake"), "needs Lean and cvc5")
class SymbolicEncodingTests(unittest.TestCase):
    def test_typed_symbolic_cases(self) -> None:
        subprocess.run(
            ["lake", "build", "MachineGenerated.SymbolicAudit"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        cases = {
            "operations-sat": "sat",
            "operations-unsat": "unsat",
            "alias-sat": "sat",
            "alias-unsat": "unsat",
            "packets-sat": "sat",
            "entry-15-sat": "sat",
            "entry-15-unsat": "unsat",
            "finite-sat": "sat",
            "finite-unsat": "unsat",
            "partial-packet-prev-zero-sat": "sat",
            "partial-packet-prev-three-sat": "sat",
            "zero-bounds-sat": "sat",
            "zero-bounds-allocated-unsat": "unsat",
        }
        with tempfile.TemporaryDirectory(
            prefix="symbolic-solver-", dir=ROOT / "Artifacts"
        ) as directory:
            output = Path(directory)
            for name, expected in cases.items():
                with self.subTest(case=name):
                    encoded = subprocess.run(
                        [
                            "lake",
                            "env",
                            "lean",
                            "--run",
                            "MachineGenerated/SymbolicTests.lean",
                            "--smt",
                            name,
                        ],
                        cwd=ROOT,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    formula = output / f"{name}.smt2"
                    formula.write_text(encoded.stdout, encoding="utf-8")
                    self.assertTrue(encoded.stdout.startswith("(set-logic ALL)"))
                    if name.startswith("entry-15-"):
                        self.assertLess(len(encoded.stdout.encode("utf-8")), 1_000_000)
                    assert CVC5 is not None
                    self.assertEqual(
                        run_solver(CVC5, formula, output, name).status, expected
                    )


if __name__ == "__main__":
    unittest.main()
