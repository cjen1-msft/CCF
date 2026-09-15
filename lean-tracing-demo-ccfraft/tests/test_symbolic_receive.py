# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run native symbolic receive correspondence and SMT regressions."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import run_solver
from tests.test_client_request_encoding import CVC5, ROOT, SOLVER_TESTS


@SOLVER_TESTS
class SymbolicReceiveTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(
            prefix="symbolic-receive-", dir=ROOT / "Artifacts"
        )
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)
        self.native_runs = 0

    @classmethod
    def setUpClass(cls) -> None:
        build = subprocess.run(
            ["nice", "-n", "10", "lake", "build", "symbolic_receive_tests"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if build.returncode:
            raise AssertionError(build.stdout + build.stderr)

    def run_native(self, *args: str) -> None:
        log = self.workspace / f"native-{self.native_runs}.log"
        self.native_runs += 1
        print(f"receive {' '.join(args)}: {log}", flush=True)
        with log.open("w", encoding="utf-8") as stream:
            result = subprocess.run(
                [
                    "nice",
                    "-n",
                    "10",
                    str(ROOT / ".lake/build/bin/symbolic_receive_tests"),
                    *args,
                ],
                cwd=ROOT,
                stdout=stream,
                stderr=subprocess.STDOUT,
                text=True,
            )
        self.assertEqual(result.returncode, 0, log.read_text(encoding="utf-8"))

    def test_fresh_entry_and_all_receive_fixtures(self) -> None:
        self.run_native("--fresh")
        self.run_native("--fixtures")

    def test_fresh_and_zero_bound_formulas(self) -> None:
        with tempfile.TemporaryDirectory(prefix="symbolic-receive-") as temporary:
            output = Path(temporary)
            fresh = output / "fresh.smt2"
            self.run_native("--smt", str(fresh))
            self.run_native("--smt-zero", str(output / "zero"))
            assert CVC5 is not None
            for name, expected in (
                ("fresh", "sat"),
                ("zero-sat", "sat"),
                ("zero-unsat", "unsat"),
            ):
                with self.subTest(case=name):
                    self.assertEqual(
                        run_solver(CVC5, output / f"{name}.smt2", output, name).status,
                        expected,
                    )


if __name__ == "__main__":
    unittest.main()
