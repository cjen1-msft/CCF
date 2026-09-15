# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run audited native transition regressions, isolating crashes by selector."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from tests.test_client_request_encoding import CVC5, ROOT
from Shared.solver import run_solver

NATIVE = ROOT / ".lake/build/bin/symbolic_transition_tests"
COMMIT_SELECTORS = [
    ("--commit",),
    ("--commit-tail",),
]
FAMILY_SELECTORS = [
    ("--configurations",),
    ("--retirement",),
    ("--signature",),
    ("--signature-tail",),
    ("--signature-symbolic-actor",),
    ("--retired-write",),
    ("--retired-write-tail",),
    ("--client",),
    ("--client-tail",),
    ("--reconfiguration",),
    ("--reconfiguration-tail",),
    ("--elections",),
    ("--election-tail",),
    ("--leadership",),
    ("--leadership-tail",),
    ("--append-send",),
    ("--append-send-tail",),
    ("--proposal",),
    ("--proposal-tail",),
]
COMMIT_SMT_CASES = {
    "commit-sat": "sat",
    "commit-unsat": "unsat",
    "commit-no-majority-unsat": "unsat",
    "commit-terminal-sat": "sat",
    "commit-overflow-unsat": "unsat",
}


@unittest.skipUnless(shutil.which("lake"), "needs Lean")
class SymbolicTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        built = subprocess.run(
            [
                "nice",
                "-n",
                "10",
                "lake",
                "build",
                "MachineGenerated.SymbolicTransitionAudit",
                "symbolic_transition_tests",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if built.returncode != 0:
            raise RuntimeError(
                f"transition proof/native build failed ({built.returncode})\n"
                f"{built.stdout}\n{built.stderr}"
            )
        directory = tempfile.TemporaryDirectory(
            prefix="symbolic-transitions-", dir=ROOT / "Artifacts"
        )
        cls.addClassCleanup(directory.cleanup)
        cls.workspace = Path(directory.name)
        cls.native_runs = 0
        _, diagnostic = cls.run_native("--invalid-selector", expected_exit=1)
        if "usage: SymbolicTransitionTests.lean" not in diagnostic.read_text(
            encoding="utf-8"
        ):
            raise AssertionError(f"native selector dispatch failed; see {diagnostic}")

    @classmethod
    def run_native(cls, *arguments: str, expected_exit: int = 0) -> tuple[Path, Path]:
        stem = f"native-{cls.native_runs}"
        cls.native_runs += 1
        suffix = ".smt2" if arguments[0] == "--smt" else ".stdout"
        stdout = cls.workspace / f"{stem}{suffix}"
        stderr = cls.workspace / f"{stem}.stderr"
        print(
            f"transition {' '.join(arguments)}: stdout={stdout} stderr={stderr}",
            flush=True,
        )
        started = time.monotonic()
        with (
            stdout.open("w", encoding="utf-8") as output,
            stderr.open("w", encoding="utf-8") as diagnostics,
        ):
            completed = subprocess.run(
                ["nice", "-n", "10", str(NATIVE), *arguments],
                cwd=ROOT,
                stdout=output,
                stderr=diagnostics,
                text=True,
                check=False,
            )
        print(
            f"transition {' '.join(arguments)}: exit={completed.returncode} "
            f"seconds={time.monotonic() - started:.3f}",
            flush=True,
        )
        if completed.returncode != expected_exit:
            raise AssertionError(
                f"native selector {arguments} failed ({completed.returncode}); "
                f"stdout={stdout} stderr={stderr}\n"
                f"{stderr.read_text(encoding='utf-8')}"
            )
        return stdout, stderr

    def test_commit_cases(self) -> None:
        for selector in COMMIT_SELECTORS:
            with self.subTest(selector=selector):
                self.run_native(*selector)

    @unittest.skipUnless(CVC5 is not None, "needs cvc5")
    def test_commit_smt_cases(self) -> None:
        assert CVC5 is not None
        for name, expected in COMMIT_SMT_CASES.items():
            with self.subTest(case=name):
                formula, _ = self.run_native("--smt", name)
                with formula.open(encoding="utf-8") as stream:
                    self.assertTrue(stream.readline().startswith("(set-logic ALL)"))
                self.assertEqual(
                    run_solver(CVC5, formula, self.workspace, name).status, expected
                )

    def test_other_families(self) -> None:
        for selector in FAMILY_SELECTORS:
            with self.subTest(selector=selector):
                self.run_native(*selector)


if __name__ == "__main__":
    unittest.main()
