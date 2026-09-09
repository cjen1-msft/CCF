# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Keep producer groups necessary in the indexed symbolic trace encoder."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from Shared.smt import add_query, parse_unsat_core, restrict_to_assertions
from Shared.solver import query_payload, run_solver
from tests.test_client_request_encoding import CVC5, ROOT


@unittest.skipUnless(CVC5 is not None and shutil.which("lake"), "needs Lean and cvc5")
class SymbolicCausalityTests(unittest.TestCase):
    def assert_causal_fixture(
        self, source: str, argument: str, groups: tuple[str, ...]
    ) -> None:
        encoded = subprocess.run(
            [
                "nice",
                "-n",
                "10",
                "lake",
                "env",
                "lean",
                "--run",
                source,
                argument,
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        formula = encoded.stdout
        with tempfile.TemporaryDirectory(prefix="symbolic-causality-") as directory:
            output = Path(directory)
            assert CVC5 is not None
            core_path = output / "core.smt2"
            core_path.write_text(add_query(formula, "get-unsat-core"), encoding="utf-8")
            result = run_solver(CVC5, core_path, output, "core")
            self.assertEqual(result.status, "unsat")
            core = parse_unsat_core(query_payload(result, "get-unsat-core"))
            self.assertTrue({"group_0", "group_1", "group_2"}.issubset(core))

            for removed in ("group_0", "group_1", "group_2"):
                with self.subTest(removed=removed):
                    selected = [name for name in groups if name != removed]
                    path = output / f"without-{removed}.smt2"
                    path.write_text(
                        restrict_to_assertions(formula, selected), encoding="utf-8"
                    )
                    self.assertEqual(
                        run_solver(CVC5, path, output, f"without-{removed}").status,
                        "sat",
                    )

    def test_core_requires_entry_writer_and_conflicting_observation(self) -> None:
        self.assert_causal_fixture(
            "Shared/SymbolicTraceTests.lean",
            "--smt",
            ("group_0", "group_1", "group_2", "group_3"),
        )

    def test_conditional_frontier_keeps_the_predicate_writer(self) -> None:
        self.assert_causal_fixture(
            "Shared/SmtConditionalFixtureMain.lean",
            "--conditional",
            ("group_0", "group_1", "group_2"),
        )


if __name__ == "__main__":
    unittest.main()
