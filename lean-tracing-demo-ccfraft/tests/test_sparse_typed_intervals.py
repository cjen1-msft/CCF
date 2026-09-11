"""Opt-in typed root/version arrays, including native Entry cells."""

from itertools import product
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


def concrete_splice(name: str) -> bool:
    _, _, lower, upper, position, want_inside = name.split("-")
    inside = int(lower) <= int(position) < int(upper)
    return any(
        left != right
        and (left if inside else right) == (left if want_inside == "true" else right)
        for left, right in product((0, 1), repeat=2)
    )


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseTypedIntervalTests(unittest.TestCase):
    def test_typed_shared_arrays(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.TypedIntervalFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/TypedIntervalFixtureMain.lean",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 408)
        by_name = {case["name"]: case for case in cases}
        self.assertEqual(len(by_name), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-typed-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    if case["name"].startswith("splice-"):
                        self.assertEqual(case["expected"], "sat" if concrete_splice(case["name"]) else "unsat")
                    self.assertEqual(case["next_function"], case["base"] + case["roots"] + case["versions"])
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, case["expected"])
        self.assertGreater(by_name["unused-constant-metadata"]["base"], 1000)
        self.assertGreater(by_name["expected-function-metadata"]["base"], 2000)
        self.assertEqual(by_name["million-roots-trillion-position"]["demands"], 1)
        self.assertEqual(by_name["empty-native"]["demands"], 0)
        for verdict in ("sat", "unsat"):
            self.assertEqual(by_name[f"entry-400-points-{verdict}"]["demands"], 800)
            self.assertEqual(by_name[f"entry-400-versions-{verdict}"]["demands"], 401)


if __name__ == "__main__":
    unittest.main()
