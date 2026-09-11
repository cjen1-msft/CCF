"""Opt-in native-sort scripts, including every unary signature."""

from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseNativeSortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.NativeSortFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )

    def load(self, *arguments: str):
        generated = subprocess.run(
            [
                "nice", "-n", "10", "lake", "env", "lean", "--run",
                "Sparse/NativeSortFixtureMain.lean", *arguments,
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        return json.loads(generated.stdout)

    def assert_cases(self, cases: list[dict]) -> None:
        self.assertEqual(len(cases), 73)
        by_name = {case["name"]: case for case in cases}
        self.assertEqual(len(by_name), len(cases))
        self.assertEqual(Counter(case["expected"] for case in cases), {"sat": 37, "unsat": 36})
        self.assert_scripts(cases)
        self.assertEqual(by_name["all-signatures"]["declarations"], 30)
        for index in (0, 1):
            self.assertEqual(by_name[f"self-{index}-sat"]["prelude"], ["(set-logic QF_UFLIA)"])
        self.assertEqual(by_name["self-2-sat"]["prelude"], ["(set-logic ALL)"])
        self.assertEqual(len(by_name["self-3-sat"]["prelude"]), 2)
        entry_prelude = by_name["self-4-sat"]["prelude"]
        self.assertEqual(len(entry_prelude), 3)
        self.assertEqual(by_name["inactive-native"]["prelude"], entry_prelude)
        self.assertEqual(by_name["false-before-native"]["prelude"], entry_prelude)

    def assert_scripts(self, cases: list[dict]) -> None:
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        requested = os.environ.get("CVC5")
        cvc5 = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="sparse-native-") as directory:
            artifacts = Path(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    self.assertTrue(case["script"].isascii())
                    self.assertEqual(case["reference_script"], case["script"])
                    self.assertEqual(case["parsed_script"], case["script"])
                    self.assertIsNotNone(case["command_value"])
                    self.assertEqual(case["parsed_value"], case["command_value"])
                    path = artifacts / (case["name"] + ".smt2")
                    path.write_text(case["script"], encoding="ascii")
                    result = run_solver(cvc5, path, artifacts, case["name"])
                    self.assertEqual(result.status, case["expected"])

    def test_native_sort_scripts(self) -> None:
        self.assert_cases(self.load())

    def assert_constructor_cases(self, cases: list[dict]) -> None:
        self.assertEqual(len(cases), 314)
        self.assertEqual(Counter(case["expected"] for case in cases), {"sat": 157, "unsat": 157})
        self.assert_scripts(cases)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["command_value"], case["expected"] == "sat")
                if case["declarations"] == 0:
                    self.assertEqual(case["prelude"][0], "(set-logic ALL)")
                    self.assertGreaterEqual(len(case["prelude"]), 2)
        by_name = {case["name"]: case for case in cases}
        for name in ("literal-only", "false-before-literal", "dead-literal"):
            self.assertEqual(by_name[name]["declarations"], 0)
            self.assertEqual(len(by_name[name]["prelude"]), 3)

    def test_native_constructor_scripts(self) -> None:
        self.assert_constructor_cases(self.load("--constructors"))

    def assert_selector_cases(self, cases: list[dict]) -> None:
        self.assertEqual(len(cases), 105)
        self.assertEqual(Counter(case["expected"] for case in cases), {"sat": 58, "unsat": 47})
        self.assert_scripts(cases)
        for case in cases:
            with self.subTest(case=case["name"]):
                if "tester" in case["name"]:
                    self.assertIn("((_ is ccf_", case["script"])
                self.assertEqual(case["prelude"][0], "(set-logic ALL)")
                self.assertGreaterEqual(len(case["prelude"]), 2)

    def test_native_selector_scripts(self) -> None:
        self.assert_selector_cases(self.load("--selectors"))

    def assert_node_cases(self, cases: list[dict]) -> None:
        self.assertEqual(len(cases), 512)
        self.assertEqual(Counter(case["expected"] for case in cases), {"sat": 256, "unsat": 256})
        for case in cases:
            with self.subTest(case=case["name"]):
                operation, *values = case["name"].split("-")
                if operation == "member":
                    mask, node = map(int, values[:2])
                    holds = bool((mask >> node) & 1) == (values[2] == "true")
                elif operation == "not":
                    mask, proposed = map(int, values)
                    holds = (~mask & 32767) == proposed
                else:
                    left, right, proposed = map(int, values)
                    self.assertIn(operation, ("and", "or"))
                    holds = (left & right if operation == "and" else left | right) == proposed
                self.assertEqual(case["expected"], "sat" if holds else "unsat")
                self.assertEqual(case["prelude"], ["(set-logic ALL)"])
        self.assert_scripts(cases)

    def test_native_node_scripts(self) -> None:
        self.assert_node_cases(self.load("--nodes"))

    def assert_masks(self, data: dict) -> None:
        self.assertEqual(len(data["masks"]), 32768)
        for expected, (value, text, parsed) in enumerate(data["masks"]):
            self.assertEqual(value, expected)
            self.assertEqual(text, f"#b{expected:015b}")
            self.assertEqual(parsed, expected)
        self.assertEqual(len(data["invalid"]), 8)
        self.assertTrue(all(rejected for _, rejected in data["invalid"]))

    def test_all_fixed_mask_literals(self) -> None:
        self.assert_masks(self.load("--masks"))


if __name__ == "__main__":
    unittest.main()
