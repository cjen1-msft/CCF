"""Opt-in queue component checks, including a finite concrete queue oracle."""

import json
from itertools import product
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from Shared.solver import find_cvc5, run_solver


ROOT = Path(__file__).resolve().parents[1]


def load_fixtures(*args: str) -> list[dict]:
    generated = subprocess.run(
        [
            "nice", "-n", "10", "lake", "env", "lean", "--run",
            "Sparse/QueueCountFixtureMain.lean", *args,
        ],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return json.loads(generated.stdout)


def concrete_follows(initial: tuple[int, ...], events: list, aliases: bool) -> bool:
    queue = list(initial)
    for kind, argument in events:
        value = 0 if aliases else argument
        if kind == "send":
            if value not in queue:
                queue.append(value)
        elif kind == "pop":
            if not queue or queue[0] != value:
                return False
            queue.pop(0)
        elif kind == "peek":
            if not queue or queue[0] != value:
                return False
        elif kind == "length":
            if len(queue) != argument:
                return False
        else:
            raise ValueError(f"unknown fixture event: {kind}")
    return True


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean and cvc5 available",
)
class SparseQueueEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        requested = os.environ.get("CVC5")
        cls.cvc5 = find_cvc5(Path(requested) if requested else None)
        cls.temporary = tempfile.TemporaryDirectory(prefix="sparse-counts-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.artifacts = Path(cls.temporary.name)
        subprocess.run(
            [
                "nice", "-n", "10", "lake", "build", "Sparse.QueueEncoding",
                "Sparse.QueueScalarEncoding", "Sparse.SmtScriptText",
                "Sparse.QueueInitialEncoding", "Sparse.QueueTraceEncoding",
                "Sparse.QueueSummaryEncoding",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        cls.fixtures = load_fixtures()
        cls.scalar_fixtures = load_fixtures("--scalar")
        cls.initial_fixtures = load_fixtures("--initial")
        cls.summary_fixtures = load_fixtures("--summary-initial")

    def assert_scripts(self, fixtures: list[dict], scope: str) -> None:
        self.assertEqual(len({case["name"] for case in fixtures}), len(fixtures))
        for case in fixtures:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["scope"], scope)
                self.assertTrue(case["script"].isascii())
                self.assertEqual(case["parsed_script"], case["script"])
                self.assertEqual(case["parsed_value"], case["command_value"])
                name = scope + "-" + case["name"]
                path = self.artifacts / (name + ".smt2")
                path.write_text(case["script"], encoding="ascii")
                result = run_solver(self.cvc5, path, self.artifacts, name)
                self.assertEqual(result.status, case["expected"])

    def test_count_read_scripts(self) -> None:
        self.assertEqual(len(self.fixtures), 13)
        self.assert_scripts(self.fixtures, "count-read")
        cases = {case["name"]: case for case in self.fixtures}
        self.assertEqual(cases["duplicate-send"]["query_pairs"], 4)
        self.assertEqual(cases["duplicate-send-contradiction"]["query_pairs"], 4)
        self.assertEqual(cases["other-key-preserved"]["query_pairs"], 3)
        self.assertEqual(cases["aliased-root-counts"]["query_pairs"], 2)

    def test_scalar_scripts(self) -> None:
        self.assertEqual(len(self.scalar_fixtures), 14)
        self.assert_scripts(self.scalar_fixtures, "count-and-scalar")
        for case in self.scalar_fixtures:
            with self.subTest(case=case["name"]):
                self.assertLessEqual(case["count_range_end"], case["scalar_base"])

    def test_initial_accounting_scripts(self) -> None:
        self.assertEqual(len(self.initial_fixtures), 20)
        self.assert_scripts(self.initial_fixtures, "count-scalar-initial")
        cases = {case["name"]: case for case in self.initial_fixtures}
        self.assertEqual(cases["initial-duplicates-allowed"]["tracked_keys"], 1)
        self.assertEqual(cases["aliased-keys-count-once"]["tracked_keys"], 2)
        self.assertEqual(cases["last-unconsumed-peek"]["tracked_keys"], 3)

    def test_exhaustive_two_event_traces(self) -> None:
        for flag in ("--exhaustive", "--summary-exhaustive"):
            with self.subTest(compiler=flag):
                self.assert_exhaustive(load_fixtures(flag), flag.removeprefix("--"))

    def test_summary_scripts(self) -> None:
        self.assertEqual(len(self.summary_fixtures), 25)
        self.assert_scripts(self.summary_fixtures, "summary-whole-queue")
        cases = {case["name"]: case for case in self.summary_fixtures}
        self.assertEqual(cases["sent-key-remains-present"]["encoded_events"], 3)
        self.assertEqual(cases["alias-pop-requires-send"]["encoded_events"], 4)
        self.assertEqual(cases["distinct-literal-pop-preserves-present"]["encoded_events"], 3)
        self.assertEqual(cases["contradictory-earlier-length-retained"]["encoded_events"], 3)

    def test_cached_compiler_preserves_exact_scripts(self) -> None:
        cases = load_fixtures("--cache-equivalence")
        self.assertEqual([case["case"] for case in cases], list(range(54)))
        self.assertTrue(all(case["bytes"] > 0 for case in cases))

    def assert_exhaustive(self, cases: list[dict], scope: str) -> None:
        self.assertEqual(len(cases), 486)
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        verdicts = set()
        for case in cases:
            # Two named keys plus one class for all unobserved initial values.
            alphabet = (0, 2) if case["aliases"] else (0, 1, 2)
            possible = any(
                concrete_follows(queue, case["events"], case["aliases"])
                for queue in product(alphabet, repeat=case["initial_length"])
            )
            expected = "sat" if possible else "unsat"
            verdicts.add(expected)
            with self.subTest(case=case["name"], expected=expected):
                self.assertEqual(case["parsed_script"], case["script"])
                self.assertEqual(case["parsed_value"], case["command_value"])
                name = scope + "-" + case["name"]
                path = self.artifacts / (name + ".smt2")
                path.write_text(case["script"], encoding="ascii")
                result = run_solver(self.cvc5, path, self.artifacts, name)
                self.assertEqual(result.status, expected)
        self.assertEqual(verdicts, {"sat", "unsat"})


if __name__ == "__main__":
    unittest.main()
